import type { SpfEvaluation, SpfNode } from './evaluate.js';
import { LOOKUP_LIMIT } from './evaluate.js';
import type { Term } from './parse.js';

/**
 * Flattening replaces `include:` chains with the addresses they currently resolve to,
 * trading a permanent maintenance burden for headroom under the 10-lookup limit.
 *
 * Two deliberate design choices:
 *
 * 1. **Flatten the minimum, not everything.** The obvious implementation inlines every
 *    include and emits one enormous record. That maximises the staleness problem for no
 *    reason. We flatten the most expensive subtrees only until the count is legal, and
 *    leave the rest as includes so the provider can still rotate their own IPs.
 *
 * 2. **Never flatten what cannot be resolved.** `exists:` with a macro and `ptr` have no
 *    static address set. Flattening them would silently drop senders.
 *
 * This output goes into the mail delivery path. If it is wrong, the customer's mail
 * stops. Every caveat here is load-bearing — do not trim them for UI tidiness.
 */

/** DNS character-string limit (RFC 1035 §3.3). Longer values must be split. */
const CHUNK_LIMIT = 255;
/** Above this, the TXT response starts risking truncation and resolver fallback. */
const SIZE_WARN = 450;

export interface FlattenPlan {
  /** Include/a/mx targets that were inlined. */
  flattened: string[];
  /** Terms left untouched, in their original order. */
  kept: string[];
  record: string;
  /** The record split into DNS character-strings, if it exceeds 255 bytes. */
  chunks: string[];
  byteLength: number;
  lookupsBefore: number;
  lookupsAfter: number;
  /** False when flattening everything resolvable still leaves too many lookups. */
  sufficient: boolean;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// IPv4 CIDR collapsing
// ---------------------------------------------------------------------------

interface V4Range { start: number; end: number; text: string; len: number }

function parseV4(entry: string): V4Range | null {
  const [addr, lenRaw] = entry.split('/');
  const octets = (addr ?? '').split('.');
  if (octets.length !== 4) return null;

  let value = 0;
  for (const o of octets) {
    const n = Number(o);
    if (!Number.isInteger(n) || n < 0 || n > 255 || o === '') return null;
    value = (value * 256) + n;
  }

  const len = lenRaw === undefined ? 32 : Number(lenRaw);
  if (!Number.isInteger(len) || len < 0 || len > 32) return null;

  const size = 2 ** (32 - len);
  const start = Math.floor(value / size) * size;
  return { start, end: start + size - 1, text: entry, len };
}

/**
 * Drop any range wholly contained in another. Providers routinely publish both a
 * covering /17 and individual /29s inside it; keeping both wastes scarce record bytes.
 * This only removes redundancy — it never widens the permitted set.
 */
function collapseV4(entries: readonly string[]): string[] {
  const parsed: V4Range[] = [];
  const unparseable: string[] = [];

  for (const e of entries) {
    const r = parseV4(e);
    if (r) parsed.push(r); else unparseable.push(e);
  }

  // Widest first, so a covering range is always considered before what it covers.
  parsed.sort((a, b) => a.len - b.len || a.start - b.start);

  const kept: V4Range[] = [];
  for (const r of parsed) {
    if (!kept.some((k) => k.start <= r.start && k.end >= r.end)) kept.push(r);
  }

  kept.sort((a, b) => a.start - b.start);
  return [...kept.map((k) => k.text), ...[...new Set(unparseable)]];
}

// ---------------------------------------------------------------------------
// Subtree accounting
// ---------------------------------------------------------------------------

/** Costly terms in this node and everything below it. */
function subtreeCost(node: SpfNode | null): number {
  if (!node?.parsed) return 0;
  let cost = 0;
  for (const term of node.parsed.terms) if (term.costsLookup) cost++;
  for (const child of node.children) cost += subtreeCost(child.node);
  return cost;
}

function subtreeIps(node: SpfNode | null): { ip4: string[]; ip6: string[] } {
  if (!node) return { ip4: [], ip6: [] };
  const ip4 = [...node.ownIp4];
  const ip6 = [...node.ownIp6];
  for (const child of node.children) {
    const sub = subtreeIps(child.node);
    ip4.push(...sub.ip4);
    ip6.push(...sub.ip6);
  }
  return { ip4, ip6 };
}

/** Terms whose address set is knowable today. `exists`/`ptr` never are. */
function isFlattenable(term: Term, node: SpfNode | null): boolean {
  if (term.hasMacro) return false;
  if (term.name === 'a' || term.name === 'mx') return true;
  if (term.name === 'include' || term.name === 'redirect') return Boolean(node?.record);
  return false;
}

// ---------------------------------------------------------------------------
// Record rendering
// ---------------------------------------------------------------------------

/** Split into ≤255-byte character-strings, breaking only between terms. */
function chunk(record: string): string[] {
  if (Buffer.byteLength(record) <= CHUNK_LIMIT) return [record];

  const out: string[] = [];
  let current = '';
  for (const token of record.split(' ')) {
    const candidate = current === '' ? token : `${current} ${token}`;
    if (Buffer.byteLength(candidate) > CHUNK_LIMIT) {
      if (current !== '') out.push(current);
      current = token;
    } else {
      current = candidate;
    }
  }
  if (current !== '') out.push(current);
  return out;
}

export function planFlattening(evaluation: SpfEvaluation): FlattenPlan | null {
  const root = evaluation.tree;
  if (!root?.parsed) return null;

  const apexTerms = root.parsed.terms;
  const candidates = root.children
    .map((child) => ({
      child,
      // Inlining an include retires the include term itself (1) *and* every costly
      // term beneath it. Counting only the subtree undercounts the saving by one and
      // leaves the plan short of the limit it was supposed to reach.
      cost: child.term.name === 'include' || child.term.name === 'redirect'
        ? 1 + subtreeCost(child.node)
        : 1,
    }))
    .filter(({ child }) => child.term.costsLookup && isFlattenable(child.term, child.node))
    .sort((a, b) => b.cost - a.cost);

  const warnings: string[] = [];
  const chosen = new Set<Term>();
  let remaining = evaluation.lookupCount;

  // Greedy: retire the most expensive subtree first. Flattening a subtree removes its
  // entire cost, so this reaches a legal record while touching the fewest includes.
  for (const { child, cost } of candidates) {
    if (remaining <= LOOKUP_LIMIT) break;
    chosen.add(child.term);
    remaining -= cost;
  }

  if (chosen.size === 0) return null;

  const ip4: string[] = [];
  const ip6: string[] = [];
  const flattened: string[] = [];
  const kept: string[] = [];

  for (const term of apexTerms) {
    if (chosen.has(term)) {
      const child = root.children.find((c) => c.term === term);
      const ips = child?.node
        ? subtreeIps(child.node)
        // Bare a/mx resolve into the apex node's own address list.
        : { ip4: root.ownIp4, ip6: root.ownIp6 };
      ip4.push(...ips.ip4);
      ip6.push(...ips.ip6);
      flattened.push(term.raw);

      // A flattened redirect loses the target's `all`; carry it across explicitly.
      if (term.name === 'redirect' && !apexTerms.some((t) => t.name === 'all')) {
        kept.push(`${evaluation.allQualifier ?? '~'}all`);
      }
      continue;
    }

    if (term.name === 'ip4' || term.name === 'ip6') {
      (term.name === 'ip4' ? ip4 : ip6).push(term.value!);
      continue;
    }
    if (term.kind === 'unknown' && term.name !== 'all') continue;
    kept.push(term.raw);
  }

  const finalV4 = collapseV4(ip4);
  const finalV6 = [...new Set(ip6)];
  const collapsed = ip4.length - finalV4.length;

  // `all` must come last; every other kept term keeps its relative order.
  const allTerm = kept.filter((t) => /all$/.test(t));
  const others = kept.filter((t) => !/all$/.test(t));

  const record = [
    'v=spf1',
    ...others,
    ...finalV4.map((ip) => `ip4:${ip}`),
    ...finalV6.map((ip) => `ip6:${ip}`),
    ...allTerm,
  ].join(' ');

  const byteLength = Buffer.byteLength(record);
  const chunks = chunk(record);

  warnings.push(
    'Flattened records are a snapshot. If any of these providers changes its sending ' +
    'IPs, your mail from that provider starts failing SPF with no warning. Re-check ' +
    'monthly, or keep the include and reduce lookups another way.',
  );
  if (chunks.length > 1) {
    warnings.push(
      `At ${byteLength} bytes this exceeds the 255-byte DNS character-string limit and ` +
      `must be published as ${chunks.length} quoted strings. Most providers do this for ` +
      'you; some require you to enter the quotes yourself.',
    );
  }
  if (byteLength > SIZE_WARN) {
    warnings.push(
      `${byteLength} bytes is a large TXT response and may fall back to TCP on some ` +
      'resolvers. Prefer removing an unused sender over flattening further.',
    );
  }
  if (collapsed > 0) {
    warnings.push(
      `${collapsed} redundant address ranges were removed because a broader range in ` +
      'the same record already covers them. No sender lost coverage.',
    );
  }
  if (remaining > LOOKUP_LIMIT) {
    warnings.push(
      `Even after flattening everything resolvable, ${remaining} lookups remain — the ` +
      'rest are macros or ptr terms with no fixed address set. You will need to remove ' +
      'a sender.',
    );
  }

  return {
    flattened,
    kept: others,
    record,
    chunks,
    byteLength,
    lookupsBefore: evaluation.lookupCount,
    lookupsAfter: Math.max(0, remaining),
    sufficient: remaining <= LOOKUP_LIMIT,
    warnings,
  };
}
