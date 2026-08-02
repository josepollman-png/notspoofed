import type { DnsBackend } from '../dns/resolver.js';
import { QueryBudgetExceeded } from '../dns/resolver.js';
import { isSpfRecord, parseSpf, type ParsedRecord, type Term } from './parse.js';

/**
 * Static SPF evaluation — walks the whole include graph and counts every term that
 * costs a DNS lookup.
 *
 * A real evaluator short-circuits as soon as a mechanism matches the connecting IP,
 * so it may never reach term #11. We deliberately count the worst case, because the
 * sender that breaks is the one whose IP sits in the *last* include, and that is
 * precisely the failure the user is here to find. Every serious checker does the same.
 */

export const LOOKUP_LIMIT = 10;
export const VOID_LIMIT = 2;
/** RFC 7208 §4.6.4 — a single `mx` or `ptr` may not fan out past 10 records. */
export const MX_PTR_LIMIT = 10;

export interface SpfNode {
  domain: string;
  record: string | null;
  parsed: ParsedRecord | null;
  /** Populated for include/redirect terms that were followed. */
  children: Array<{ term: Term; node: SpfNode | null; skipped?: string }>;
  /** Addresses contributed by this record's own terms, excluding its children.
   *  Kept per-node so flattening can replace one include at a time rather than
   *  demolishing the entire record. */
  ownIp4: string[];
  ownIp6: string[];
  error?: string;
}

export interface SpfProblem {
  code: string;
  message: string;
  /** Where in the include graph it surfaced. */
  domain: string;
}

export interface SpfEvaluation {
  domain: string;
  found: boolean;
  /** The apex record, verbatim. */
  record: string | null;
  lookupCount: number;
  voidCount: number;
  limitExceeded: boolean;
  /** Terms whose target contains a macro and so cannot be statically resolved. */
  macroTerms: Term[];
  /** Effective qualifier on `all` at the apex, e.g. '~' for ~all. */
  allQualifier: string | null;
  ip4: string[];
  ip6: string[];
  problems: SpfProblem[];
  tree: SpfNode | null;
  truncated: boolean;
  /**
   * The record is exactly `v=spf1 -all` — it authorises nobody and forbids everyone,
   * which is the correct, deliberate posture for a domain that sends no mail.
   * Without this distinction the report warns about missing DKIM on domains that are
   * configured perfectly, which is how a checker loses trust.
   */
  sendsNoMail: boolean;
}

interface State {
  dns: DnsBackend;
  lookups: number;
  voids: number;
  problems: SpfProblem[];
  ip4: Set<string>;
  ip6: Set<string>;
  macros: Term[];
  truncated: boolean;
}

function problem(state: State, domain: string, code: string, message: string): void {
  if (!state.problems.some((p) => p.code === code && p.domain === domain)) {
    state.problems.push({ code, message, domain });
  }
}

/** Fetch the single SPF record for a name, reporting the RFC's error cases. */
async function fetchSpf(
  state: State,
  domain: string,
): Promise<{ record: string | null; error?: string }> {
  const answer = await state.dns.txt(domain);

  if (answer.void) {
    state.voids++;
    return { record: null, error: 'no SPF record published' };
  }
  if (answer.error) {
    return { record: null, error: `DNS ${answer.error.toLowerCase()}` };
  }

  const spf = answer.values.filter(isSpfRecord);
  if (spf.length === 0) {
    // The name exists and has TXT records, just none of them SPF. Still a void
    // lookup for limit purposes — nothing usable came back.
    state.voids++;
    return { record: null, error: 'no SPF record published' };
  }
  if (spf.length > 1) {
    return {
      record: spf[0]!,
      error: `PermError: ${spf.length} SPF records published (RFC 7208 requires exactly one)`,
    };
  }
  return { record: spf[0]! };
}

async function walk(
  state: State,
  domain: string,
  path: readonly string[],
): Promise<SpfNode> {
  const node: SpfNode = {
    domain, record: null, parsed: null, children: [], ownIp4: [], ownIp6: [],
  };

  const { record, error } = await fetchSpf(state, domain);
  if (error) {
    node.error = error;
    problem(state, domain, error.startsWith('PermError') ? 'multiple-records' : 'no-record', error);
  }
  if (!record) return node;

  node.record = record;
  const parsed = parseSpf(record);
  node.parsed = parsed;
  for (const e of parsed.errors) problem(state, domain, 'syntax', e);

  for (const term of parsed.terms) {
    // Free mechanisms: harvest addresses for flattening, then move on.
    if (term.name === 'ip4' && term.value) {
      state.ip4.add(term.value); node.ownIp4.push(term.value); continue;
    }
    if (term.name === 'ip6' && term.value) {
      state.ip6.add(term.value); node.ownIp6.push(term.value); continue;
    }
    if (!term.costsLookup) continue;

    // Charged before the query, and charged even when we decline to follow it —
    // the limit counts terms evaluated, not packets sent.
    state.lookups++;

    if (term.hasMacro) {
      // %{i} and friends expand from the connecting client's IP. There is no honest
      // static answer, so we count the lookup and say so rather than guessing.
      state.macros.push(term);
      node.children.push({ term, node: null, skipped: 'macro — not statically evaluable' });
      continue;
    }

    if (state.lookups > LOOKUP_LIMIT) {
      node.children.push({ term, node: null, skipped: 'beyond the 10-lookup limit' });
      continue;
    }

    if (term.name === 'ptr') {
      problem(state, domain, 'ptr-deprecated',
        'the ptr mechanism is deprecated (RFC 7208 §5.5) and many receivers ignore it');
      node.children.push({ term, node: null, skipped: 'ptr not followed' });
      continue;
    }

    if (term.name === 'a' || term.name === 'mx') {
      await resolveAddresses(state, node, term, term.value ?? domain, domain);
      node.children.push({ term, node: null });
      continue;
    }

    if (term.name === 'exists') {
      node.children.push({ term, node: null, skipped: 'exists — presence check only' });
      continue;
    }

    // include / redirect
    const target = term.value;
    if (!target) {
      node.children.push({ term, node: null, skipped: 'no target' });
      continue;
    }
    if (path.includes(target.toLowerCase())) {
      problem(state, domain, 'loop', `include loop: ${[...path, target].join(' → ')}`);
      node.children.push({ term, node: null, skipped: 'loop detected' });
      continue;
    }

    const child = await walk(state, target, [...path, domain.toLowerCase()]);
    node.children.push({ term, node: child });
  }

  return node;
}

/** Resolve `a`/`mx` targets into concrete addresses, honouring the per-term fan-out cap. */
async function resolveAddresses(
  state: State,
  node: SpfNode,
  term: Term,
  target: string,
  at: string,
): Promise<void> {
  const collect = (v4: readonly string[], v6: readonly string[]): void => {
    for (const ip of v4) {
      const cidr = term.cidr4 ? `${ip}/${term.cidr4}` : ip;
      state.ip4.add(cidr); node.ownIp4.push(cidr);
    }
    for (const ip of v6) {
      const cidr = term.cidr6 ? `${ip}/${term.cidr6}` : ip;
      state.ip6.add(cidr); node.ownIp6.push(cidr);
    }
  };

  if (term.name === 'a') {
    const [v4, v6] = await Promise.all([state.dns.a(target), state.dns.aaaa(target)]);
    // Only a name with neither A nor AAAA is void; having just one is normal.
    if (v4.void && v6.void) state.voids++;
    collect(v4.values, v6.values);
    return;
  }

  const mx = await state.dns.mx(target);
  if (mx.void) { state.voids++; return; }
  if (mx.values.length > MX_PTR_LIMIT) {
    problem(state, at, 'mx-fanout',
      `mx:${target} returns ${mx.values.length} hosts; RFC 7208 caps this at ${MX_PTR_LIMIT}`);
  }
  for (const host of mx.values.slice(0, MX_PTR_LIMIT)) {
    const [v4, v6] = await Promise.all([state.dns.a(host.exchange), state.dns.aaaa(host.exchange)]);
    collect(v4.values, v6.values);
  }
}

/**
 * The qualifier that actually decides the fate of an unlisted sender.
 *
 * A record whose only term is `redirect=` has no `all` of its own — hubspot.com is
 * exactly this. RFC 7208 §6.1: when nothing matches, the redirect target's record
 * *replaces* this one, so its `all` is the operative policy. Reading only the apex
 * would report "no policy" for a domain that is in fact publishing `-all`.
 */
function effectiveAll(node: SpfNode | null): string | null {
  if (!node?.parsed) return null;

  const all = node.parsed.terms.find((t) => t.name === 'all' && t.kind === 'mechanism');
  if (all) return all.qualifier;

  // No `all` here: fall through the redirect, if one was followed.
  const redirect = node.children.find((c) => c.term.name === 'redirect' && c.node);
  return redirect ? effectiveAll(redirect.node) : null;
}

export async function evaluateSpf(dns: DnsBackend, domain: string): Promise<SpfEvaluation> {
  const state: State = {
    dns, lookups: 0, voids: 0, problems: [],
    ip4: new Set(), ip6: new Set(), macros: [], truncated: false,
  };

  let tree: SpfNode | null = null;
  try {
    tree = await walk(state, domain, []);
  } catch (err) {
    if (err instanceof QueryBudgetExceeded) {
      state.truncated = true;
      problem(state, domain, 'budget', `${err.message} — results below are incomplete`);
    } else {
      throw err;
    }
  }

  if (state.voids > VOID_LIMIT) {
    problem(state, domain, 'void-limit',
      `${state.voids} void lookups (names that resolve to nothing); RFC 7208 allows ${VOID_LIMIT}`);
  }

  return {
    domain,
    found: Boolean(tree?.record),
    record: tree?.record ?? null,
    lookupCount: state.lookups,
    voidCount: state.voids,
    limitExceeded: state.lookups > LOOKUP_LIMIT,
    macroTerms: state.macros,
    allQualifier: effectiveAll(tree),
    ip4: [...state.ip4],
    ip6: [...state.ip6],
    problems: state.problems,
    tree,
    truncated: state.truncated,
    // No addresses authorised, no terms that could authorise any, and a hard fail
    // for everyone else.
    sendsNoMail:
      Boolean(tree?.record) &&
      effectiveAll(tree) === '-' &&
      state.lookups === 0 &&
      state.ip4.size === 0 &&
      state.ip6.size === 0,
  };
}
