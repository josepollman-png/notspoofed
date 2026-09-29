import { InvalidDomainError } from '../check.js';
import { normaliseFinderDomain } from '../dkim/finder.js';
import { DnsResolver, type DnsBackend } from '../dns/resolver.js';
import {
  evaluateSpf,
  LOOKUP_LIMIT,
  VOID_LIMIT,
  type SpfEvaluation,
  type SpfNode,
} from './evaluate.js';
import { planFlattening, subtreeCost, type FlattenPlan } from './flatten.js';
import { isSpfRecord, type Term } from './parse.js';

/**
 * The SPF lookup counter: the checker's own evaluator, with the tree laid out so a
 * person can see where the tenth lookup lands.
 *
 * Nothing here parses or counts SPF a second time. `evaluateSpf` does the walk and the
 * counting, with two options the checker leaves off: evaluate a pasted draft at the
 * root, and keep following past the 10th lookup so the whole tree is visible. This file
 * only arranges the result and works out which fixes are safe.
 *
 * The fixes are ordered by how much they can hurt. Removing an include that is already
 * pulled in elsewhere changes nothing about who may send. Flattening changes nothing
 * today and breaks silently the day a provider moves its servers. Removing a service you
 * no longer use is safest of all, but only the owner knows which one that is, so the
 * tool says so instead of guessing.
 */

/** RFC 1035 §3.3: one TXT character-string is at most 255 bytes. */
const STRING_LIMIT = 255;
/** RFC 7208 §3.4: keep the whole answer within a 512-byte UDP response. */
const RECORD_BYTES_LIMIT = 512;
/** A pasted draft longer than this is not an SPF record anyone should publish. */
const DRAFT_MAX_CHARS = 4000;

export type CounterStatus = 'PASS' | 'WARNING' | 'PERMERROR';

export interface CounterNode {
  /** The term as written, qualifier included: `include:_spf.google.com`, `-mx`. */
  mechanism: string;
  name: string;
  target: string | null;
  /** Lookups this term costs on its own — always 1 for the terms shown. */
  cost: number;
  /** This term plus everything it pulls in. */
  totalCost: number;
  /** Running lookup count after this term, in evaluation order. */
  lookupsAfter: number;
  /** Void lookups this term's own query caused, and the running void count after it. */
  voids: number;
  voidsAfter: number;
  /** This is the term that took the count past 10. */
  crossesLimit: boolean;
  overLimit: boolean;
  /** This is the term that took the void count past 2. */
  crossesVoidLimit: boolean;
  /** The same include/redirect target appears elsewhere in the tree. */
  duplicate: boolean;
  /** Why the term was not followed, or what went wrong fetching its record. */
  note: string | null;
  /** The record found at the target, for include/redirect. */
  record: string | null;
  /** ip4/ip6/all and other terms in that record that cost nothing. */
  freeTerms: number;
  children: CounterNode[];
}

export interface CounterFlag {
  code:
    | 'ptr' | 'duplicate-include' | 'permissive-all' | 'no-all' | 'multiple-records'
    | 'string-too-long' | 'record-too-large' | 'void-limit' | 'loop' | 'macro'
    | 'syntax' | 'no-record' | 'mx-fanout' | 'truncated';
  severity: 'error' | 'warning' | 'info';
  message: string;
}

export interface RedundantInclude {
  mechanism: string;
  /** What else already brings the same target in. */
  alsoVia: string;
  saves: number;
}

export interface CounterFixes {
  /** (a) Includes that can go without changing who may send. */
  redundant: RedundantInclude[];
  /** Targets duplicated inside providers' own records: noted, not actionable here. */
  duplicatedElsewhere: Array<{ target: string; via: string[] }>;
  /** The apex includes, costliest first, so the owner can spot a service they dropped. */
  includesByCost: Array<{ mechanism: string; cost: number }>;
  lookupsAfterRedundant: number;
  /** (b) Partial flattening, if removing redundancy was not enough. */
  flatten: FlattenPlan | null;
  /** Why flattening was not offered when the record is still over the limit. */
  flattenUnavailable: string | null;
  /** (c) The record with (a) and, if needed, (b) applied. */
  record: string | null;
  recordLookups: number | null;
}

export interface CounterResult {
  source: 'dns' | 'pasted';
  domain: string | null;
  record: string | null;
  /** The character-strings of a pasted draft, as entered. */
  strings: string[];
  found: boolean;
  lookupCount: number;
  voidCount: number;
  status: CounterStatus;
  summary: string;
  /** PermErrors that are not about the lookup count, for the line under the summary. */
  otherPermErrors: string[];
  root: { domain: string | null; freeTerms: number; nodes: CounterNode[] };
  flags: CounterFlag[];
  fixes: CounterFixes | null;
  explanation: string[];
  truncated: boolean;
  checkedAt: string;
}

export class InvalidRecordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidRecordError';
  }
}

export function statusFor(lookups: number): CounterStatus {
  if (lookups > LOOKUP_LIMIT) return 'PERMERROR';
  if (lookups >= LOOKUP_LIMIT - 1) return 'WARNING';
  return 'PASS';
}

/**
 * Read a pasted draft. Either a bare record, or the quoted strings a zone file or DNS
 * host shows (`"v=spf1 … " "ip4:…"`), which join with nothing between them exactly as
 * the resolver joins published chunks.
 */
export function parseDraft(input: string): { record: string; strings: string[] } {
  const text = input.trim();
  if (text === '') throw new InvalidRecordError('Paste an SPF record, starting with v=spf1.');
  if (text.length > DRAFT_MAX_CHARS) {
    throw new InvalidRecordError(`That is ${text.length} characters; an SPF record that long cannot be published.`);
  }

  let strings: string[];
  if (text.includes('"')) {
    strings = [...text.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!.replace(/\\(.)/g, '$1'));
    if (strings.length === 0) throw new InvalidRecordError('The quotes in that record do not pair up.');
  } else {
    strings = [text.replace(/\s+/g, ' ')];
  }

  const record = strings.join('').trim();
  if (!isSpfRecord(record)) {
    throw new InvalidRecordError('That is not an SPF record: it must start with v=spf1.');
  }
  return { record, strings };
}

const COSTLY_FREE = (node: SpfNode | null): number =>
  node?.parsed?.terms.filter((t) => !t.costsLookup).length ?? 0;

function targetOf(term: Term, at: string): string | null {
  if (term.value) return term.value;
  if (term.name === 'a' || term.name === 'mx') return at || null;
  return null;
}

function buildNodes(node: SpfNode, targetCounts: Map<string, number>): CounterNode[] {
  return node.children.map((child) => {
    const followed = child.term.name === 'include' || child.term.name === 'redirect';
    const target = targetOf(child.term, node.domain);
    const lookupsAfter = child.lookupsAfter ?? 0;
    const voids = child.voids ?? 0;
    const voidsAfter = child.voidsAfter ?? 0;
    return {
      mechanism: child.term.raw,
      name: child.term.name,
      target,
      cost: 1,
      totalCost: followed ? 1 + subtreeCost(child.node) : 1,
      lookupsAfter,
      voids,
      voidsAfter,
      crossesLimit: lookupsAfter === LOOKUP_LIMIT + 1,
      overLimit: lookupsAfter > LOOKUP_LIMIT,
      crossesVoidLimit: voids > 0 && voidsAfter > VOID_LIMIT && voidsAfter - voids <= VOID_LIMIT,
      duplicate: followed && target !== null && (targetCounts.get(target.toLowerCase()) ?? 0) > 1,
      note: child.skipped ?? child.node?.error ?? null,
      record: child.node?.record ?? null,
      freeTerms: COSTLY_FREE(child.node),
      children: child.node ? buildNodes(child.node, targetCounts) : [],
    };
  });
}

interface Occurrence { target: string; mechanism: string; parent: string; apex: boolean; term: Term }

/** Every include/redirect in the tree, with where it was found. */
function occurrences(node: SpfNode, apex: boolean, out: Occurrence[] = []): Occurrence[] {
  for (const child of node.children) {
    if (child.term.name !== 'include' && child.term.name !== 'redirect') continue;
    if (child.term.value) {
      out.push({
        target: child.term.value.toLowerCase(),
        mechanism: child.term.raw,
        parent: node.domain,
        apex,
        term: child.term,
      });
    }
    if (child.node) occurrences(child.node, false, out);
  }
  return out;
}

/** Does anything under this node use a term whose addresses cannot be written down? */
function hasUnresolvable(node: SpfNode | null): boolean {
  if (!node) return false;
  if (!node.record || node.error) return true;
  for (const child of node.children) {
    if (child.term.hasMacro || child.term.name === 'exists' || child.term.name === 'ptr') return true;
    if (child.skipped) return true;
    if ((child.term.name === 'include' || child.term.name === 'redirect') && hasUnresolvable(child.node)) return true;
  }
  return false;
}

function apexOf(root: SpfNode, include: Term): SpfNode | null {
  return root.children.find((c) => c.term === include)?.node ?? null;
}

function planFixes(evaluation: SpfEvaluation, occ: Occurrence[]): CounterFixes | null {
  const root = evaluation.tree;
  if (!root?.parsed) return null;

  const byTarget = new Map<string, Occurrence[]>();
  for (const o of occ) byTarget.set(o.target, [...(byTarget.get(o.target) ?? []), o]);

  // (a) An apex include whose target is also reached another way. Only a plain `include`
  // qualifies: a qualified one (`-include:`, `~include:`) changes the result it returns,
  // and a redirect is not a sender list.
  const redundant: RedundantInclude[] = [];
  const removed = new Set<Term>();
  const duplicatedElsewhere: CounterFixes['duplicatedElsewhere'] = [];

  for (const [target, list] of byTarget) {
    if (list.length < 2) continue;
    const apexPlain = list.filter((o) => o.apex && o.term.name === 'include' && o.term.qualifier === '+');
    if (apexPlain.length === 0) {
      duplicatedElsewhere.push({ target, via: [...new Set(list.map((o) => o.parent))] });
      continue;
    }
    const nested = list.find((o) => !o.apex);
    // Nested elsewhere: every apex copy can go. Only at the apex: keep the first.
    const drop = nested ? apexPlain : apexPlain.slice(1);
    for (const o of drop) {
      if (removed.has(o.term)) continue;
      removed.add(o.term);
      redundant.push({
        mechanism: o.mechanism,
        alsoVia: nested ? `include:${nested.parent}` : `the first ${o.mechanism} in the same record`,
        saves: 1 + subtreeCost(apexOf(root, o.term)),
      });
    }
  }

  const includesByCost = root.children
    .filter((c) => c.term.name === 'include' && !removed.has(c.term))
    .map((c) => ({ mechanism: c.term.raw, cost: 1 + subtreeCost(c.node) }))
    .sort((a, b) => b.cost - a.cost);

  const saved = redundant.reduce((sum, r) => sum + r.saves, 0);
  const lookupsAfterRedundant = evaluation.lookupCount - saved;

  const trimmedTerms = root.parsed.terms.filter((t) => !removed.has(t));
  const trimmedRecord = ['v=spf1', ...trimmedTerms.map((t) => t.raw)].join(' ');

  let flatten: FlattenPlan | null = null;
  let flattenUnavailable: string | null = null;

  if (lookupsAfterRedundant > LOOKUP_LIMIT) {
    if (evaluation.truncated) {
      flattenUnavailable =
        'The walk hit its DNS budget before it finished, so the address list is incomplete. ' +
        'Flattening an incomplete list would drop senders, so no flattened record is offered.';
    } else {
      // The same planner the checker uses, fed the record with (a) applied. Includes
      // whose subtree holds a macro, exists, ptr or a broken record are withheld: their
      // addresses cannot be written down, and flattening them would drop senders.
      const safeChildren = root.children.filter(
        (c) => !removed.has(c.term) && !(
          (c.term.name === 'include' || c.term.name === 'redirect') && hasUnresolvable(c.node)
        ),
      );
      const trimmedRoot: SpfNode = {
        ...root,
        parsed: { ...root.parsed, terms: trimmedTerms },
        children: safeChildren,
      };
      flatten = planFlattening({ ...evaluation, tree: trimmedRoot, lookupCount: lookupsAfterRedundant });
      if (!flatten) {
        flattenUnavailable =
          'None of the includes can be flattened safely: each one relies on a macro, exists, ptr ' +
          'or a record that did not resolve. You will need to remove a sender.';
      }
    }
  }

  const record = flatten ? flatten.record : redundant.length > 0 ? trimmedRecord : null;
  const recordLookups = flatten ? flatten.lookupsAfter : redundant.length > 0 ? lookupsAfterRedundant : null;

  return {
    redundant,
    duplicatedElsewhere,
    includesByCost,
    lookupsAfterRedundant,
    flatten,
    flattenUnavailable,
    record,
    recordLookups,
  };
}

function findFlags(evaluation: SpfEvaluation, strings: string[], source: CounterResult['source'], occ: Occurrence[]): CounterFlag[] {
  const flags: CounterFlag[] = [];
  const add = (f: CounterFlag) => {
    if (!flags.some((x) => x.code === f.code && x.message === f.message)) flags.push(f);
  };

  // A pasted draft without a domain is evaluated at the empty name.
  const where = (d: string) => d || 'The draft';

  for (const p of evaluation.problems) {
    switch (p.code) {
      case 'multiple-records':
        add({ code: 'multiple-records', severity: 'error', message: `${where(p.domain)}: ${p.message.replace(/^PermError: /, '')}. Receivers return PermError before counting anything; merge them into one.` });
        break;
      case 'ptr-deprecated':
        add({ code: 'ptr', severity: 'warning', message: `${where(p.domain)} uses ptr. It is deprecated (RFC 7208 §5.5), slow, and many receivers skip it; it still costs a lookup. Replace it with ip4/ip6 or a.` });
        break;
      case 'void-limit':
        add({ code: 'void-limit', severity: 'error', message: `${evaluation.voidCount} void lookups — names that returned nothing. More than ${VOID_LIMIT} is a PermError on its own (RFC 7208 §4.6.4). Remove the includes or a/mx terms pointing at names that no longer exist.` });
        break;
      case 'loop':
        add({ code: 'loop', severity: 'error', message: `${p.message}. A receiver follows it until the lookup limit and returns PermError.` });
        break;
      case 'syntax':
        add({ code: 'syntax', severity: 'error', message: `${where(p.domain)}: ${p.message}` });
        break;
      case 'no-record':
        if (p.domain !== evaluation.domain) {
          add({ code: 'no-record', severity: 'error', message: `${p.domain} is included but has no SPF record — the include is a PermError when a receiver reaches it.` });
        }
        break;
      case 'mx-fanout':
        add({ code: 'mx-fanout', severity: 'error', message: `${where(p.domain)}: ${p.message}` });
        break;
      case 'budget':
        add({ code: 'truncated', severity: 'warning', message: 'The walk stopped at its DNS query budget, so the tree below is incomplete and the true count may be higher.' });
        break;
    }
  }

  if (evaluation.macroTerms.length > 0) {
    add({ code: 'macro', severity: 'info', message: `${evaluation.macroTerms.length} term(s) use macros such as %{i}. Each is counted as one lookup, but what it resolves to depends on the sending IP, so it is not followed.` });
  }

  const dupTargets = new Map<string, number>();
  for (const o of occ) dupTargets.set(o.target, (dupTargets.get(o.target) ?? 0) + 1);
  for (const [target, n] of dupTargets) {
    if (n > 1) add({ code: 'duplicate-include', severity: 'warning', message: `${target} is included ${n} times across the tree. Every copy is charged again.` });
  }

  if (evaluation.found) {
    const q = evaluation.allQualifier;
    if (q === '+') add({ code: 'permissive-all', severity: 'error', message: '+all authorises every server on the internet to send as this domain. Use ~all or -all.' });
    else if (q === '?') add({ code: 'permissive-all', severity: 'warning', message: '?all is neutral: unlisted servers are neither passed nor failed, which protects nothing. Use ~all or -all.' });
    else if (q === null) add({ code: 'no-all', severity: 'warning', message: 'No all mechanism, so unlisted servers get a neutral result — the same as ?all. End the record with ~all or -all.' });
  }

  if (source === 'pasted') {
    strings.forEach((s, i) => {
      const bytes = Buffer.byteLength(s);
      if (bytes <= STRING_LIMIT) return;
      add({
        code: 'string-too-long',
        severity: 'warning',
        message: strings.length === 1
          ? `At ${bytes} bytes this must be published as at least ${Math.ceil(bytes / STRING_LIMIT)} quoted strings of up to ${STRING_LIMIT} bytes. Many DNS hosts split it for you; some reject it instead.`
          : `String ${i + 1} is ${bytes} bytes; one TXT string holds at most ${STRING_LIMIT}. Split it.`,
      });
    });
  }

  const bytes = evaluation.record ? Buffer.byteLength(evaluation.record) : 0;
  if (bytes > RECORD_BYTES_LIMIT) {
    add({ code: 'record-too-large', severity: 'warning', message: `The record is ${bytes} bytes. Over ${RECORD_BYTES_LIMIT}, the DNS answer no longer fits a plain UDP response (RFC 7208 §3.4), and some receivers fail to fetch it.` });
  }

  const order = { error: 0, warning: 1, info: 2 };
  return flags.sort((a, b) => order[a.severity] - order[b.severity]);
}

function explain(r: Omit<CounterResult, 'explanation'>): string[] {
  const subject = r.source === 'pasted' ? 'This draft record' : `${r.domain}'s SPF record`;
  if (!r.found) {
    return [
      `${r.domain} publishes no SPF record, so there is nothing to count.`,
      'Without one, receivers cannot tell your mail from a forgery; publish a record that lists the services that send for you and ends in ~all.',
    ];
  }

  const out = [`${subject} needs ${r.lookupCount} DNS lookup${r.lookupCount === 1 ? '' : 's'} when a receiver checks it; RFC 7208 allows 10.`];
  const nodes = flatten(r.root.nodes);

  if (r.status === 'PERMERROR') {
    const first = nodes.find((n) => n.crossesLimit);
    out.push(
      `A receiver stops at the 11th${first ? ` (${first.mechanism})` : ''} and returns PermError, which DMARC treats as SPF not passing — so any server listed from there on stops passing SPF, and its mail fails DMARC unless DKIM passes.`,
    );
  } else if (r.status === 'WARNING') {
    out.push(`That is legal, but with ${LOOKUP_LIMIT - r.lookupCount} to spare, one more sending service or a provider adding a nested include will tip it into PermError.`);
  } else {
    out.push(`That leaves ${LOOKUP_LIMIT - r.lookupCount} lookups of headroom.`);
  }

  const costliest = [...r.root.nodes].sort((a, b) => b.totalCost - a.totalCost)[0];
  if (r.status !== 'PASS' && costliest && costliest.totalCost > 1) {
    out.push(`The biggest cost is ${costliest.mechanism} at ${costliest.totalCost} lookups on its own.`);
  }

  const serious = r.flags.find((f) => f.severity === 'error' && f.code !== 'duplicate-include');
  if (r.otherPermErrors.length > 0) {
    out.push(`Separately from the count, it already fails: ${r.otherPermErrors[0]}.`);
  } else if (serious) {
    out.push(serious.message.split('. ')[0]!.replace(/\.$/, '') + '.');
  } else if (r.status === 'PERMERROR') {
    out.push('The safest fix is removing includes for services you no longer use; flattening works, but goes stale when a provider changes its addresses.');
  }

  return out.slice(0, 4);
}

function flatten(nodes: CounterNode[]): CounterNode[] {
  return nodes.flatMap((n) => [n, ...flatten(n.children)]);
}

export interface CountOptions {
  domain?: string;
  record?: string;
  dns?: DnsBackend;
}

/**
 * Count one domain's lookups, or a pasted draft's. A draft may come with the domain it
 * is for, which bare `a` and `mx` need; without one, those terms are charged and noted.
 */
export async function countSpfLookups(options: CountOptions): Promise<CounterResult> {
  const domainInput = options.domain?.trim() ?? '';
  const draftInput = options.record?.trim() ?? '';
  const source: CounterResult['source'] = draftInput ? 'pasted' : 'dns';

  if (!draftInput && !domainInput) throw new InvalidDomainError('Enter a domain name, or paste a record.');
  const domain = domainInput ? normaliseFinderDomain(domainInput) : null;
  const draft = draftInput ? parseDraft(draftInput) : null;

  const dns = options.dns ?? new DnsResolver({ maxQueries: 250, deadlineMs: 20_000 });
  const evaluation = await evaluateSpf(dns, domain ?? '', {
    followBeyondLimit: true,
    ...(draft ? { record: draft.record } : {}),
  });

  const occ = evaluation.tree ? occurrences(evaluation.tree, true) : [];
  const targetCounts = new Map<string, number>();
  for (const o of occ) targetCounts.set(o.target, (targetCounts.get(o.target) ?? 0) + 1);

  const status = statusFor(evaluation.lookupCount);
  const flags = findFlags(evaluation, draft?.strings ?? [], source, occ);
  // PermErrors that have nothing to do with the count. A record at 4 lookups with two
  // SPF records published still fails, and a bare PASS would say otherwise.
  const PERMERROR_TEXT: Partial<Record<CounterFlag['code'], string>> = {
    'multiple-records': 'more than one SPF record is published',
    'void-limit': `${evaluation.voidCount} void lookups, over the limit of ${VOID_LIMIT}`,
    loop: 'an include loop',
    syntax: 'a syntax error',
  };
  const otherPermErrors = [...new Set(flags.flatMap((f) => PERMERROR_TEXT[f.code] ?? []))];

  const base = {
    source,
    domain,
    record: evaluation.record,
    strings: draft?.strings ?? [],
    found: evaluation.found,
    lookupCount: evaluation.lookupCount,
    voidCount: evaluation.voidCount,
    status,
    summary: `${evaluation.lookupCount} of ${LOOKUP_LIMIT} DNS lookups used`,
    otherPermErrors,
    root: {
      domain,
      freeTerms: COSTLY_FREE(evaluation.tree),
      nodes: evaluation.tree ? buildNodes(evaluation.tree, targetCounts) : [],
    },
    flags,
    fixes: evaluation.found ? planFixes(evaluation, occ) : null,
    truncated: evaluation.truncated,
    checkedAt: new Date().toISOString(),
  };
  return { ...base, explanation: explain(base) };
}
