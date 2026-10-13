import type { DnsBackend, QueryError } from '../dns/resolver.js';
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

/**
 * One evaluated term that costs a lookup, with the counters as they stood when the
 * receiver reached it. The running totals follow RFC 7208's evaluation order — depth
 * first, left to right — so `lookupsAfter` is the exact point at which a receiver would
 * give up with a PermError. The lookup counter tool draws its tree from these.
 */
export interface SpfChild {
  term: Term;
  node: SpfNode | null;
  skipped?: string;
  /** Lookups charged so far, including this term. */
  lookupsAfter?: number;
  /** Void lookups caused by this term's own query (not its children's). */
  voids?: number;
  /** Void lookups so far, including this term's own. */
  voidsAfter?: number;
}

export interface SpfNode {
  domain: string;
  record: string | null;
  parsed: ParsedRecord | null;
  /** Populated for include/redirect terms that were followed. */
  children: SpfChild[];
  /** Addresses contributed by this record's own terms, excluding its children.
   *  Kept per-node so flattening can replace one include at a time rather than
   *  demolishing the entire record. */
  ownIp4: string[];
  ownIp6: string[];
  error?: string;
  /** Void lookups caused by fetching this node's own TXT record. */
  fetchVoids?: number;
}

export interface EvaluateOptions {
  /**
   * Evaluate this record at the root instead of fetching the domain's own — a draft
   * pasted into the lookup counter. Includes below it are still resolved live.
   */
  record?: string;
  /**
   * Keep following includes past the 10th lookup. A receiver stops there, and the
   * checker does too; the lookup counter needs the whole tree to show what flattening
   * would have to remove. Counting is unchanged either way.
   */
  followBeyondLimit?: boolean;
}

export interface SpfProblem {
  code: string;
  message: string;
  /** Where in the include graph it surfaced. */
  domain: string;
  /** For a syntax error in one term: the term as written. */
  term?: string;
  /** For a syntax error that is two terms run together: the corrected pair. */
  suggestion?: string;
  /**
   * For a record that could not be fetched: whether an include or a redirect= led to
   * it. The RFC treats the two differently — a redirect target with no record is a
   * permerror under §6.1, an include target under §5.2 — and the report says which.
   */
  via?: 'include' | 'redirect';
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
   * Why a receiver following RFC 7208 would return permerror for this record, or null.
   * When set, `lookupCount` is informational: a receiver never gets to count, or stops
   * counting, because the record is broken.
   */
  permerror: string | null;
  /**
   * The apex TXT lookup got no answer (SERVFAIL, timeout) even after a retry. `found`
   * is then false for want of an answer, not because the domain publishes nothing.
   */
  lookupError: QueryError | null;
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
  lookupError: QueryError | null;
  options: EvaluateOptions;
}

function problem(state: State, domain: string, code: string, message: string): void {
  if (!state.problems.some((p) => p.code === code && p.domain === domain)) {
    state.problems.push({ code, message, domain });
  }
}

/** Fetch the single SPF record for a name, reporting the RFC's error cases. */
const TRANSIENT = new Set<QueryError>(['SERVFAIL', 'TIMEOUT', 'REFUSED', 'OTHER']);

async function fetchSpf(
  state: State,
  domain: string,
): Promise<{ record: string | null; error?: string; dnsError?: QueryError }> {
  let answer = await state.dns.txt(domain);
  // One retry for a failure that is not an answer. The resolver keeps no cache of
  // those, so this reaches the network again.
  if (answer.error && TRANSIENT.has(answer.error)) answer = await state.dns.txt(domain);

  if (answer.void) {
    state.voids++;
    return {
      record: null,
      error: answer.error === 'NXDOMAIN'
        ? 'no SPF record published (the name does not exist, NXDOMAIN)'
        : 'no SPF record published (the name has no TXT records)',
    };
  }
  if (answer.error) {
    return { record: null, error: `DNS ${answer.error.toLowerCase()}`, dnsError: answer.error };
  }

  const spf = answer.values.filter(isSpfRecord);
  if (spf.length === 0) {
    // The name exists and has TXT records, just none of them SPF. Still a void
    // lookup for limit purposes — nothing usable came back.
    state.voids++;
    return { record: null, error: 'no SPF record published (it has TXT records, none of them SPF)' };
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
  via?: 'include' | 'redirect',
): Promise<SpfNode> {
  const node: SpfNode = {
    domain, record: null, parsed: null, children: [], ownIp4: [], ownIp6: [],
  };

  const voidsBefore = state.voids;
  const { record, error, dnsError } = path.length === 0 && state.options.record !== undefined
    ? { record: state.options.record, error: undefined, dnsError: undefined }
    : await fetchSpf(state, domain);
  node.fetchVoids = state.voids - voidsBefore;
  if (error) {
    node.error = error;
    // A DNS failure is not "no record": the first is unknown, the second a fact.
    const code = error.startsWith('PermError') ? 'multiple-records' : dnsError ? 'dns-error' : 'no-record';
    problem(state, domain, code, error);
    if (via) {
      const p = state.problems.find((x) => x.code === code && x.domain === domain);
      if (p && !p.via) p.via = via;
    }
    if (dnsError && path.length === 0) state.lookupError = dnsError;
  }
  if (!record) return node;

  node.record = record;
  const parsed = parseSpf(record);
  node.parsed = parsed;
  // One problem per malformed term, so each is named with its own fix.
  for (const t of parsed.terms) {
    if (!t.error) continue;
    state.problems.push({
      code: 'syntax', domain, term: t.raw, message: `malformed term "${t.raw}": ${t.error}`,
      ...(t.suggestion ? { suggestion: t.suggestion } : {}),
    });
  }
  for (const e of parsed.recordErrors) state.problems.push({ code: 'syntax', domain, message: e });
  for (const w of parsed.warnings) problem(state, domain, 'dead-terms', w);

  const hasAll = parsed.terms.some((t) => t.name === 'all' && t.kind === 'mechanism');

  for (const term of parsed.terms) {
    // Free mechanisms: harvest addresses for flattening, then move on. A malformed
    // address is not an address, and must never reach a suggested record.
    if (term.name === 'ip4' && term.value) {
      if (!term.error) { state.ip4.add(term.value); node.ownIp4.push(term.value); }
      continue;
    }
    if (term.name === 'ip6' && term.value) {
      if (!term.error) { state.ip6.add(term.value); node.ownIp6.push(term.value); }
      continue;
    }
    if (!term.costsLookup) continue;

    // RFC 7208 §6.1: with an `all` in the record, redirect= is ignored — a receiver
    // never fetches it, so it is neither charged nor followed. The parser warns.
    if (term.name === 'redirect' && hasAll) {
      node.children.push({ term, node: null, skipped: 'ignored — the record has an all mechanism' });
      continue;
    }

    // Charged before the query, and charged even when we decline to follow it —
    // the limit counts terms evaluated, not packets sent.
    state.lookups++;
    const lookupsAfter = state.lookups;
    const voidsBefore = state.voids;
    const push = (entry: { node: SpfNode | null; skipped?: string }, voids = 0): void => {
      node.children.push({
        term, ...entry, lookupsAfter, voids, voidsAfter: voidsBefore + voids,
      });
    };

    if (term.hasMacro) {
      // %{i} and friends expand from the connecting client's IP. There is no honest
      // static answer, so we count the lookup and say so rather than guessing.
      state.macros.push(term);
      push({ node: null, skipped: 'macro — not statically evaluable' });
      continue;
    }

    if (state.lookups > LOOKUP_LIMIT && !state.options.followBeyondLimit) {
      push({ node: null, skipped: 'beyond the 10-lookup limit' });
      continue;
    }

    if (term.name === 'ptr') {
      problem(state, domain, 'ptr-deprecated',
        'the ptr mechanism is deprecated (RFC 7208 §5.5) and many receivers ignore it');
      push({ node: null, skipped: 'ptr not followed' });
      continue;
    }

    if (term.name === 'a' || term.name === 'mx') {
      const target = term.value ?? domain;
      if (!target) {
        // A pasted draft with no domain: a bare `a` or `mx` means "this domain", and
        // there is none to ask about. Charged, not guessed.
        push({ node: null, skipped: 'needs the domain the record is for' });
        continue;
      }
      await resolveAddresses(state, node, term, target, domain);
      push({ node: null }, state.voids - voidsBefore);
      continue;
    }

    if (term.name === 'exists') {
      push({ node: null, skipped: 'exists — presence check only' });
      continue;
    }

    // include / redirect
    const target = term.value;
    if (!target) {
      push({ node: null, skipped: 'no target' });
      continue;
    }
    if (path.includes(target.toLowerCase())) {
      problem(state, domain, 'loop', `include loop: ${[...path, target].join(' → ')}`);
      push({ node: null, skipped: 'loop detected' });
      continue;
    }

    const child = await walk(state, target, [...path, domain.toLowerCase()], term.name === 'redirect' ? 'redirect' : 'include');
    push({ node: child }, child.fetchVoids ?? 0);
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
 * Which record's `all` decides the fate of an unlisted sender, and whether we know.
 *
 * A record whose only term is `redirect=` has no `all` of its own — hubspot.com is
 * exactly this. RFC 7208 §6.1: when nothing matches, the redirect target's record
 * *replaces* this one, so its `all` is the operative policy. Reading only the apex
 * would report "no policy" for a domain that is in fact publishing `-all`.
 *
 * - `all`        — found: `term` in `node`, which is the apex or a redirect target.
 * - `none`       — the chain ends in a record with neither `all` nor `redirect=`.
 * - `unresolved` — a redirect= was not followed to a record: the lookup failed, the
 *                  target publishes none, or it was a macro, a loop or past the limit.
 *                  Nothing can be said about `all` then, and above all a missing one
 *                  must not be reported: the record ends in redirect= by design.
 */
export type AllSource =
  | { status: 'all'; node: SpfNode; term: Term }
  | { status: 'none'; node: SpfNode }
  | { status: 'unresolved'; node: SpfNode; redirect: SpfChild };

export function allSource(node: SpfNode | null): AllSource | null {
  if (!node?.parsed) return null;

  const all = node.parsed.terms.find((t) => t.name === 'all' && t.kind === 'mechanism');
  if (all) return { status: 'all', node, term: all };

  const redirect = node.children.find((c) => c.term.name === 'redirect');
  if (!redirect) return { status: 'none', node };
  // No `all` here: fall through the redirect, if it reached a record.
  if (!redirect.node?.parsed) return { status: 'unresolved', node, redirect };
  return allSource(redirect.node);
}

function effectiveAll(node: SpfNode | null): string | null {
  const source = allSource(node);
  return source?.status === 'all' ? source.term.qualifier : null;
}

/**
 * The first reason a spec-following receiver would return permerror, in the order it
 * would hit them. RFC 7208: several SPF records (§4.5), a syntax error anywhere it
 * evaluates (§4.6), an include whose target publishes no record (§5.2), more than ten
 * lookups or two void lookups (§4.6.4), and an mx that fans out past ten hosts.
 *
 * `redirect=` alongside `all` is deliberately absent: §6.1 says the redirect is then
 * ignored, which is a mistake worth a warning but not an error.
 */
function permerrorReason(state: State, apex: string): string | null {
  const first = (code: string) => state.problems.find((p) => p.code === code);
  const multiple = first('multiple-records');
  if (multiple) return multiple.domain === apex ? 'more than one SPF record is published' : `${multiple.domain} publishes more than one SPF record`;
  const syntax = first('syntax');
  if (syntax) return syntax.term ? `malformed term "${syntax.term}"` : syntax.message;
  const missing = state.problems.find((p) => p.code === 'no-record' && p.domain !== apex);
  if (missing) {
    return missing.via === 'redirect'
      ? `the redirect= target ${missing.domain} publishes no SPF record`
      : `${missing.domain} is included but publishes no SPF record`;
  }
  if (first('loop')) return 'an include loop';
  if (state.lookups > LOOKUP_LIMIT) return `${state.lookups} DNS lookups, over the limit of ${LOOKUP_LIMIT}`;
  if (state.voids > VOID_LIMIT) return `${state.voids} void lookups, over the limit of ${VOID_LIMIT}`;
  if (first('mx-fanout')) return 'an mx mechanism returns more than 10 hosts';
  return null;
}

export async function evaluateSpf(
  dns: DnsBackend,
  domain: string,
  options: EvaluateOptions = {},
): Promise<SpfEvaluation> {
  const state: State = {
    dns, lookups: 0, voids: 0, problems: [],
    ip4: new Set(), ip6: new Set(), macros: [], truncated: false, lookupError: null, options,
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
    permerror: permerrorReason(state, domain),
    lookupError: state.lookupError,
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
