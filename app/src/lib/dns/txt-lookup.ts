import type { DnsBackend, QueryError } from './resolver.js';

/**
 * One TXT policy lookup — `_dmarc`, `_mta-sts`, `_smtp._tls`, `default._bimi` — with
 * the evidence to back whatever it concludes.
 *
 * The checks used to call `dns.txt()` and read "no matching value" as "not published".
 * That conflated two different things. NXDOMAIN and NODATA are answers: the name, or
 * the record, does not exist. SERVFAIL, a timeout or a refusal is the absence of an
 * answer, and reporting it as "no DMARC record" is a false negative about the one
 * question the domain owner came to ask. It showed up on costco.com, whose `_dmarc` is
 * a CNAME into Proofpoint: the chain needs a second zone resolved, a cold cache
 * occasionally answers SERVFAIL, and the report said the domain had no policy when it
 * publishes `p=reject`.
 *
 * So this returns a status, not just values:
 *
 * - `found`   — at least one value matched the record type.
 * - `absent`  — the DNS said so: NXDOMAIN, NODATA, or TXT values of some other kind.
 * - `unknown` — no answer, after one retry. Callers must say "could not check", never
 *               "not published".
 *
 * CNAMEs are followed by the recursive resolver, as they are for every other lookup
 * here. The chain is also walked explicitly, a hop at a time, so the report can say
 * where a record really lives ("via CNAME to …pphosted.com") and so an absence can say
 * what came back. When the resolver fails on the chain as a whole, the final target is
 * asked directly — the same record, one step closer.
 */

/** Hops walked before giving up. Resolvers allow more; a policy record needs far fewer. */
export const CNAME_HOP_LIMIT = 5;

export type TxtOutcome = 'records' | 'other-txt' | 'NXDOMAIN' | 'NODATA' | QueryError;

export interface TxtLookup {
  /** The name queried, e.g. `_dmarc.example.com`. */
  name: string;
  status: 'found' | 'absent' | 'unknown';
  /** Values that matched the record type. */
  records: string[];
  /** What the lookup returned, in words a report can quote. */
  outcome: TxtOutcome;
  /** CNAME targets from `name` onwards, in order. Empty when `name` is not an alias. */
  cnameChain: string[];
  /** Set when the chain loops or runs past the hop limit. */
  cnameProblem?: 'loop' | 'too-long';
}

const TRANSIENT = new Set<QueryError>(['SERVFAIL', 'TIMEOUT', 'REFUSED', 'OTHER']);

const strip = (name: string) => name.toLowerCase().replace(/\.$/, '');

/** Walk the alias chain one CNAME query at a time. */
export async function walkCnames(
  dns: DnsBackend,
  name: string,
): Promise<{ chain: string[]; problem?: 'loop' | 'too-long' }> {
  const chain: string[] = [];
  const seen = new Set([strip(name)]);
  let current = name;

  for (let hop = 0; hop < CNAME_HOP_LIMIT; hop++) {
    const answer = await dns.cname(current);
    const target = answer.values[0];
    if (!target) return { chain };
    const next = strip(target);
    if (seen.has(next)) return { chain: [...chain, next], problem: 'loop' };
    seen.add(next);
    chain.push(next);
    current = next;
  }

  // Still aliasing after the limit: say so rather than guess.
  const more = (await dns.cname(current)).values.length > 0;
  return more ? { chain, problem: 'too-long' } : { chain };
}

async function queryTxt(dns: DnsBackend, name: string) {
  let answer = await dns.txt(name);
  // One retry for a transient failure. The resolver does not cache those, so this
  // reaches the network again; a second SERVFAIL is reported as unknown.
  if (answer.error && TRANSIENT.has(answer.error)) answer = await dns.txt(name);
  return answer;
}

export async function lookupTxt(
  dns: DnsBackend,
  name: string,
  isRecord: (value: string) => boolean,
): Promise<TxtLookup> {
  const answer = await queryTxt(dns, name);
  const { chain, problem } = await walkCnames(dns, name);
  const base = { name, cnameChain: chain, ...(problem ? { cnameProblem: problem } : {}) };

  let values = answer.values;
  let error = answer.error;

  // The resolver could not follow the chain as a whole. Ask the final target itself,
  // unless the chain is broken, in which case there is nothing sound to ask.
  if (error && TRANSIENT.has(error) && chain.length > 0 && !problem) {
    const direct = await queryTxt(dns, chain[chain.length - 1]!);
    values = direct.values;
    error = direct.error;
  }

  const records = values.filter((v) => isRecord(v.trim()));
  if (records.length > 0) return { ...base, status: 'found', records, outcome: 'records' };

  // A looping or endless chain never yields a record, whatever the resolver said.
  if (problem) return { ...base, status: 'absent', records: [], outcome: error ?? 'NODATA' };

  if (error && TRANSIENT.has(error)) return { ...base, status: 'unknown', records: [], outcome: error };
  if (error === 'NXDOMAIN') return { ...base, status: 'absent', records: [], outcome: 'NXDOMAIN' };
  if (values.length > 0) return { ...base, status: 'absent', records: [], outcome: 'other-txt' };
  return { ...base, status: 'absent', records: [], outcome: 'NODATA' };
}

/**
 * The evidence for a result, as one sentence: what was queried and what came back.
 * Absence is a stronger claim than presence, so it never appears without this.
 */
export function describeLookup(lookup: TxtLookup): string {
  const via = lookup.cnameChain.length > 0
    ? ` (a CNAME to ${lookup.cnameChain.join(' → ')})`
    : '';
  const q = `${lookup.name}${via}`;

  if (lookup.cnameProblem === 'loop') return `${q} is a CNAME loop, so no record can be reached.`;
  if (lookup.cnameProblem === 'too-long') {
    return `${q} is a CNAME chain longer than ${CNAME_HOP_LIMIT} hops; we stopped following it.`;
  }

  switch (lookup.outcome) {
    case 'records':
      return lookup.cnameChain.length > 0
        ? `Found at ${lookup.cnameChain[lookup.cnameChain.length - 1]}, via a CNAME from ${lookup.name}.`
        : `Found at ${lookup.name}.`;
    case 'NXDOMAIN':
      return lookup.cnameChain.length > 0
        ? `Queried ${q}: the CNAME target does not exist (NXDOMAIN).`
        : `Queried ${q}: the name does not exist (NXDOMAIN).`;
    case 'NODATA':
      return lookup.cnameChain.length > 0
        ? `Queried ${q}: the CNAME target has no TXT record.`
        : `Queried ${q}: the name exists but has no TXT record (NODATA).`;
    case 'other-txt':
      return `Queried ${q}: TXT records exist there, but none is this kind of record.`;
    default:
      return `Queried ${q}: no answer (${lookup.outcome}), after a retry.`;
  }
}
