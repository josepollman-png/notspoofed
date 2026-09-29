import type { Answer, DnsBackend, MxRecord, QueryError } from '../src/lib/dns/resolver.js';

/**
 * A DnsBackend backed by a fixture map, so the interesting cases can be tested
 * deterministically. Live DNS belongs in *.live.test.ts and proves we agree with
 * reality; these fixtures prove we agree with the RFC, including situations too rare
 * or too transient to find in the wild on demand.
 *
 * Names ending in a leading `*.` act as wildcards, mirroring the wildcard TXT records
 * that make DKIM discovery unreliable on real domains.
 */

export interface Zone {
  TXT?: Record<string, string[]>;
  MX?: Record<string, MxRecord[]>;
  A?: Record<string, string[]>;
  AAAA?: Record<string, string[]>;
  PTR?: Record<string, string[]>;
  CNAME?: Record<string, string[]>;
  /**
   * Failures to return instead of an answer, keyed `"TXT _dmarc.example.com"`. A list
   * is consumed one entry per query, so `['SERVFAIL']` fails once and then answers —
   * the transient failure a retry exists for.
   */
  ERRORS?: Record<string, QueryError | QueryError[]>;
}

/** Recursive resolvers give up on a chain this long; so does the fixture. */
const CHAIN_LIMIT = 8;

export class FakeDns implements DnsBackend {
  #queries = 0;
  readonly log: string[] = [];

  constructor(private readonly zone: Zone) {}

  get queryCount(): number {
    return this.#queries;
  }

  #lookup<T>(type: Exclude<keyof Zone, 'ERRORS'>, name: string): Answer<T> {
    this.#queries++;
    this.log.push(`${type} ${name}`);

    const key = name.toLowerCase().replace(/\.$/, '');
    const injected = this.zone.ERRORS?.[`${type} ${key}`];
    if (injected !== undefined) {
      const error = Array.isArray(injected) ? injected.shift() : injected;
      if (error) return { values: [], void: error === 'NXDOMAIN' || error === 'NODATA', error };
    }

    // A recursive resolver answers a TXT query at an alias with the target's records,
    // so the fixture does too. A loop or an over-long chain is SERVFAIL, as it is there.
    if (type === 'TXT' && !(key in (this.zone.TXT ?? {})) && this.zone.CNAME?.[key]) {
      const seen = new Set([key]);
      let current = key;
      for (let hop = 0; hop < CHAIN_LIMIT; hop++) {
        const next = this.zone.CNAME?.[current]?.[0]?.toLowerCase().replace(/\.$/, '');
        if (!next) break;
        if (seen.has(next)) return { values: [], void: false, error: 'SERVFAIL' };
        seen.add(next);
        current = next;
        if (current in (this.zone.TXT ?? {})) break;
      }
      if (this.zone.CNAME?.[current]) return { values: [], void: false, error: 'SERVFAIL' };
      const values = (this.zone.TXT ?? {})[current] as T[] | undefined;
      if (!values) return { values: [], void: true, error: 'NXDOMAIN' };
      return { values, void: values.length === 0 };
    }

    const table = (this.zone[type] ?? {}) as Record<string, T[]>;

    if (key in table) return { values: table[key]!, void: table[key]!.length === 0 };

    // Longest-suffix wildcard match: "*.＿domainkey.example.com" style entries.
    for (const pattern of Object.keys(table)) {
      if (!pattern.startsWith('*.')) continue;
      if (key.endsWith(pattern.slice(1))) {
        return { values: table[pattern]!, void: false };
      }
    }

    return { values: [], void: true, error: 'NXDOMAIN' };
  }

  txt(name: string): Promise<Answer<string>> {
    return Promise.resolve(this.#lookup<string>('TXT', name));
  }
  mx(name: string): Promise<Answer<MxRecord>> {
    return Promise.resolve(this.#lookup<MxRecord>('MX', name));
  }
  a(name: string): Promise<Answer<string>> {
    return Promise.resolve(this.#lookup<string>('A', name));
  }
  aaaa(name: string): Promise<Answer<string>> {
    return Promise.resolve(this.#lookup<string>('AAAA', name));
  }
  ptr(name: string): Promise<Answer<string>> {
    return Promise.resolve(this.#lookup<string>('PTR', name));
  }
  cname(name: string): Promise<Answer<string>> {
    return Promise.resolve(this.#lookup<string>('CNAME', name));
  }
}
