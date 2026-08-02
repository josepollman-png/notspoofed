import type { Answer, DnsBackend, MxRecord } from '../src/lib/dns/resolver.js';

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
}

export class FakeDns implements DnsBackend {
  #queries = 0;
  readonly log: string[] = [];

  constructor(private readonly zone: Zone) {}

  get queryCount(): number {
    return this.#queries;
  }

  #lookup<T>(type: keyof Zone, name: string): Answer<T> {
    this.#queries++;
    this.log.push(`${type} ${name}`);

    const table = (this.zone[type] ?? {}) as Record<string, T[]>;
    const key = name.toLowerCase().replace(/\.$/, '');

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
}
