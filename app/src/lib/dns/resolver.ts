import { Resolver } from 'node:dns/promises';
import { resolverAddresses } from './servers.js';

/**
 * The DNS substrate every checker sits on.
 *
 * Two things here are load-bearing and easy to get wrong:
 *
 * 1. TXT chunk joining. Node returns each TXT record as string[] because a record
 *    over 255 bytes is transmitted as multiple character-strings. RFC 7208 3.3 says
 *    they concatenate with *nothing* between them, and real records split mid-token:
 *    _hspf.hubspot.com ends one chunk with "...ip4" and starts the next with
 *    ":161.38.192.0/20". Joining on " " silently corrupts that into `ip4 :161...`.
 *
 * 2. Caching must never change a verdict. The RFC's limit counts *terms evaluated*,
 *    not packets sent, so the term counter lives in the SPF evaluator and is
 *    incremented before consulting this layer. The cache below is a latency and
 *    politeness optimisation only.
 */

export type QueryError = 'NXDOMAIN' | 'NODATA' | 'TIMEOUT' | 'SERVFAIL' | 'REFUSED' | 'OTHER';

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface Answer<T> {
  values: T[];
  /** No records of this type exist (NXDOMAIN or an empty answer section). */
  void: boolean;
  error?: QueryError;
}

export interface DnsBackend {
  txt(name: string): Promise<Answer<string>>;
  mx(name: string): Promise<Answer<MxRecord>>;
  a(name: string): Promise<Answer<string>>;
  aaaa(name: string): Promise<Answer<string>>;
  ptr(name: string): Promise<Answer<string>>;
  /** Raw queries actually issued — abuse accounting, not RFC accounting. */
  readonly queryCount: number;
}

export interface ResolverOptions {
  servers?: string[];
  /** Per-query timeout in ms. */
  timeout?: number;
  /** Hard ceiling on raw queries per evaluation. Abuse control, not an RFC limit. */
  maxQueries?: number;
  /** Wall-clock ceiling for the whole evaluation. */
  deadlineMs?: number;
}

const DEFAULTS = {
  timeout: 3000,
  maxQueries: 100,
  deadlineMs: 15000,
} satisfies Required<Omit<ResolverOptions, 'servers'>>;

export class QueryBudgetExceeded extends Error {
  constructor(what: 'queries' | 'time') {
    super(
      what === 'queries'
        ? 'DNS query budget exhausted for this request'
        : 'DNS evaluation exceeded its time budget',
    );
    this.name = 'QueryBudgetExceeded';
  }
}

function classify(err: unknown): QueryError {
  const code = (err as NodeJS.ErrnoException)?.code;
  switch (code) {
    case 'ENOTFOUND':
    case 'ENODATA':
      // c-ares reports both "name does not exist" and "name exists, no records of
      // this type" through these two codes without cleanly separating them. Both are
      // void lookups for RFC 7208 purposes, so the distinction does not affect us.
      return code === 'ENOTFOUND' ? 'NXDOMAIN' : 'NODATA';
    case 'ETIMEOUT':
    case 'ETIMEDOUT':
      return 'TIMEOUT';
    case 'ESERVFAIL':
      return 'SERVFAIL';
    case 'EREFUSED':
      return 'REFUSED';
    default:
      return 'OTHER';
  }
}

/** A void lookup per RFC 7208 4.6.4: the name yielded no usable records. */
function isVoid(e: QueryError): boolean {
  return e === 'NXDOMAIN' || e === 'NODATA';
}

export class DnsResolver implements DnsBackend {
  readonly #resolver: Resolver;
  readonly #opts: Required<Omit<ResolverOptions, 'servers'>>;
  readonly #cache = new Map<string, Promise<Answer<unknown>>>();
  readonly #startedAt = Date.now();
  #queries = 0;
  /** Server discovery is async, so the first query waits on it. */
  #ready: Promise<void>;

  constructor(opts: ResolverOptions = {}) {
    this.#opts = { ...DEFAULTS, ...opts };
    this.#resolver = new Resolver({ timeout: this.#opts.timeout, tries: 2 });

    if (opts.servers) {
      this.#resolver.setServers(opts.servers);
      this.#ready = Promise.resolve();
    } else {
      this.#ready = resolverAddresses().then((servers) => {
        this.#resolver.setServers(servers);
      });
    }
  }

  get queryCount(): number {
    return this.#queries;
  }

  get elapsedMs(): number {
    return Date.now() - this.#startedAt;
  }

  #budgetCheck(): void {
    if (this.#queries >= this.#opts.maxQueries) throw new QueryBudgetExceeded('queries');
    if (this.elapsedMs > this.#opts.deadlineMs) throw new QueryBudgetExceeded('time');
  }

  #run<T>(type: string, name: string, fn: () => Promise<T[]>): Promise<Answer<T>> {
    const key = `${type}:${name.toLowerCase()}`;
    const hit = this.#cache.get(key);
    if (hit) return hit as Promise<Answer<T>>;

    // Budget is charged per distinct query; a cache hit is free because no packet
    // leaves the box. RFC term-counting is handled by the caller and is unaffected.
    this.#budgetCheck();
    this.#queries++;

    const p = this.#ready.then(fn).then(
      (values): Answer<T> => ({ values, void: values.length === 0 }),
      (err): Answer<T> => {
        const error = classify(err);
        return { values: [], void: isVoid(error), error };
      },
    );
    this.#cache.set(key, p as Promise<Answer<unknown>>);
    return p;
  }

  txt(name: string): Promise<Answer<string>> {
    // The '' join is the whole point — see the note at the top of this file.
    return this.#run('TXT', name, async () =>
      (await this.#resolver.resolveTxt(name)).map((chunks) => chunks.join('')),
    );
  }

  mx(name: string): Promise<Answer<MxRecord>> {
    return this.#run('MX', name, () => this.#resolver.resolveMx(name));
  }

  a(name: string): Promise<Answer<string>> {
    return this.#run('A', name, () => this.#resolver.resolve4(name));
  }

  aaaa(name: string): Promise<Answer<string>> {
    return this.#run('AAAA', name, () => this.#resolver.resolve6(name));
  }

  ptr(name: string): Promise<Answer<string>> {
    return this.#run('PTR', name, () => this.#resolver.resolvePtr(name));
  }
}
