import { randomBytes } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { InvalidDomainError, normaliseDomain } from '../check.js';
import { DnsResolver, QueryBudgetExceeded, type DnsBackend } from '../dns/resolver.js';
import { parseDkimRecord, parseTags } from './check.js';
import cnameProviders from '../../data/dkim-cname-providers.json';
import selectorList from '../../data/dkim-selectors.json';

/**
 * The DKIM selector finder.
 *
 * ## The problem it exists for
 *
 * A DKIM public key lives at `<selector>._domainkey.<domain>`, and there is no DNS
 * query that lists the names under `_domainkey`. You have to know the selector to look
 * it up. So "which selectors does this domain have" can only be answered by guessing,
 * and the quality of the answer is the quality of the guess list plus the honesty about
 * what a miss means. This module guesses from `data/dkim-selectors.json`, and it says
 * "not found in the list" rather than "no DKIM".
 *
 * ## Three things that are easy to get wrong
 *
 * 1. **Wildcards.** Some domains answer every `*._domainkey` query. hubspot.com and
 *    zendesk.com return an SPF record for any selector; example.com returns a
 *    structurally valid revoked key. A finder that trusts "got an answer" reports
 *    hundreds of imaginary selectors. The defence, inherited from `check.ts`: probe a
 *    random nonsense selector first, remember what it said, and discard any hit that
 *    says exactly the same thing. Hits that differ from the wildcard answer are kept —
 *    a domain can have a wildcard *and* real keys.
 *
 * 2. **CNAME delegation.** Microsoft 365, SendGrid, Postmark, HubSpot and others do not
 *    publish the key in your zone; they have you CNAME the selector name to a name in
 *    theirs. A TXT query follows that transparently, so the key is found either way —
 *    but the CNAME target is the single most reliable provider attribution there is,
 *    far better than the selector's name. It is queried for every hit and only for hits.
 *
 * 3. **The budget.** 273 selectors is a real amount of DNS. Queries run twenty at a
 *    time against a hard wall-clock budget, and when the budget is hit the result says
 *    so and returns what it has, rather than either hanging or pretending it finished.
 */

export type SelectorFlag =
  | 'revoked'
  | 'testing'
  | 'strict'
  | 'insecure-key'
  | 'weak-key'
  | 'duplicate-key'
  | 'no-version'
  | 'parse-error';

export interface FoundSelector {
  selector: string;
  /** How the record was reached. `CNAME` when the selector name points into another zone. */
  source: 'TXT' | 'CNAME';
  cnameTarget: string | null;
  providerGuess: string | null;
  /** Where the guess came from. The CNAME target is evidence; the list is a hint. */
  providerSource: 'cname' | 'list' | 'user' | null;
  keyType: string;
  keyBits: number | null;
  flags: SelectorFlag[];
  rawRecord: string;
  tags: { h?: string; s?: string; n?: string; t?: string };
}

export interface FinderResult {
  domain: string;
  checkedAt: string;
  listVersion: string;
  selectorsTried: number;
  selectorsTotal: number;
  selectorsFound: FoundSelector[];
  wildcardDetected: boolean;
  /** What the wildcard answered with, so the reader can see it rather than take our word. */
  wildcardRecord: string | null;
  /** Selectors whose only answer was the wildcard's, and were therefore discarded. */
  wildcardMatches: number;
  timedOut: boolean;
  elapsedMs: number;
  notes: string[];
  /** Custom selectors the caller supplied that did not resolve. */
  missingCustomSelectors: string[];
}

export interface FinderOptions {
  customSelectors?: readonly string[];
  concurrency?: number;
  budgetMs?: number;
  /** Injected for tests. Production builds its own resolver sized for this job. */
  dns?: DnsBackend;
}

export class DomainDoesNotResolveError extends Error {
  constructor(domain: string) {
    super(`${domain} does not resolve — no MX, A, AAAA or TXT records were found for it.`);
    this.name = 'DomainDoesNotResolveError';
  }
}

export const SELECTOR_LIST_VERSION: string = selectorList.version;
export const SELECTOR_LIST = selectorList.selectors as ReadonlyArray<{
  selector: string;
  providers: string[];
  note?: string;
}>;

const CNAME_PROVIDERS = cnameProviders.providers as Record<string, string>;

const DEFAULT_CONCURRENCY = 20;
const DEFAULT_BUDGET_MS = 8000;
export const MAX_CUSTOM_SELECTORS = 20;

/** RFC 1035 label: letters, digits, hyphens, no leading or trailing hyphen, ≤63. */
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Accepts what people paste — a domain, a URL, an address, a name with a trailing dot,
 * an internationalised name — and returns the ASCII hostname to query, or throws.
 *
 * IDNs are converted to punycode here rather than rejected, which is where this
 * differs from the main checker's normaliser: the finder's whole input is one domain,
 * so there is nothing ambiguous about converting it.
 */
export function normaliseFinderDomain(input: string): string {
  let value = input.trim();
  if (value === '') throw new InvalidDomainError('Enter a domain name.');

  // Strip scheme, path and mailbox exactly as the checker does, but *before* the IDN
  // conversion, so `https://münchen.example/x` and `me@münchen.example` both work.
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  const at = value.lastIndexOf('@');
  if (at >= 0) value = value.slice(at + 1);
  value = value.split(/[/?#]/)[0] ?? '';
  value = value.replace(/:\d+$/, '').replace(/\.$/, '');

  if (/[^\x00-\x7f]/.test(value)) {
    const ascii = domainToASCII(value);
    if (ascii === '') throw new InvalidDomainError(`"${value}" is not a valid domain name.`);
    value = ascii;
  }

  return normaliseDomain(value);
}

/** Validate and de-duplicate user-supplied selectors; the count is capped, not truncated silently. */
export function normaliseCustomSelectors(raw: readonly string[]): string[] {
  const out: string[] = [];
  for (const item of raw) {
    const selector = item.trim().toLowerCase();
    if (selector === '') continue;
    if (!LABEL.test(selector)) {
      throw new InvalidDomainError(
        `"${selector}" is not a valid selector: letters, digits and hyphens only, up to 63 characters.`,
      );
    }
    if (!out.includes(selector)) out.push(selector);
  }
  if (out.length > MAX_CUSTOM_SELECTORS) {
    throw new InvalidDomainError(`At most ${MAX_CUSTOM_SELECTORS} custom selectors per run.`);
  }
  return out;
}

/** Longest matching suffix in the CNAME provider map. */
export function providerFromCname(target: string): string | null {
  const host = target.toLowerCase().replace(/\.$/, '');
  let best: { suffix: string; provider: string } | null = null;
  for (const [suffix, provider] of Object.entries(CNAME_PROVIDERS)) {
    if (host === suffix || host.endsWith(`.${suffix}`)) {
      if (!best || suffix.length > best.suffix.length) best = { suffix, provider };
    }
  }
  return best?.provider ?? null;
}

interface Candidate {
  selector: string;
  providers: string[];
  user: boolean;
}

/**
 * Run `fn` over `items` with bounded concurrency and a wall-clock budget.
 *
 * When the budget expires nothing new is started, and the call returns whatever has
 * completed. Queries still in flight finish on their own and are discarded — the
 * alternative is a response that arrives whenever the slowest nameserver feels like it.
 */
async function pooled<T, R>(
  items: readonly T[],
  concurrency: number,
  deadline: number,
  fn: (item: T) => Promise<R>,
): Promise<{ results: (R | undefined)[]; completed: number; timedOut: boolean }> {
  const results: (R | undefined)[] = new Array(items.length);
  let cursor = 0;
  let completed = 0;
  let timedOut = false;

  const worker = async () => {
    for (;;) {
      if (Date.now() >= deadline) {
        timedOut = cursor < items.length;
        return;
      }
      const i = cursor++;
      if (i >= items.length) return;
      try {
        results[i] = await fn(items[i]!);
      } catch (err) {
        if (err instanceof QueryBudgetExceeded) {
          timedOut = true;
          return;
        }
        results[i] = undefined;
      }
      completed++;
    }
  };

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, worker);
  let wallTimer: ReturnType<typeof setTimeout> | undefined;
  const wall = new Promise<void>((resolve) => {
    wallTimer = setTimeout(resolve, Math.max(0, deadline - Date.now()));
  });
  await Promise.race([Promise.all(workers).then(() => undefined), wall]);
  clearTimeout(wallTimer);

  // One definition, whichever way we got here: the sweep is complete only if every
  // item completed. A worker that stopped on the deadline, a resolver that threw its
  // budget error, or the wall-clock race ending first all leave items unfinished.
  timedOut = completed < items.length;

  return { results, completed, timedOut };
}

function keyFlags(key: ReturnType<typeof parseDkimRecord>, tags: Record<string, string>): SelectorFlag[] {
  if (!key) return [];
  const flags: SelectorFlag[] = [];
  const t = (tags['t'] ?? '').split(':');
  if (key.revoked) flags.push('revoked');
  if (key.testing) flags.push('testing');
  if (t.includes('s')) flags.push('strict');
  if (key.parseError) flags.push('parse-error');
  if (!key.versionOk) flags.push('no-version');
  if (key.keyType === 'rsa' && key.bits !== undefined) {
    if (key.bits < 1024) flags.push('insecure-key');
    else if (key.bits === 1024) flags.push('weak-key');
  }
  return flags;
}

export async function findSelectors(input: string, options: FinderOptions = {}): Promise<FinderResult> {
  const startedAt = Date.now();
  const domain = normaliseFinderDomain(input);
  const custom = normaliseCustomSelectors(options.customSelectors ?? []);
  const budgetMs = options.budgetMs ?? DEFAULT_BUDGET_MS;
  const deadline = startedAt + budgetMs;

  const dns =
    options.dns ??
    new DnsResolver({
      timeout: 2000,
      // The main checker's default of 100 is right for a 50-query check and wrong for
      // a 300-query sweep; the wall-clock budget below is the real ceiling here.
      maxQueries: 1000,
      deadlineMs: budgetMs,
    });

  const notes: string[] = [];

  // 1. The domain has to exist. Anything with no MX, A, AAAA or apex TXT is either a
  //    typo or not a mail domain, and either way there is nothing to sweep.
  const [mx, a, aaaa, txt] = await Promise.all([dns.mx(domain), dns.a(domain), dns.aaaa(domain), dns.txt(domain)]);
  if (mx.void && a.void && aaaa.void && txt.void) throw new DomainDoesNotResolveError(domain);
  if (mx.void) notes.push('This domain publishes no MX record, so it may not receive mail — DKIM can still be set up for sending.');

  // 2. Wildcard probe, before anything is trusted.
  const probeName = `zq7x9-notreal-${randomBytes(4).toString('hex')}._domainkey.${domain}`;
  const probe = await dns.txt(probeName);
  const wildcardAnswers = new Set(probe.values.map((v) => v.trim()));
  const wildcardDkim = probe.values.find((v) => parseDkimRecord(v, 'probe', 'probe') !== null) ?? null;
  const wildcardDetected = !probe.void && probe.values.length > 0;
  if (wildcardDetected) {
    notes.push(
      wildcardDkim
        ? 'This domain has a wildcard _domainkey record that returns a DKIM-shaped answer for every selector name. Only answers that differ from it are listed below; absence of a selector here proves nothing.'
        : 'This domain answers every _domainkey query with the same non-DKIM record (usually a wildcard SPF). Those answers were discarded; a selector that returned something different is listed below.',
    );
  }

  // 3. The sweep. Custom selectors go first so a caller checking one specific name
  //    gets it inside the budget even on a slow nameserver.
  const listed = new Set(custom);
  const candidates: Candidate[] = [
    ...custom.map((selector) => ({ selector, providers: [], user: true })),
    ...SELECTOR_LIST.filter((s) => !listed.has(s.selector)).map((s) => ({
      selector: s.selector,
      providers: s.providers,
      user: false,
    })),
  ];

  let wildcardMatches = 0;

  const { results, completed, timedOut } = await pooled(candidates, options.concurrency ?? DEFAULT_CONCURRENCY, deadline, async (c) => {
    const name = `${c.selector}._domainkey.${domain}`;
    const answer = await dns.txt(name);
    if (answer.void || answer.values.length === 0) return null;

    for (const value of answer.values) {
      const trimmed = value.trim();
      if (wildcardAnswers.has(trimmed)) {
        wildcardMatches++;
        continue;
      }
      const key = parseDkimRecord(trimmed, c.selector, c.providers[0] ?? 'unknown');
      if (!key) continue;

      // Attribution: the CNAME target, when there is one, beats the list.
      const cname = await dns.cname(name);
      const target = cname.values[0]?.toLowerCase().replace(/\.$/, '') ?? null;
      const fromCname = target ? providerFromCname(target) : null;
      const tags = parseTags(trimmed);

      let providerGuess: string | null = fromCname;
      let providerSource: FoundSelector['providerSource'] = fromCname ? 'cname' : null;
      if (!providerGuess && c.user) {
        providerSource = 'user';
      } else if (!providerGuess && c.providers[0] && c.providers[0] !== 'generic' && !c.providers[0].startsWith('generic ')) {
        providerGuess = c.providers.join(' / ');
        providerSource = 'list';
      }

      const found: FoundSelector = {
        selector: c.selector,
        source: target ? 'CNAME' : 'TXT',
        cnameTarget: target,
        providerGuess,
        providerSource,
        keyType: key.keyType,
        keyBits: key.keyType === 'ed25519' ? 256 : (key.bits ?? null),
        flags: keyFlags(key, tags),
        rawRecord: trimmed,
        tags: {
          ...(tags['h'] ? { h: tags['h'] } : {}),
          ...(tags['s'] ? { s: tags['s'] } : {}),
          ...(tags['n'] ? { n: tags['n'] } : {}),
          ...(tags['t'] ? { t: tags['t'] } : {}),
        },
      };
      return found;
    }
    return null;
  });

  const selectorsFound = results.filter((r): r is FoundSelector => r !== null && r !== undefined);

  // 4. The same public key under two names is one key with two labels — usually a
  //    provider that publishes both selectors from one pair, sometimes a copy-paste.
  const byKey = new Map<string, FoundSelector[]>();
  for (const f of selectorsFound) {
    const p = parseTags(f.rawRecord)['p'];
    if (!p) continue;
    byKey.set(p, [...(byKey.get(p) ?? []), f]);
  }
  for (const group of byKey.values()) {
    if (group.length > 1) for (const f of group) f.flags.push('duplicate-key');
  }

  for (const f of selectorsFound) {
    if (f.cnameTarget?.endsWith('dkim.amazonses.com')) {
      notes.push(`${f.selector} points at Amazon SES. SES Easy DKIM issues random selectors, so any others it has will not be in this list — the SES console shows them.`);
    }
  }

  if (timedOut) {
    notes.push(`Timed out after ${completed} of ${candidates.length} selectors. The nameserver was slow; the result is partial. Re-check to try again.`);
  }

  const elapsedMs = Date.now() - startedAt;
  // Timings only: checked domains are never logged.
  console.log(JSON.stringify({ dkimFinder: true, ms: elapsedMs, tried: completed, found: selectorsFound.length, wildcard: wildcardDetected, timedOut }));

  return {
    domain,
    checkedAt: new Date().toISOString(),
    listVersion: SELECTOR_LIST_VERSION,
    selectorsTried: completed,
    selectorsTotal: candidates.length,
    selectorsFound,
    wildcardDetected,
    wildcardRecord: wildcardDetected ? (probe.values[0] ?? null) : null,
    wildcardMatches,
    timedOut,
    elapsedMs,
    notes,
    missingCustomSelectors: custom.filter((s) => !selectorsFound.some((f) => f.selector === s)),
  };
}
