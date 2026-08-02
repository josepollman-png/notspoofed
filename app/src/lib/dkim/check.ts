import { createPublicKey } from 'node:crypto';
import type { DnsBackend } from '../dns/resolver.js';
import { COMMON_SELECTORS, type SelectorGuess } from './selectors.js';

/**
 * DKIM discovery.
 *
 * The trap this module exists to avoid: a TXT record existing at
 * `<selector>._domainkey.<domain>` proves nothing. Domains with a wildcard TXT record
 * answer *every* name. hubspot.com and zendesk.com both do this today — querying
 * `zzqx-bogus._domainkey.hubspot.com` returns `v=spf1 ~all`. A checker that treats
 * "got an answer" as "found a selector" will confidently report a dozen imaginary
 * DKIM keys.
 *
 * The defence is three-layered:
 *   1. Require the record to actually parse as DKIM — specifically a `p=` tag, which
 *      RFC 6376 makes mandatory. `v=DKIM1` is only RECOMMENDED, so its absence is a
 *      warning rather than a rejection.
 *   2. Probe a deliberately nonsensical selector up front. If that answers, the domain
 *      is wildcarded and we say so, because it degrades every other result.
 *   3. Discard any hit byte-identical to what the nonsense probe returned. Layer 1
 *      alone is not enough: example.com publishes a wildcard `v=DKIM1; p=`, which is
 *      a structurally valid DKIM record, so every one of our 45 guesses came back
 *      looking like a revoked key. Comparing against the wildcard's own answer is the
 *      general fix — it works whatever the wildcard happens to contain, while still
 *      letting real selectors through on domains that have both.
 */

export interface DkimKey {
  selector: string;
  provider: string;
  raw: string;
  /** Key algorithm from `k=`, defaulting to rsa per RFC 6376. */
  keyType: string;
  /** RSA modulus size. Undefined for ed25519 or an unparseable key. */
  bits?: number;
  /** `p=` present but empty — the key has been revoked. */
  revoked: boolean;
  testing: boolean;
  /** Only `v=DKIM1` is legal when the tag is present at all. */
  versionOk: boolean;
  parseError?: string;
}

export interface DkimResult {
  domain: string;
  keys: DkimKey[];
  /** Selectors tried, so the UI can be honest about coverage. */
  triedCount: number;
  /** The domain answers TXT for any name, so absence of proof is meaningless here. */
  wildcardDns: boolean;
  /** A selector the user supplied that turned out not to exist. */
  missingUserSelectors: string[];
}

interface DkimTags { [tag: string]: string }

function parseTags(raw: string): DkimTags {
  const tags: DkimTags = {};
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim().toLowerCase();
    if (name === '') continue;
    // Base64 keys are commonly wrapped across the record; strip all internal
    // whitespace so the value round-trips through a decoder.
    tags[name] = part.slice(eq + 1).replace(/\s+/g, '');
  }
  return tags;
}

/** Read the RSA modulus size out of the DER SubjectPublicKeyInfo in `p=`. */
function inspectKey(p: string, keyType: string): { bits?: number; error?: string } {
  if (keyType === 'ed25519') return {};
  try {
    const der = Buffer.from(p, 'base64');
    if (der.length === 0) return { error: 'public key is not valid base64' };
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    const bits = key.asymmetricKeyDetails?.modulusLength;
    return bits ? { bits } : {};
  } catch {
    return { error: 'public key is present but could not be parsed' };
  }
}

/**
 * Decide whether a TXT record is a real DKIM key. This is the wildcard defence —
 * everything hinges on requiring `p=`.
 */
export function parseDkimRecord(raw: string, selector: string, provider: string): DkimKey | null {
  const tags = parseTags(raw);

  // `p` is mandatory (RFC 6376 §3.6.1). Without it this is not a DKIM record,
  // whatever else it may be — an SPF record served by a wildcard, most likely.
  if (!('p' in tags)) return null;

  const version = tags['v'];
  if (version !== undefined && version.toUpperCase() !== 'DKIM1') return null;

  const keyType = (tags['k'] ?? 'rsa').toLowerCase();
  const p = tags['p'] ?? '';
  const revoked = p === '';
  const { bits, error } = revoked ? {} : inspectKey(p, keyType);

  return {
    selector,
    provider,
    raw,
    keyType,
    bits,
    revoked,
    testing: (tags['t'] ?? '').split(':').includes('y'),
    versionOk: version !== undefined,
    parseError: error,
  };
}

/** Run `jobs` with bounded concurrency so a 45-selector sweep stays polite. */
async function pooled<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]!);
    }
  });
  await Promise.all(workers);
  return results;
}

const NONSENSE_SELECTOR = 'zzqx-wildcard-probe-9f2a';

export async function checkDkim(
  dns: DnsBackend,
  domain: string,
  userSelectors: readonly string[] = [],
): Promise<DkimResult> {
  // Establish whether the domain answers for anything at all before trusting hits,
  // and remember exactly what it said so we can recognise that answer again.
  const probe = await dns.txt(`${NONSENSE_SELECTOR}._domainkey.${domain}`);
  const wildcardDns = !probe.void && probe.values.length > 0;
  const wildcardAnswers = new Set(probe.values.map((v) => v.trim()));

  const candidates: SelectorGuess[] = [
    ...userSelectors.map((s) => ({ selector: s, provider: 'user-supplied' })),
    ...COMMON_SELECTORS.filter((c) => !userSelectors.includes(c.selector)),
  ];

  const found = await pooled(candidates, 10, async ({ selector, provider }) => {
    const answer = await dns.txt(`${selector}._domainkey.${domain}`);
    if (answer.void || answer.values.length === 0) return null;
    for (const value of answer.values) {
      // The wildcard answering again tells us nothing about this selector.
      if (wildcardAnswers.has(value.trim())) continue;
      const key = parseDkimRecord(value, selector, provider);
      if (key) return key;
    }
    return null;
  });

  const keys = found.filter((k): k is DkimKey => k !== null);
  const userSet = new Set(userSelectors);

  return {
    domain,
    keys,
    triedCount: candidates.length,
    wildcardDns,
    missingUserSelectors: userSelectors.filter(
      (s) => !keys.some((k) => k.selector === s && userSet.has(s)),
    ),
  };
}
