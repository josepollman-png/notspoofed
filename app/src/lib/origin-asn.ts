/**
 * "Is this address a rented machine?" — for the traffic counters only.
 *
 * Server-only. Never import this from anything under `lib/headers/`.
 *
 * Three properties this has to have, because it runs on the hot path of every page view:
 *
 * 1. **It never blocks a response.** The only caller is the fire-and-forget metrics
 *    write, and a Cymru timeout must cost a counter, not a page.
 * 2. **It queries at most once per /24 per week.** A lookup per request would put a DNS
 *    query in front of every page load for a number nobody reads in real time.
 * 3. **It stores no address.** The Redis key is the /24 prefix, which is a property of
 *    the network rather than of a visitor, and the cached value is an AS number. Nothing
 *    here can reconstruct who visited — see the note at the top of stats.ts.
 */

import { DnsResolver } from './dns/resolver.js';
import { isHostingAsn } from './hosting-asns.js';
import { isPublicIpv4, isIpv4, reverseIpv4 } from './ip/check.js';
import { markRedisDead, redis } from './redis.js';

const CACHE_PREFIX = 'mailcheck:asn';
const CACHE_TTL_SECONDS = 7 * 86400;
/** Short: a slow answer is worth less than a fast page, and the fallback is "human". */
const LOOKUP_TIMEOUT_MS = 1500;
/** Negative marker, so a network with no origin AS is not re-queried every request. */
const NONE = '-';

/** Group by /24. ASN assignment is a property of the prefix, not of one address, and
 *  this keeps the cache small and the stored value coarse. */
function prefixKey(ip: string): string {
  return ip.split('.').slice(0, 3).join('.');
}

async function lookupOriginAsn(ip: string): Promise<string> {
  // Team Cymru's free DNS interface: "15169 | 209.85.128.0/17 | US | arin | 2006-01-13".
  // A dedicated one-shot resolver rather than the request's — the per-request query
  // budget exists to bound what a visitor can make us do, and this is our own overhead.
  const dns = new DnsResolver({ timeout: LOOKUP_TIMEOUT_MS, maxQueries: 2, deadlineMs: LOOKUP_TIMEOUT_MS });
  const answer = await dns.txt(`${reverseIpv4(ip)}.origin.asn.cymru.com`);
  const asn = answer.values[0]?.split('|')[0]?.trim();
  return asn && /^\d{1,10}$/.test(asn) ? asn : NONE;
}

/**
 * Resolves to the origin AS number, or null when it cannot be determined.
 *
 * Unknown is reported as unknown. Callers treat that as "not a datacenter", so a Cymru
 * outage quietly stops filtering rather than silently reclassifying every visitor —
 * the same principle the checker itself follows for refused blocklist queries.
 */
export async function originAsn(ip: string | null): Promise<string | null> {
  // IPv6 is not covered: Cymru's origin zone needs a different query format, and the
  // traffic in question is overwhelmingly v4. Better to skip than to guess.
  if (!ip || !isIpv4(ip) || !isPublicIpv4(ip)) return null;

  const r = redis();
  const key = `${CACHE_PREFIX}:${prefixKey(ip)}`;

  if (r) {
    try {
      const hit = await r.get(key);
      if (hit) return hit === NONE ? null : hit;
    } catch {
      markRedisDead();
    }
  }

  let asn: string;
  try {
    asn = await lookupOriginAsn(ip);
  } catch {
    return null;
  }

  if (r) {
    try {
      await r.set(key, asn, 'EX', CACHE_TTL_SECONDS);
    } catch {
      markRedisDead();
    }
  }

  return asn === NONE ? null : asn;
}

/** True only when we positively identified a hosting network. Unknown is not a bot. */
export async function isDatacenterIp(ip: string | null): Promise<boolean> {
  return isHostingAsn(await originAsn(ip));
}
