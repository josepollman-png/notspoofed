import type { DnsBackend } from '../dns/resolver.js';
import {
  BLOCKLISTS, describeRefusal, describeSpamhausCode, isRefusalCode,
  type Blocklist,
} from './blocklists.js';

/**
 * Sending-IP diagnostic: reverse DNS, forward confirmation, and blocklist status.
 *
 * This is the tool people reach for mid-incident, which raises the bar on honesty. The
 * failure mode to design against is a *false all-clear*: a list that refuses our query
 * returns nothing useful, and reporting that as "not listed" is worse than not checking
 * at all. Refusals are surfaced as unknown, never as clean.
 */

export interface BlocklistHit {
  list: Blocklist;
  status: 'listed' | 'clean' | 'unavailable';
  /** The 127.0.0.x address the list returned. */
  code?: string;
  /** The list's own explanation, from its TXT record. */
  reason?: string;
  /** Our interpretation, where the code carries meaning. */
  meaning?: string;
}

export interface IpCheckResult {
  ip: string;
  version: 4 | 6;
  /** The hostname the caller supplied, if they gave a name rather than an address. */
  hostname?: string;
  ptr: string[];
  /** The PTR name resolves back to this same IP (FCrDNS). */
  forwardConfirmed: boolean;
  /** PTR looks auto-generated — receivers penalise these heavily. */
  genericPtr: boolean;
  asn?: { number: string; prefix: string; country: string; registry: string };
  blocklists: BlocklistHit[];
  listedOn: BlocklistHit[];
  unavailable: BlocklistHit[];
}

const PRIVATE_V4 = [
  /^0\./, /^10\./, /^127\./, /^169\.254\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./, /^192\.0\.2\./, /^198\.51\.100\./, /^203\.0\.113\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, /^(22[4-9]|2[3-5]\d)\./,
];

export function isIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

export function isIpv6(value: string): boolean {
  return value.includes(':') && /^[0-9a-f:]+$/i.test(value);
}

/** Reject anything that cannot meaningfully be a public sending address. */
export function isPublicIpv4(ip: string): boolean {
  return isIpv4(ip) && !PRIVATE_V4.some((re) => re.test(ip));
}

/** DNSBL and PTR lookups both use the reversed-octet form. */
export function reverseIpv4(ip: string): string {
  return ip.split('.').reverse().join('.');
}

/**
 * PTR names that are obviously machine-generated — they embed the address, or advertise
 * a dynamic pool. Receivers treat these as a strong negative signal, and it is a common
 * reason mail from an otherwise clean IP lands in spam.
 */
export function looksGeneric(ptr: string, ip: string): boolean {
  const host = ptr.toLowerCase().replace(/\.$/, '');
  const octets = ip.split('.');

  // The address embedded in the name, in either order and with any separator.
  const joined = octets.join('[-._]');
  if (new RegExp(joined).test(host)) return true;
  if (new RegExp([...octets].reverse().join('[-._]')).test(host)) return true;

  return /(^|[.-])(dynamic|dyn|dsl|pool|ppp|dialup|broadband|cable|client|customer|static|unassigned|no-?rdns|host)\d*[.-]/.test(host);
}

async function checkList(
  dns: DnsBackend,
  reversed: string,
  list: Blocklist,
): Promise<BlocklistHit> {
  const answer = await dns.a(`${reversed}.${list.zone}`);

  // A refusal is not an answer about the IP. Never let it read as "clean".
  const refusal = answer.values.find((v) => isRefusalCode(v));
  if (refusal) {
    return { list, status: 'unavailable', code: refusal, reason: describeRefusal(refusal) };
  }
  if (answer.error && !answer.void) {
    return { list, status: 'unavailable', reason: `lookup failed (${answer.error.toLowerCase()})` };
  }
  if (answer.values.length === 0) return { list, status: 'clean' };

  const code = answer.values[0]!;
  const txt = await dns.txt(`${reversed}.${list.zone}`);

  return {
    list,
    status: 'listed',
    code,
    reason: txt.values[0],
    meaning: list.zone === 'zen.spamhaus.org'
      ? (describeSpamhausCode(code) ?? undefined)
      : undefined,
  };
}

async function lookupAsn(
  dns: DnsBackend,
  reversed: string,
): Promise<IpCheckResult['asn']> {
  // Team Cymru's free DNS interface — no key, no rate limit worth worrying about.
  // Format: "15169 | 209.85.128.0/17 | US | arin | 2006-01-13"
  const answer = await dns.txt(`${reversed}.origin.asn.cymru.com`);
  const raw = answer.values[0];
  if (!raw) return undefined;

  const [number, prefix, country, registry] = raw.split('|').map((s) => s.trim());
  return number ? { number, prefix: prefix ?? '', country: country ?? '', registry: registry ?? '' } : undefined;
}

export async function checkIp(dns: DnsBackend, ip: string): Promise<IpCheckResult> {
  const version = isIpv6(ip) ? 6 : 4;
  const reversed = version === 4 ? reverseIpv4(ip) : '';

  const ptrAnswer = await dns.ptr(
    version === 4 ? `${reversed}.in-addr.arpa` : ip,
  );
  const ptr = ptrAnswer.values.map((p) => p.replace(/\.$/, ''));

  // Forward-confirmed reverse DNS: the PTR name must resolve back to this address.
  // A PTR alone proves nothing — anyone can point one anywhere.
  let forwardConfirmed = false;
  for (const name of ptr) {
    const forward = version === 4 ? await dns.a(name) : await dns.aaaa(name);
    if (forward.values.includes(ip)) { forwardConfirmed = true; break; }
  }

  // Most DNSBLs are IPv4-only; querying them with a v6 address yields silence, which
  // would be indistinguishable from "clean".
  const blocklists = version === 4
    ? await Promise.all(BLOCKLISTS.map((list) => checkList(dns, reversed, list)))
    : [];

  const asn = version === 4 ? await lookupAsn(dns, reversed) : undefined;

  return {
    ip,
    version,
    ptr,
    forwardConfirmed,
    genericPtr: version === 4 && ptr.length > 0 && ptr.every((p) => looksGeneric(p, ip)),
    asn,
    blocklists,
    listedOn: blocklists.filter((b) => b.status === 'listed'),
    unavailable: blocklists.filter((b) => b.status === 'unavailable'),
  };
}
