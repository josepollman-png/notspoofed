import { getDomain } from 'tldts';
import { dohQuery, RR } from '../dns/doh.js';
import type { DnsBackend, MxRecord } from '../dns/resolver.js';

/**
 * The checks beyond SPF/DKIM/DMARC: MTA-STS, TLS-RPT, BIMI and DNSSEC.
 *
 * These are grouped because they share a shape — a single TXT lookup plus some
 * validation — and because they are where a free checker can still be better than
 * the incumbents. Most free tools either skip them or check only that the DNS record
 * exists, which misses the failures that actually matter:
 *
 *   - An MTA-STS DNS record with no reachable policy file does nothing at all.
 *   - A policy file listing MX hosts that don't match the real MX records causes
 *     compliant senders to *refuse delivery*. That is worse than not publishing one.
 *   - A BIMI record on a domain at p=none is ignored by every mailbox provider.
 */

// ---------------------------------------------------------------------------
// MTA-STS (RFC 8461)
// ---------------------------------------------------------------------------

export interface MtaStsPolicy {
  version?: string;
  mode?: 'enforce' | 'testing' | 'none';
  mx: string[];
  maxAge?: number;
  errors: string[];
}

export interface MtaStsResult {
  /** The `_mta-sts` TXT record, if published. */
  record: string | null;
  id?: string;
  /** Policy file fetched from https://mta-sts.<domain>/.well-known/mta-sts.txt */
  policy: MtaStsPolicy | null;
  policyError?: string;
  /** MX hosts in the live DNS that no policy `mx:` pattern covers. */
  unmatchedMx: string[];
  errors: string[];
}

/** RFC 8461 §3.2 — `mx:` entries allow a single leading `*.` wildcard label. */
export function mxMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, '');
  const h = host.toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    if (!h.endsWith(suffix)) return false;
    // The wildcard covers exactly one label, not arbitrary depth.
    return !h.slice(0, h.length - suffix.length).includes('.');
  }
  return p === h;
}

export function parseMtaStsPolicy(body: string): MtaStsPolicy {
  const policy: MtaStsPolicy = { mx: [], errors: [] };

  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '') continue;
    const colon = line.indexOf(':');
    if (colon < 0) { policy.errors.push(`malformed line "${line}"`); continue; }

    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();

    switch (key) {
      case 'version': policy.version = value; break;
      case 'mode':
        if (value === 'enforce' || value === 'testing' || value === 'none') policy.mode = value;
        else policy.errors.push(`mode "${value}" must be enforce, testing or none`);
        break;
      case 'mx': policy.mx.push(value); break;
      case 'max_age': {
        const n = Number(value);
        if (!Number.isInteger(n) || n <= 0) policy.errors.push(`max_age "${value}" must be a positive integer`);
        else policy.maxAge = n;
        break;
      }
      default: break; // unknown keys are ignored per spec
    }
  }

  if (policy.version !== 'STSv1') policy.errors.push('version must be STSv1');
  if (!policy.mode) policy.errors.push('mode is required');
  if (policy.mx.length === 0 && policy.mode !== 'none') {
    policy.errors.push('at least one mx entry is required unless mode is none');
  }
  if (policy.maxAge === undefined) policy.errors.push('max_age is required');
  else if (policy.maxAge > 31_557_600) policy.errors.push('max_age exceeds the one-year maximum');

  return policy;
}

/**
 * Fetch the policy file. Redirects are deliberately not followed (RFC 8461 §3.3
 * forbids it), the body is capped, and the URL host is derived from an already
 * validated public domain — this endpoint must never become a general fetcher.
 */
async function fetchPolicy(
  domain: string,
  timeoutMs = 6000,
): Promise<{ policy: MtaStsPolicy | null; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, {
      redirect: 'manual',
      signal: controller.signal,
      headers: { accept: 'text/plain' },
    });

    if (res.status >= 300 && res.status < 400) {
      return { policy: null, error: 'the policy URL redirects, which RFC 8461 forbids' };
    }
    if (!res.ok) {
      return { policy: null, error: `policy file returned HTTP ${res.status}` };
    }

    const body = (await res.text()).slice(0, 64_000);
    return { policy: parseMtaStsPolicy(body) };
  } catch (err) {
    const reason = (err as Error)?.name === 'AbortError' ? 'timed out' : 'could not be reached';
    return {
      policy: null,
      error: `https://mta-sts.${domain}/.well-known/mta-sts.txt ${reason} ` +
        '(this also fails if its TLS certificate is invalid)',
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkMtaSts(dns: DnsBackend, domain: string): Promise<MtaStsResult> {
  const errors: string[] = [];
  const answer = await dns.txt(`_mta-sts.${domain}`);
  const records = answer.values.filter((v) => /^v=STSv1/i.test(v.trim()));

  if (records.length === 0) {
    return { record: null, policy: null, unmatchedMx: [], errors };
  }
  if (records.length > 1) errors.push('more than one MTA-STS record published');

  const record = records[0]!;
  const id = /(?:^|;)\s*id\s*=\s*([^;]+)/i.exec(record)?.[1]?.trim();
  if (!id) errors.push('the record has no id= tag, so receivers cannot detect policy changes');

  const { policy, error } = await fetchPolicy(domain);

  // The cross-check that matters: a policy naming the wrong MX hosts makes
  // compliant senders refuse to deliver.
  let unmatchedMx: string[] = [];
  if (policy && policy.mx.length > 0) {
    const mx = await dns.mx(domain);
    unmatchedMx = mx.values
      .map((m: MxRecord) => m.exchange)
      .filter((host) => !policy.mx.some((p) => mxMatches(p, host)));
  }

  return { record, id, policy, policyError: error, unmatchedMx, errors };
}

// ---------------------------------------------------------------------------
// TLS-RPT (RFC 8460)
// ---------------------------------------------------------------------------

export interface TlsRptResult {
  record: string | null;
  rua: string[];
  errors: string[];
}

export async function checkTlsRpt(dns: DnsBackend, domain: string): Promise<TlsRptResult> {
  const answer = await dns.txt(`_smtp._tls.${domain}`);
  const records = answer.values.filter((v) => /^v=TLSRPTv1/i.test(v.trim()));
  const errors: string[] = [];

  if (records.length === 0) return { record: null, rua: [], errors };
  if (records.length > 1) errors.push('more than one TLS-RPT record published');

  const record = records[0]!;
  const ruaTag = /(?:^|;)\s*rua\s*=\s*([^;]+)/i.exec(record)?.[1]?.trim() ?? '';
  const rua = ruaTag.split(',').map((s) => s.trim()).filter(Boolean);

  if (rua.length === 0) errors.push('rua= is required — without it no reports are sent');
  for (const uri of rua) {
    if (!/^(mailto:|https:)/i.test(uri)) errors.push(`rua entry "${uri}" must be a mailto: or https: URI`);
  }

  return { record, rua, errors };
}

// ---------------------------------------------------------------------------
// BIMI
// ---------------------------------------------------------------------------

export interface BimiResult {
  record: string | null;
  /** Logo URL from `l=`. Never fetched — see note below. */
  logoUrl?: string;
  /** VMC certificate URL from `a=`. */
  vmcUrl?: string;
  errors: string[];
}

export async function checkBimi(dns: DnsBackend, domain: string): Promise<BimiResult> {
  const answer = await dns.txt(`default._bimi.${domain}`);
  const records = answer.values.filter((v) => /^v=BIMI1/i.test(v.trim()));
  const errors: string[] = [];

  if (records.length === 0) return { record: null, errors };
  if (records.length > 1) errors.push('more than one BIMI record published');

  const record = records[0]!;
  const logoUrl = /(?:^|;)\s*l\s*=\s*([^;]*)/i.exec(record)?.[1]?.trim() || undefined;
  const vmcUrl = /(?:^|;)\s*a\s*=\s*([^;]*)/i.exec(record)?.[1]?.trim() || undefined;

  // The logo URL is attacker-controlled content from a TXT record. We validate its
  // shape and stop there — fetching arbitrary URLs from user-supplied domains would
  // turn this endpoint into a general-purpose fetcher for no real benefit.
  if (!logoUrl) {
    errors.push('l= is empty, so there is no logo to display');
  } else if (!/^https:\/\//i.test(logoUrl)) {
    errors.push('the logo URL must be https');
  } else if (!/\.svg(\?|$)/i.test(logoUrl)) {
    errors.push('the logo must be an SVG (SVG Tiny Portable/Secure profile)');
  }

  if (vmcUrl && !/^https:\/\//i.test(vmcUrl)) errors.push('the VMC certificate URL must be https');

  return { record, logoUrl, vmcUrl, errors };
}

// ---------------------------------------------------------------------------
// DNSSEC
// ---------------------------------------------------------------------------

export interface DnssecResult {
  /** A DS record exists in the parent zone. */
  signed: boolean;
  /** The zone the DS was looked up for — the registrable domain. */
  zone: string;
  /** DoH was unreachable; state is genuinely unknown rather than "not signed". */
  unknown: boolean;
}

export async function checkDnssec(domain: string): Promise<DnssecResult> {
  // DS records live in the parent zone and are published per registrable domain,
  // so a subdomain inherits its parent's signing status.
  const zone = getDomain(domain) ?? domain;
  const res = await dohQuery(zone, RR.DS);

  if (res === null) return { signed: false, zone, unknown: true };
  return { signed: (res.Answer?.length ?? 0) > 0, zone, unknown: false };
}
