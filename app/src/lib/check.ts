import { parse } from 'tldts';
import { checkDkim } from './dkim/check.js';
import { checkDmarc } from './dmarc/check.js';
import { DnsResolver, type MxRecord, type ResolverOptions } from './dns/resolver.js';
import { checkBimi, checkDnssec, checkMtaSts, checkTlsRpt } from './modern/check.js';
import { buildReport, type Report } from './remediate.js';
import { evaluateSpf } from './spf/evaluate.js';
import { planFlattening } from './spf/flatten.js';
import type { SpfEvaluation } from './spf/evaluate.js';
import type { FlattenPlan } from './spf/flatten.js';
import type { DkimResult } from './dkim/check.js';
import type { DmarcResult } from './dmarc/check.js';
import type { BimiResult, DnssecResult, MtaStsResult, TlsRptResult } from './modern/check.js';

/**
 * Entry point: normalise user input, then run the three checks.
 *
 * Input handling is a security boundary, not a convenience. This endpoint performs
 * outbound DNS on whatever it is given, so without validation it is a free DNS
 * scanning proxy pointed at anything an attacker names. Everything not resolvable to
 * a real public domain is rejected before a single packet leaves the box.
 */

export class InvalidDomainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidDomainError';
  }
}

/**
 * Accepts what people actually paste — a bare domain, a URL, or an email address —
 * and returns the registrable hostname, or throws.
 */
export function normaliseDomain(input: string): string {
  let value = input.trim().toLowerCase();
  if (value === '') throw new InvalidDomainError('Enter a domain name.');

  // "https://example.com/pricing?x=1" → "example.com"
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  // "someone@example.com" → "example.com"
  const at = value.lastIndexOf('@');
  if (at >= 0) value = value.slice(at + 1);
  // strip path, query, port, and the root dot
  value = value.split(/[/?#]/)[0] ?? '';
  value = value.replace(/:\d+$/, '').replace(/\.$/, '');

  if (value === '') throw new InvalidDomainError('Enter a domain name.');
  if (value.length > 253) throw new InvalidDomainError('That domain name is too long to be real.');

  const parsed = parse(value, { allowPrivateDomains: false });

  // An IP literal is never a mail domain and is the obvious way to aim this at
  // internal infrastructure.
  if (parsed.isIp) {
    throw new InvalidDomainError('Enter a domain name, not an IP address.');
  }
  // Requires a real ICANN public suffix, which excludes localhost, .local, .internal,
  // .test, single-label names, and anything else that only resolves inside a network.
  if (!parsed.domain || !parsed.isIcann) {
    throw new InvalidDomainError(
      `"${value}" is not a public domain name. Check the spelling — it needs a real ` +
      'suffix like .com or .co.uk.',
    );
  }
  if (!/^[a-z0-9.-]+$/.test(value)) {
    throw new InvalidDomainError(
      'Internationalised domains must be entered in their punycode (xn--) form.',
    );
  }

  return parsed.hostname ?? value;
}

export interface CheckResult {
  domain: string;
  spf: SpfEvaluation;
  flatten: FlattenPlan | null;
  dkim: DkimResult;
  dmarc: DmarcResult;
  mtaSts: MtaStsResult;
  tlsRpt: TlsRptResult;
  bimi: BimiResult;
  dnssec: DnssecResult;
  mx: MxRecord[];
  /** RFC 7505 null MX — the domain declares that it accepts no mail at all. */
  nullMx: boolean;
  report: Report;
  /** Raw DNS queries issued. Surfaced so the cost of a check is never a mystery. */
  queryCount: number;
  elapsedMs: number;
}

export interface CheckOptions extends ResolverOptions {
  /** Selectors the user supplied because we could not guess theirs. */
  selectors?: string[];
}

export async function runCheck(input: string, options: CheckOptions = {}): Promise<CheckResult> {
  const domain = normaliseDomain(input);
  const started = Date.now();

  // One resolver for the whole check, so its cache and budget are shared. The DKIM
  // sweep alone is ~45 queries, hence the headroom over the resolver default.
  const dns = new DnsResolver({
    maxQueries: 250,
    deadlineMs: 20_000,
    ...options,
  });

  const spf = await evaluateSpf(dns, domain);

  // Everything below is independent of SPF and of each other. MTA-STS and DNSSEC
  // reach outside DNS (HTTPS policy fetch, DoH) and both fail soft, so a slow or
  // broken third party degrades one section rather than the whole report.
  const [dkim, dmarc, mtaSts, tlsRpt, bimi, dnssec, mxAnswer] = await Promise.all([
    checkDkim(dns, domain, options.selectors ?? []),
    checkDmarc(dns, domain),
    checkMtaSts(dns, domain),
    checkTlsRpt(dns, domain),
    checkBimi(dns, domain),
    checkDnssec(domain),
    dns.mx(domain),
  ]);

  // RFC 7505: a single MX whose exchange is the root label means "no mail accepted".
  // Node surfaces that root label as either '.' or an empty string.
  const mx = mxAnswer.values;
  const nullMx = mx.length === 1 && (mx[0]!.exchange === '.' || mx[0]!.exchange === '');

  const flatten = spf.limitExceeded ? planFlattening(spf) : null;
  const report = buildReport({
    domain, spf, flatten, dkim, dmarc, mtaSts, tlsRpt, bimi, dnssec, mx, nullMx,
  });

  return {
    domain, spf, flatten, dkim, dmarc, mtaSts, tlsRpt, bimi, dnssec, mx, nullMx, report,
    queryCount: dns.queryCount,
    elapsedMs: Date.now() - started,
  };
}
