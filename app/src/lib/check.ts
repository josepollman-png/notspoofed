import { parse } from 'tldts';
import { checkDkim } from './dkim/check.js';
import { checkDmarc } from './dmarc/check.js';
import { DnsResolver, type DnsBackend, type MxRecord, type ResolverOptions } from './dns/resolver.js';
import { walkCnames } from './dns/txt-lookup.js';
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

/** True for a name that is itself a public suffix, such as `gov.uk`, `co.uk` or `com`. */
export function isPublicSuffix(domain: string): boolean {
  const parsed = parse(domain, { allowPrivateDomains: false });
  return !parsed.domain && parsed.isIcann === true && parsed.publicSuffix === domain;
}

export interface NormaliseOptions {
  /**
   * Accept a public suffix itself (`gov.uk`). The checker does, and then checks only
   * one that publishes SPF or DMARC; the single-purpose tools do not.
   */
  allowPublicSuffix?: boolean;
}

/**
 * Accepts what people actually paste — a bare domain, a URL, or an email address —
 * and returns the registrable hostname, or throws.
 */
export function normaliseDomain(input: string, options: NormaliseOptions = {}): string {
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
  // A public suffix is spelled correctly and is public: gov.uk publishes DMARC. It was
  // rejected below with "check the spelling", which was wrong on both counts.
  if (!parsed.domain && parsed.isIcann && parsed.publicSuffix === value && /^[a-z0-9.-]+$/.test(value)) {
    if (options.allowPublicSuffix) return value;
    throw new InvalidDomainError(
      `"${value}" is a public suffix — names are registered under it, like ` +
      `example.${value} — and public suffixes are not checked here. Enter a domain ` +
      'registered under it.',
    );
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
  /** The CNAME chain at the checked name, when it is an alias. Usually empty. */
  domainCnameChain: string[];
  /** The checked name is itself a public suffix, such as gov.uk. */
  publicSuffix: boolean;
  report: Report;
  /** Raw DNS queries issued. Surfaced so the cost of a check is never a mystery. */
  queryCount: number;
  elapsedMs: number;
}

export interface CheckOptions extends ResolverOptions {
  /** Selectors the user supplied because we could not guess theirs. */
  selectors?: string[];
  /**
   * Answer DNS from this backend instead of a live resolver. For replaying recorded
   * answers in tests and before/after comparisons; production never sets it.
   */
  dns?: DnsBackend;
  /** Stands in for the DoH DNSSEC lookup, for the same reason. */
  dnssec?: (domain: string) => Promise<DnssecResult>;
}

export async function runCheck(input: string, options: CheckOptions = {}): Promise<CheckResult> {
  const domain = normaliseDomain(input, { allowPublicSuffix: true });
  const publicSuffix = isPublicSuffix(domain);
  const started = Date.now();

  // One resolver for the whole check, so its cache and budget are shared. The DKIM
  // sweep alone is ~45 queries, hence the headroom over the resolver default.
  const dns = options.dns ?? new DnsResolver({
    maxQueries: 250,
    deadlineMs: 20_000,
    ...options,
  });

  const spf = await evaluateSpf(dns, domain);

  // A public suffix is checked only when it publishes a policy of its own. One that
  // publishes neither SPF nor DMARC — `com`, nearly every `co.xx` — has nothing to
  // report, and a page of "No SPF record" findings for it would be noise. An
  // unanswered lookup is not "publishes nothing", so it does not count against it.
  const earlyDmarc = publicSuffix ? await checkDmarc(dns, domain) : null;
  if (earlyDmarc && !spf.found && !spf.lookupError && earlyDmarc.status === 'absent') {
    throw new InvalidDomainError(
      `"${domain}" is a public suffix — names are registered under it, like ` +
      `example.${domain} — and it publishes no SPF or DMARC record of its own, so ` +
      'there is nothing to check. Enter a domain registered under it.',
    );
  }

  // Everything below is independent of SPF and of each other. MTA-STS and DNSSEC
  // reach outside DNS (HTTPS policy fetch, DoH) and both fail soft, so a slow or
  // broken third party degrades one section rather than the whole report.
  const [dkim, dmarc, mtaSts, tlsRpt, bimi, dnssec, mxAnswer, alias] = await Promise.all([
    checkDkim(dns, domain, options.selectors ?? []),
    earlyDmarc ?? checkDmarc(dns, domain),
    checkMtaSts(dns, domain),
    checkTlsRpt(dns, domain),
    checkBimi(dns, domain),
    (options.dnssec ?? checkDnssec)(domain),
    dns.mx(domain),
    // An alias cannot carry its own TXT records, so an SPF fix must not be aimed at it.
    walkCnames(dns, domain),
  ]);

  // RFC 7505: a single MX whose exchange is the root label means "no mail accepted".
  // Node surfaces that root label as either '.' or an empty string.
  const mx = mxAnswer.values;
  const nullMx = mx.length === 1 && (mx[0]!.exchange === '.' || mx[0]!.exchange === '');

  const flatten = spf.limitExceeded ? planFlattening(spf) : null;
  const domainCnameChain = alias.chain;
  const report = buildReport({
    domain, spf, flatten, dkim, dmarc, mtaSts, tlsRpt, bimi, dnssec, mx, nullMx, domainCnameChain,
    publicSuffix,
  });

  return {
    domain, spf, flatten, dkim, dmarc, mtaSts, tlsRpt, bimi, dnssec, mx, nullMx, domainCnameChain,
    publicSuffix, report,
    queryCount: dns.queryCount,
    elapsedMs: Date.now() - started,
  };
}
