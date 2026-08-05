/**
 * Every check terminates in one of these. The `fix` field is the product: a finding
 * without an actionable fix is just a complaint, and five well-funded competitors
 * already do complaints for free.
 */

export type Severity = 'critical' | 'warning' | 'info' | 'pass';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  warning: 1,
  info: 2,
  pass: 3,
};

/** A DNS record the user can paste verbatim into their provider. */
export interface RecordFix {
  kind: 'record';
  host: string;
  type: 'TXT' | 'CNAME';
  value: string;
  /** Anything the user must understand before publishing this. Never omit for
   *  records that sit in the mail delivery path. */
  caveat?: string;
}

/** Something to do that isn't a record — ask a vendor, check a console. */
export interface ActionFix {
  kind: 'action';
  steps: string[];
}

export type Fix = RecordFix | ActionFix;

/**
 * Every finding id the checker can emit.
 *
 * These are a public contract: the JSON API documents them as the thing callers should
 * branch on, precisely because titles are prose and get reworded. Typing the union here
 * means a rename or a typo is a compile error rather than a silent break for anyone
 * built against the API.
 *
 * Adding an id is a non-breaking change. Removing or renaming one is not — bump the
 * API version if you do.
 */
export const FINDING_IDS = [
  // SPF
  'spf-missing', 'spf-lookup-limit', 'spf-lookup-headroom', 'spf-permissive-all',
  'spf-no-all', 'spf-neutral-all', 'spf-macros', 'spf-multiple-records',
  'spf-void-limit', 'spf-ptr', 'spf-loop', 'spf-mx-fanout', 'spf-syntax',
  // DKIM
  'non-sending-domain', 'dkim-wildcard-dns', 'dkim-none-found', 'dkim-weak-key',
  'dkim-revoked', 'dkim-testing', 'dkim-ok',
  // DMARC
  'dmarc-missing', 'dmarc-inherited', 'dmarc-p-none', 'dmarc-quarantine',
  'dmarc-reject', 'dmarc-pct', 'dmarc-no-rua', 'dmarc-rua-undeliverable',
  'dmarc-external-unauthorised', 'dmarc-sp-weaker', 'dmarc-syntax', 'dmarc-unknown-tags',
  'dmarc-test-mode', 'dmarc-no-np', 'dmarc-deprecated-tags',
  // MTA-STS / TLS-RPT / BIMI / DNSSEC
  'mtasts-policy-unreachable', 'mtasts-mx-mismatch', 'mtasts-testing', 'mtasts-syntax',
  'mtasts-ok', 'mtasts-missing', 'tlsrpt-syntax', 'tlsrpt-missing',
  'bimi-without-enforcement', 'bimi-syntax', 'bimi-no-vmc', 'bimi-opportunity',
  'dnssec-ok', 'dnssec-missing',
  // Header analyzer
  'header-no-auth-results', 'header-dmarc-pass', 'header-dmarc-fail',
  'header-spf-not-aligned', 'header-dkim-not-aligned', 'header-spf-fail',
  'header-dkim-fail', 'header-no-dkim', 'header-slow-hop', 'header-reply-to-differs',
  'header-no-received', 'header-arc-present',
  // Sending-IP diagnostic
  'ip-no-ptr', 'ip-ptr-not-confirmed', 'ip-ptr-generic', 'ip-ptr-ok',
  'ip-blocklisted-major', 'ip-blocklisted-secondary', 'ip-blocklisted-informational',
  'ip-blocklist-unavailable', 'ip-not-listed', 'ip-ipv6-limited',
] as const;

export type FindingId = (typeof FINDING_IDS)[number];

export interface Finding {
  /** Stable slug — part of the public API contract. See FINDING_IDS. */
  id: FindingId;
  severity: Severity;
  title: string;
  /** What actually goes wrong for the user, in plain language. Not a spec citation. */
  detail: string;
  fix?: Fix;
}

export function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
}

export const worst = (findings: Finding[]): Severity =>
  findings.reduce<Severity>(
    (acc, f) => (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[acc] ? f.severity : acc),
    'pass',
  );
