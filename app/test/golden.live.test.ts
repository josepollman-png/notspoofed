import { describe, expect, it } from 'vitest';
import { runCheck } from '../src/lib/check.js';
import { DnsResolver } from '../src/lib/dns/resolver.js';
import { checkDkim } from '../src/lib/dkim/check.js';
import { checkDmarc } from '../src/lib/dmarc/check.js';
import { evaluateSpf } from '../src/lib/spf/evaluate.js';

/**
 * Live-DNS corpus. Opt-in via LIVE_DNS=1 — these hit the real internet, so they are
 * slow and can fail for reasons that are not our fault.
 *
 * Each case pins a specific real-world behaviour that broke, or nearly broke, an
 * earlier version of this code. Where a domain could plausibly change its records,
 * the assertion is written against the *shape* of the answer rather than exact
 * values, so a vendor rotating IPs does not produce a spurious failure.
 */

const resolver = () => new DnsResolver({ maxQueries: 300, deadlineMs: 25_000 });

describe.skipIf(!process.env.LIVE_DNS)('golden corpus', () => {
  it('hubspot.com: follows redirect= and never reports zero lookups', async () => {
    // The silent-undercount bug. A ':'-only tokenizer scores this domain 0.
    const r = await evaluateSpf(resolver(), 'hubspot.com');
    expect(r.record).toMatch(/redirect=/);
    expect(r.lookupCount).toBeGreaterThan(0);
    // The redirect target's -all is the operative policy; the apex has no `all`.
    expect(r.allQualifier).not.toBeNull();
  }, 30_000);

  it('_hspf.hubspot.com: parses a record whose TXT chunks split mid-token', async () => {
    // This record ends one character-string with "…ip4" and begins the next with
    // ":161.38.192.0/20". Joining chunks on " " yields the invalid token `ip4 :161…`.
    const r = await evaluateSpf(resolver(), '_hspf.hubspot.com');
    expect(r.found).toBe(true);
    const syntax = r.problems.filter((p) => p.code === 'syntax');
    expect(syntax).toEqual([]);
    expect(r.ip4.some((ip) => ip.startsWith('161.38.192.'))).toBe(true);
  }, 30_000);

  it('salesforce.com: reports macros instead of guessing at them', async () => {
    const r = await evaluateSpf(resolver(), 'salesforce.com');
    expect(r.macroTerms.length).toBeGreaterThan(0);
    expect(r.macroTerms.every((t) => t.raw.includes('%{'))).toBe(true);
    // Macros still cost a lookup even though we cannot follow them.
    expect(r.lookupCount).toBeGreaterThanOrEqual(r.macroTerms.length);
  }, 30_000);

  it('_spf.google.com: is flat, so nothing nests beneath it', async () => {
    const r = await evaluateSpf(resolver(), '_spf.google.com');
    expect(r.lookupCount).toBe(0);
    expect(r.ip4.length).toBeGreaterThan(0);
  }, 30_000);

  it('hubspot.com: wildcard TXT does not manufacture DKIM selectors', async () => {
    // Querying zzqx-bogus._domainkey.hubspot.com returns "v=spf1 ~all". Any checker
    // testing only for record existence reports a dozen imaginary keys here.
    const r = await checkDkim(resolver(), 'hubspot.com');
    expect(r.wildcardDns).toBe(true);
    // Whatever we do report must be a genuine key, never the wildcard's SPF answer.
    for (const key of r.keys) {
      expect(key.raw).not.toMatch(/^v=spf1/i);
      expect(key.raw).toMatch(/p=/);
    }
  }, 60_000);

  it('example.com: a wildcard publishing a valid-looking DKIM key finds nothing', async () => {
    // *._domainkey.example.com answers "v=DKIM1; p=" — structurally a DKIM record,
    // so requiring p= is not sufficient on its own.
    const r = await checkDkim(resolver(), 'example.com');
    expect(r.wildcardDns).toBe(true);
    expect(r.keys).toHaveLength(0);
  }, 60_000);

  it('paypal.com: external report destinations are authorised', async () => {
    // The §7.1 mechanism, confirmed live: paypal.com._report._dmarc.rua.agari.com
    const r = await checkDmarc(resolver(), 'paypal.com');
    expect(r.record?.policy).toBe('reject');
    const external = r.externalDestinations.filter((d) => d.required);
    expect(external.length).toBeGreaterThan(0);
    for (const d of external) {
      expect(d.authorised).toBe(true);
      expect(d.expectedRecord).toMatch(/^paypal\.com\._report\._dmarc\./);
    }
  }, 30_000);

  it('amazon.com: same-org report destination needs no authorisation', async () => {
    // rua points at dmarc.amazon.com — same organizational domain, so §7.1 does not
    // apply. Demanding a record here would be a false positive.
    const r = await checkDmarc(resolver(), 'amazon.com');
    expect(r.externalDestinations.every((d) => !d.required)).toBe(true);
  }, 30_000);

  it('amazon.com: multi-string DMARC record parses cleanly', async () => {
    // Returned as "v=DMARC1;" "p=quarantine;" "pct=100;" … in separate chunks.
    const r = await checkDmarc(resolver(), 'amazon.com');
    expect(r.record?.policy).toBe('quarantine');
    expect(r.record?.errors).toEqual([]);
  }, 30_000);

  it('mail.google.com: inherits its policy from the organizational domain', async () => {
    const r = await checkDmarc(resolver(), 'mail.google.com');
    expect(r.found).toBe(true);
    expect(r.record?.inherited).toBe(true);
    expect(r.record?.foundAt).toBe('google.com');
  }, 30_000);

  it('produces an actionable fix for every critical finding', async () => {
    // The product thesis, asserted: a critical finding with no fix is a complaint.
    for (const domain of ['lyft.com', 'google.com', 'example.com']) {
      const { report } = await runCheck(domain);
      for (const f of report.findings.filter((x) => x.severity === 'critical')) {
        expect(f.fix, `${domain}: "${f.title}" has no fix`).toBeDefined();
      }
    }
  }, 120_000);

  it('every generated SPF fix is a syntactically valid record', async () => {
    const { report, flatten } = await runCheck('lyft.com');
    const spfFix = report.findings.find((f) => f.id === 'spf-lookup-limit')?.fix;
    expect(spfFix?.kind).toBe('record');
    if (spfFix?.kind !== 'record') return;

    expect(spfFix.value).toMatch(/^v=spf1 /);
    expect(spfFix.value).toMatch(/ [-~?+]?all$/);
    // A record that goes into the mail path must always carry its caveat.
    expect(spfFix.caveat).toBeTruthy();
    // And it must actually solve the problem it claims to solve.
    expect(flatten!.lookupsAfter).toBeLessThanOrEqual(10);
  }, 60_000);
});
