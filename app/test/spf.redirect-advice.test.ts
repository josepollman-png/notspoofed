import { describe, expect, it } from 'vitest';
import { apiBody } from '../src/lib/api-body.js';
import { runCheck } from '../src/lib/check.js';
import type { Finding } from '../src/lib/findings.js';
import { FakeDns, type Zone } from './fake-dns.js';

/**
 * Advice about `all` on a record that ends in redirect=.
 *
 * The regression, seen on servicenow.com on 12 October 2026: its SPF record is exactly
 * `v=spf1 redirect=8sfr6god._spf._d.mim.ec`. One run got SERVFAIL for the target, and
 * the report said "SPF has no all mechanism" and offered
 * `v=spf1 redirect=8sfr6god._spf._d.mim.ec ~all`. RFC 7208 §6.1 ignores a redirect
 * whenever the record has an `all`, so that record switches the redirect off and
 * softfails every sender, the real ones included. A record ending in redirect= has no
 * `all` by design; its `all` lives in the target.
 */

const noDnssec = async (domain: string) => ({ signed: false, zone: domain, unknown: true });
const check = (zone: Zone, domain = 'example.com') =>
  runCheck(domain, { dns: new FakeDns(zone), dnssec: noDnssec });

const SERVICENOW = 'v=spf1 redirect=8sfr6god._spf._d.mim.ec';
const TARGET = '8sfr6god._spf._d.mim.ec';

const spfIds = (findings: Finding[]) => findings.filter((f) => f.id.startsWith('spf-')).map((f) => f.id);

/** Every SPF record this check hands out, whatever form the fix takes. */
function suggestedSpf(r: Awaited<ReturnType<typeof check>>): string[] {
  const out: string[] = [];
  for (const f of r.report.findings) {
    if (f.fix?.kind === 'record' && f.fix.value.startsWith('v=spf1')) out.push(f.fix.value);
    if (f.fix?.kind === 'action' && f.fix.managedRecord?.value.startsWith('v=spf1')) out.push(f.fix.managedRecord.value);
  }
  const body = apiBody(r);
  if (body.spf.suggestedRecord) out.push(body.spf.suggestedRecord);
  return out;
}

/** The invariant: no suggested record has both an `all` and a `redirect=`. */
function expectNoRedirectWithAll(r: Awaited<ReturnType<typeof check>>) {
  for (const record of suggestedSpf(r)) {
    const tokens = record.split(/\s+/);
    const both = tokens.some((t) => /^[+\-~?]?all$/.test(t)) && tokens.some((t) => t.startsWith('redirect='));
    expect(both, record).toBe(false);
  }
}

describe('redirect= target that did not answer (temperror)', () => {
  for (const error of ['SERVFAIL', 'TIMEOUT'] as const) {
    it(`${error}: says the target could not be checked, and nothing about all`, async () => {
      const r = await check({
        TXT: { 'example.com': [SERVICENOW] },
        ERRORS: { [`TXT ${TARGET}`]: error },
      });

      // The only SPF finding is the one saying what happened.
      expect(spfIds(r.report.findings)).toEqual(['spf-lookup-failed']);
      const f = r.report.findings.find((x) => x.id === 'spf-lookup-failed')!;
      expect(f.severity).toBe('warning');
      expect(f.title).toBe(`SPF could not be checked: the redirect= target ${TARGET} did not answer`);
      expect(f.detail).toContain(`(DNS ${error.toLowerCase()})`);
      expect(f.detail).toContain('temperror');
      expect(f.fix).toBeUndefined();
      expectNoRedirectWithAll(r);
    });
  }
});

describe('redirect= target with no SPF record (permerror)', () => {
  it('NXDOMAIN: a permerror naming the redirect, not "no all mechanism"', async () => {
    const r = await check({ TXT: { 'example.com': [SERVICENOW] } });

    expect(spfIds(r.report.findings)).toEqual(['spf-include-no-record']);
    const f = r.report.findings.find((x) => x.id === 'spf-include-no-record')!;
    expect(f.title).toBe(`SPF permerror: the redirect= target ${TARGET} publishes no SPF record`);
    expect(f.detail).toContain('the name does not exist, NXDOMAIN');
    expect(f.detail).toContain('RFC 7208 §6.1');
    expect(r.spf.permerror).toBe(`the redirect= target ${TARGET} publishes no SPF record`);
    expectNoRedirectWithAll(r);
  });

  it('a target with TXT records but no SPF one says so', async () => {
    const r = await check({ TXT: { 'example.com': [SERVICENOW], [TARGET]: ['google-site-verification=x'] } });
    expect(r.report.findings.find((x) => x.id === 'spf-include-no-record')?.detail)
      .toContain('it has TXT records, none of them SPF');
  });

  it('an include with no record keeps its own wording', async () => {
    const r = await check({ TXT: { 'example.com': ['v=spf1 include:gone.example.net -all'] } });
    expect(r.report.findings.find((x) => x.id === 'spf-include-no-record')?.title)
      .toBe('SPF permerror: gone.example.net publishes no SPF record');
    expect(r.spf.permerror).toBe('gone.example.net is included but publishes no SPF record');
  });
});

describe('redirect= target that resolves', () => {
  it('a valid target is clean (servicenow.com on a good run)', async () => {
    const r = await check({ TXT: { 'example.com': [SERVICENOW], [TARGET]: ['v=spf1 ip4:192.0.2.0/24 -all'] } });
    expect(spfIds(r.report.findings)).toEqual([]);
    expect(r.spf.allQualifier).toBe('-');
  });

  it('the gmail.com shape stays clean', async () => {
    const r = await check({
      TXT: {
        'gmail.com': ['v=spf1 redirect=_spf.google.com'],
        '_spf.google.com': ['v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all'],
        '_netblocks.google.com': ['v=spf1 ip4:35.190.247.0/24 ~all'],
        '_netblocks2.google.com': ['v=spf1 ip6:2001:4860:4000::/36 ~all'],
        '_netblocks3.google.com': ['v=spf1 ip4:172.217.0.0/19 ~all'],
      },
    }, 'gmail.com');
    expect(spfIds(r.report.findings)).toEqual([]);
    expect(r.spf.allQualifier).toBe('~');
    expectNoRedirectWithAll(r);
  });

  it('a target without all gets the fix at the target, never at the apex', async () => {
    const r = await check({ TXT: { 'example.com': ['v=spf1 redirect=_spf.example.com'], '_spf.example.com': ['v=spf1 ip4:192.0.2.1'] } });
    const f = r.report.findings.find((x) => x.id === 'spf-no-all')!;
    expect(f.fix).toMatchObject({ kind: 'record', host: '_spf.example.com', value: 'v=spf1 ip4:192.0.2.1 ~all' });
    expect(f.fix?.kind === 'record' && f.fix.caveat).toContain('would switch its redirect= off');
    expectNoRedirectWithAll(r);
  });

  it('a +all in the target is fixed in the target', async () => {
    const r = await check({ TXT: { 'example.com': ['v=spf1 redirect=_spf.example.com'], '_spf.example.com': ['v=spf1 ip4:192.0.2.1 +all'] } });
    expect(r.report.findings.find((x) => x.id === 'spf-permissive-all')?.fix)
      .toMatchObject({ kind: 'record', host: '_spf.example.com', value: 'v=spf1 ip4:192.0.2.1 ~all' });
  });
});

describe('records that already have both', () => {
  it('a dead redirect= is dropped from the suggestion, and the caveat says why', async () => {
    const r = await check({ TXT: { 'example.com': ['v=spf1 ip4:192.0.2.1 redirect=_spf.example.com ?all'] } });
    const fix = r.report.findings.find((x) => x.id === 'spf-neutral-all')?.fix;
    expect(fix).toMatchObject({ kind: 'record', host: 'example.com', value: 'v=spf1 ip4:192.0.2.1 ~all' });
    expect(fix?.kind === 'record' && fix.caveat).toContain('leaves out redirect=_spf.example.com');
    expectNoRedirectWithAll(r);
  });

  it('an all that is not the last term is still the one replaced', async () => {
    // The old fix matched /\+?all\s*$/ and returned this record unchanged.
    const r = await check({ TXT: { 'example.com': ['v=spf1 ip4:192.0.2.1 +all exp=explain.example.com'] } });
    expect(r.report.findings.find((x) => x.id === 'spf-permissive-all')?.fix)
      .toMatchObject({ value: 'v=spf1 ip4:192.0.2.1 ~all exp=explain.example.com' });
  });

  it('a flattened suggestion never carries a dead redirect= either', async () => {
    const includes: Record<string, string[]> = {};
    const terms: string[] = [];
    for (let i = 1; i <= 11; i++) {
      includes[`s${i}.example.net`] = [`v=spf1 ip4:198.51.100.${i} -all`];
      terms.push(`include:s${i}.example.net`);
    }
    const r = await check({
      TXT: { 'example.com': [`v=spf1 ${terms.join(' ')} redirect=_spf.example.com ~all`], ...includes },
    });
    expect(r.spf.limitExceeded).toBe(true);
    expect(apiBody(r).spf.suggestedRecord).not.toContain('redirect=');
    expectNoRedirectWithAll(r);
  });
});
