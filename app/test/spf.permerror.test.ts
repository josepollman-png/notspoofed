import { describe, expect, it } from 'vitest';
import { spfSummary } from '../src/lib/summary.js';
import { checkDkim } from '../src/lib/dkim/check.js';
import { checkDmarc } from '../src/lib/dmarc/check.js';
import { checkBimi, checkMtaSts, checkTlsRpt } from '../src/lib/modern/check.js';
import { buildReport } from '../src/lib/remediate.js';
import { evaluateSpf } from '../src/lib/spf/evaluate.js';
import { isIp4, isIp6, parseSpf } from '../src/lib/spf/parse.js';
import { FakeDns, type Zone } from './fake-dns.js';

/**
 * Records a spec-following receiver returns permerror for (RFC 7208 §4.6, §4.6.4, §5.2,
 * §6). The regression: centos.org publishes its record as two TXT strings, the first
 * ending "ip6:2620:52:3::214" with no trailing space. Strings join with nothing between
 * them (§3.3), so the record contains `ip6:2620:52:3::214ip4:8.43.84.199` — and the
 * parser accepted any text after `ip6:`, reporting "1/10 lookups" for a broken record.
 */

// Exactly as published, the two strings joined as the resolver joins them.
const CENTOS =
  'v=spf1 mx ip4:8.43.84.214 ip4:8.43.84.213 ip6:2620:52:3::214' +
  'ip4:8.43.84.199 ip4:8.43.84.213 ip6:2620:52:3::214 ip4:8.43.84.214 ip4:38.145.33.27 ' +
  'ip6:2620:52:6:2111::47 -all';
const BAD_TERM = 'ip6:2620:52:3::214ip4:8.43.84.199';

async function reportFor(zone: Zone, domain = 'example.com') {
  const dns = new FakeDns(zone);
  const [spf, dkim, dmarc, mtaSts, tlsRpt, bimi] = await Promise.all([
    evaluateSpf(dns, domain), checkDkim(dns, domain, []), checkDmarc(dns, domain),
    checkMtaSts(dns, domain), checkTlsRpt(dns, domain), checkBimi(dns, domain),
  ]);
  const report = buildReport({
    domain, spf, flatten: null, dkim, dmarc, mtaSts, tlsRpt, bimi, mx: [], nullMx: false,
    dnssec: { signed: false, zone: domain, unknown: true },
  });
  return { spf, findings: report.findings };
}

describe('centos.org: two terms run together', () => {
  it('names the malformed term and makes the record a permerror', async () => {
    const parsed = parseSpf(CENTOS);
    expect(parsed.errors).toEqual([
      `malformed term "${BAD_TERM}": "2620:52:3::214ip4:8.43.84.199" is not a valid IPv6 address`,
    ]);

    const { spf, findings } = await reportFor({
      TXT: { 'centos.org': [CENTOS] },
      MX: { 'centos.org': [{ exchange: 'mail.centos.org', priority: 10 }] },
      A: { 'mail.centos.org': ['8.43.84.199'] },
    }, 'centos.org');

    expect(spf.permerror).toBe(`malformed term "${BAD_TERM}"`);
    // The count is still computed, but only as information; the report says permerror.
    expect(spf.lookupCount).toBe(1);

    const finding = findings.find((f) => f.id === 'spf-syntax');
    expect(finding?.severity).toBe('critical');
    expect(finding?.title).toBe(`SPF permerror: malformed term ${BAD_TERM}`);
    expect(finding?.detail).toMatch(/whole SPF check a permerror/);
  });

  it('offers the missing space as the fix', async () => {
    const t = parseSpf(CENTOS).terms.find((x) => x.raw === BAD_TERM);
    expect(t?.suggestion).toBe('ip6:2620:52:3::214 ip4:8.43.84.199');

    const { findings } = await reportFor({ TXT: { 'centos.org': [CENTOS] } }, 'centos.org');
    const fix = findings.find((f) => f.id === 'spf-syntax')?.fix;
    expect(fix?.kind).toBe('record');
    const value = fix?.kind === 'record' ? fix.value : '';
    expect(value).toContain('ip6:2620:52:3::214 ip4:8.43.84.199');
    expect(parseSpf(value).errors).toEqual([]);
  });

  it('keeps the duplicate terms as published, and says they can go', async () => {
    const { findings } = await reportFor({ TXT: { 'centos.org': [CENTOS] } }, 'centos.org');
    const fix = findings.find((f) => f.id === 'spf-syntax')?.fix;
    if (fix?.kind !== 'record') throw new Error('expected a record fix');
    // Only the missing space changes: every other term, duplicates included, stays.
    expect(fix.value).toBe(CENTOS.replace(BAD_TERM, 'ip6:2620:52:3::214 ip4:8.43.84.199'));
    expect(fix.value.match(/ip4:8\.43\.84\.213/g)).toHaveLength(2);
    expect(fix.caveat).toContain(
      'The record also lists ip4:8.43.84.213, ip6:2620:52:3::214, ip4:8.43.84.214 more than once.',
    );
    expect(fix.caveat).toContain('Duplicates are harmless and cost no lookups');
  });
});

describe('a valid record is unchanged', () => {
  it('parses without errors and is not a permerror', async () => {
    const record = 'v=spf1 include:_spf.example.net ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx/24 -all';
    expect(parseSpf(record).errors).toEqual([]);
    const { spf, findings } = await reportFor({
      TXT: { 'example.com': [record], '_spf.example.net': ['v=spf1 ip4:198.51.100.0/24 -all'] },
      A: { 'example.com': ['192.0.2.1'] },
      MX: { 'example.com': [{ exchange: 'mx.example.com', priority: 10 }] },
      AAAA: { 'example.com': ['2001:db8::1'] },
    });
    expect(spf.permerror).toBeNull();
    expect(spf.lookupCount).toBe(3);
    expect(findings.filter((f) => f.id.startsWith('spf-') && f.severity === 'critical')).toEqual([]);
  });

  it('accepts macros in domain-specs and ignores unknown modifiers, as the RFC requires', () => {
    expect(parseSpf('v=spf1 exists:%{i}._spf.mta.salesforce.com include:%{d}.example.net foo=bar -all').errors).toEqual([]);
  });
});

describe('term syntax, checked against the ABNF', () => {
  it('parses IPv4 and IPv6 strictly', () => {
    expect(['0.0.0.0', '192.0.2.1', '255.255.255.255'].every(isIp4)).toBe(true);
    expect(['256.0.0.1', '192.0.2', '01.2.3.4', '1.2.3.4.5', ''].some(isIp4)).toBe(false);
    expect(['::', '::1', '2001:db8::', '2001:db8:0:0:0:0:0:1', '::ffff:192.0.2.1', '2620:52:6:2111::47'].every(isIp6)).toBe(true);
    expect(['2001:db8::1::2', '1:2:3:4:5:6:7:8:9', '2001:db8::g', '2620:52:3::214ip4:8.43.84.199', ':1:2'].some(isIp6)).toBe(false);
  });

  it.each([
    ['ip4:192.0.2.0/33', /prefix length/],
    ['ip6:2001:db8::/129', /prefix length/],
    ['ip4:192.0.2.300', /not a valid IPv4 address/],
    ['a/33', /dual-cidr/],
    ['mx//129', /dual-cidr/],
    ['all:example.com', /all takes no value/],
    ['include:spf', /not a fully qualified domain/],
    ['include:192.0.2.1', /not a valid top-level label/],
    ['redirect:example.com', /unknown mechanism/],
    ['ipv4:192.0.2.1', /unknown mechanism/],
    ['ip4', /requires an address/],
  ])('%s is a syntax error', (term, why) => {
    const r = parseSpf(`v=spf1 ${term} -all`);
    expect(r.errors.join(' ')).toMatch(why);
  });
});

describe('the neighbouring permerror cases', () => {
  it('two SPF records', async () => {
    const { spf, findings } = await reportFor({ TXT: { 'example.com': ['v=spf1 -all', 'v=spf1 mx -all'] } });
    expect(spf.permerror).toBe('more than one SPF record is published');
    expect(findings.find((f) => f.id === 'spf-multiple-records')?.severity).toBe('critical');
  });

  it('more than ten DNS-querying terms', async () => {
    const TXT: Record<string, string[]> = {
      'example.com': [`v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(' ')} -all`],
    };
    for (let i = 0; i < 11; i++) TXT[`s${i}.example.net`] = ['v=spf1 -all'];
    const { spf } = await reportFor({ TXT });
    expect(spf.permerror).toBe('11 DNS lookups, over the limit of 10');
  });

  it('more than two void lookups', async () => {
    const { spf, findings } = await reportFor({
      TXT: { 'example.com': ['v=spf1 a:gone1.example.net a:gone2.example.net a:gone3.example.net -all'] },
    });
    expect(spf.permerror).toBe('3 void lookups, over the limit of 2');
    const f = findings.find((x) => x.id === 'spf-void-limit');
    expect(f?.severity).toBe('critical');
    expect(f?.title).toMatch(/^SPF permerror/);
  });

  it('an include whose target publishes no SPF record', async () => {
    const { spf, findings } = await reportFor({
      TXT: { 'example.com': ['v=spf1 include:old-vendor.example.net -all'], 'old-vendor.example.net': ['some=thing'] },
    });
    expect(spf.permerror).toBe('old-vendor.example.net is included but publishes no SPF record');
    expect(findings.find((f) => f.id === 'spf-include-no-record')?.severity).toBe('critical');
  });

  it('redirect= or exp= more than once', () => {
    expect(parseSpf('v=spf1 redirect=a.example.net redirect=b.example.net').errors.join(' '))
      .toMatch(/redirect= appears 2 times/);
    expect(parseSpf('v=spf1 -all exp=a.example.net exp=b.example.net').errors.join(' '))
      .toMatch(/exp= appears 2 times/);
  });

  it('redirect= alongside all is a warning, not a permerror (RFC 7208 §6.1 ignores the redirect)', async () => {
    const r = parseSpf('v=spf1 mx -all redirect=_spf.example.net');
    expect(r.errors).toEqual([]);
    expect(r.warnings).toContain('redirect= is ignored because an "all" mechanism is present');
    const { spf, findings } = await reportFor({ TXT: { 'example.com': ['v=spf1 -all redirect=_spf.example.net'] } });
    expect(spf.permerror).toBeNull();
    expect(findings.find((f) => f.id === 'spf-dead-terms')?.severity).toBe('warning');
  });
});

describe('the report summary line', () => {
  it('says "1 lookup", not "1 lookups" (centos.org)', async () => {
    const { spf } = await reportFor({ TXT: { 'centos.org': [CENTOS] }, MX: { 'centos.org': [] } }, 'centos.org');
    expect(spfSummary(spf)).toBe('permerror (1 lookup counted)');
    expect(spfSummary({ ...spf, lookupCount: 3 })).toBe('permerror (3 lookups counted)');
  });
});
