import { describe, expect, it } from 'vitest';
import { evaluateSpf } from '../src/lib/spf/evaluate.js';
import { planFlattening } from '../src/lib/spf/flatten.js';
import { FakeDns } from './fake-dns.js';

describe('lookup counting', () => {
  it('counts only DNS-querying terms', async () => {
    const dns = new FakeDns({
      TXT: { 'e.com': ['v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 include:a.com -all'], 'a.com': ['v=spf1 -all'] },
    });
    const r = await evaluateSpf(dns, 'e.com');
    expect(r.lookupCount).toBe(1);
    expect(r.limitExceeded).toBe(false);
  });

  it('follows redirect= and counts it', async () => {
    // The regression: hubspot.com is nothing but a redirect. Missing it reports zero.
    const dns = new FakeDns({
      TXT: {
        'e.com': ['v=spf1 redirect=_spf.e.com'],
        '_spf.e.com': ['v=spf1 include:a.com include:b.com -all'],
        'a.com': ['v=spf1 -all'],
        'b.com': ['v=spf1 -all'],
      },
    });
    const r = await evaluateSpf(dns, 'e.com');
    expect(r.lookupCount).toBe(3);
  });

  it('inherits the all qualifier through a redirect', async () => {
    const dns = new FakeDns({
      TXT: { 'e.com': ['v=spf1 redirect=_spf.e.com'], '_spf.e.com': ['v=spf1 ip4:1.2.3.4 -all'] },
    });
    expect((await evaluateSpf(dns, 'e.com')).allQualifier).toBe('-');
  });

  it('flags a record that exceeds the limit', async () => {
    const TXT: Record<string, string[]> = {
      'e.com': [`v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:i${i}.com`).join(' ')} -all`],
    };
    for (let i = 0; i < 11; i++) TXT[`i${i}.com`] = ['v=spf1 ip4:10.0.0.1 -all'];
    const r = await evaluateSpf(new FakeDns({ TXT }), 'e.com');
    expect(r.lookupCount).toBe(11);
    expect(r.limitExceeded).toBe(true);
  });

  it('charges macro terms without pretending to resolve them', async () => {
    const dns = new FakeDns({ TXT: { 'e.com': ['v=spf1 exists:%{i}._spf.e.com include:a.com ~all'], 'a.com': ['v=spf1 -all'] } });
    const r = await evaluateSpf(dns, 'e.com');
    expect(r.lookupCount).toBe(2);
    expect(r.macroTerms).toHaveLength(1);
    expect(dns.log).not.toContain('TXT %{i}._spf.e.com');
  });
});

describe('error conditions', () => {
  it('reports more than one SPF record', async () => {
    const dns = new FakeDns({ TXT: { 'e.com': ['v=spf1 -all', 'v=spf1 ip4:1.1.1.1 -all'] } });
    const r = await evaluateSpf(dns, 'e.com');
    expect(r.problems.map((p) => p.code)).toContain('multiple-records');
  });

  it('counts void lookups and complains past two', async () => {
    const dns = new FakeDns({
      TXT: { 'e.com': ['v=spf1 include:x1.com include:x2.com include:x3.com -all'] },
    });
    const r = await evaluateSpf(dns, 'e.com');
    expect(r.voidCount).toBe(3);
    expect(r.problems.map((p) => p.code)).toContain('void-limit');
  });

  it('breaks include loops instead of recursing forever', async () => {
    const dns = new FakeDns({
      TXT: { 'a.com': ['v=spf1 include:b.com -all'], 'b.com': ['v=spf1 include:a.com -all'] },
    });
    const r = await evaluateSpf(dns, 'a.com');
    expect(r.problems.map((p) => p.code)).toContain('loop');
  });

  it('treats a TXT record that is not SPF as no record at all', async () => {
    const dns = new FakeDns({ TXT: { 'e.com': ['google-site-verification=abc'] } });
    expect((await evaluateSpf(dns, 'e.com')).found).toBe(false);
  });
});

describe('flattening', () => {
  // Mirrors lyft.com: one expensive include among several cheap ones.
  const zone = {
    TXT: {
      'e.com': ['v=spf1 include:big.com include:s1.com include:s2.com include:s3.com include:s4.com include:s5.com include:s6.com include:s7.com include:s8.com -all'],
      'big.com': ['v=spf1 include:b1.com include:b2.com include:b3.com ip4:203.0.113.0/24 -all'],
      'b1.com': ['v=spf1 ip4:198.51.100.1 -all'],
      'b2.com': ['v=spf1 ip4:198.51.100.2 -all'],
      'b3.com': ['v=spf1 ip4:198.51.100.3 -all'],
      ...Object.fromEntries(
        Array.from({ length: 8 }, (_, i) => [`s${i + 1}.com`, [`v=spf1 ip4:192.0.2.${i + 1} -all`]]),
      ),
    },
  };

  it('flattens the fewest includes needed to get under the limit', async () => {
    const r = await evaluateSpf(new FakeDns(zone), 'e.com');
    expect(r.lookupCount).toBe(12);

    const plan = planFlattening(r)!;
    expect(plan).not.toBeNull();
    // big.com costs 4; removing it alone drops 12 -> 8. The eight cheap includes stay.
    expect(plan.flattened).toEqual(['include:big.com']);
    expect(plan.lookupsAfter).toBe(8);
    expect(plan.sufficient).toBe(true);
    expect(plan.kept).toContain('include:s1.com');
    expect(plan.record).toContain('ip4:198.51.100.1');
    expect(plan.record).toContain('ip4:203.0.113.0/24');
    expect(plan.record).toMatch(/-all$/);
  });

  it('always carries a staleness caveat, because this record goes live in the mail path', async () => {
    const plan = planFlattening(await evaluateSpf(new FakeDns(zone), 'e.com'))!;
    expect(plan.warnings.join(' ')).toMatch(/snapshot|changes its sending IPs/i);
  });

  it('collapses ranges already covered by a broader one', async () => {
    const dns = new FakeDns({
      TXT: {
        'e.com': [`v=spf1 include:wide.com ${Array.from({ length: 11 }, (_, i) => `include:n${i}.com`).join(' ')} -all`],
        'wide.com': ['v=spf1 ip4:10.0.0.0/8 ip4:10.1.2.0/24 ip4:10.255.255.255 ip4:192.0.2.0/24 -all'],
        ...Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`n${i}.com`, ['v=spf1 -all']])),
      },
    });
    const plan = planFlattening(await evaluateSpf(dns, 'e.com'))!;
    // The /24 and the single host both sit inside 10.0.0.0/8 and add nothing.
    expect(plan.record).toContain('ip4:10.0.0.0/8');
    expect(plan.record).not.toContain('ip4:10.1.2.0/24');
    expect(plan.record).not.toContain('ip4:10.255.255.255');
    expect(plan.record).toContain('ip4:192.0.2.0/24');
  });

  it('splits records over 255 bytes into DNS character-strings', async () => {
    const many = Array.from({ length: 40 }, (_, i) => `ip4:192.0.2.${i}`).join(' ');
    const dns = new FakeDns({
      TXT: {
        'e.com': [`v=spf1 include:fat.com ${Array.from({ length: 11 }, (_, i) => `include:n${i}.com`).join(' ')} -all`],
        'fat.com': [`v=spf1 ${many} -all`],
        ...Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`n${i}.com`, ['v=spf1 -all']])),
      },
    });
    const plan = planFlattening(await evaluateSpf(dns, 'e.com'))!;
    expect(plan.byteLength).toBeGreaterThan(255);
    expect(plan.chunks.length).toBeGreaterThan(1);
    for (const c of plan.chunks) expect(Buffer.byteLength(c)).toBeLessThanOrEqual(255);
    // Rejoining the chunks with nothing between them must reproduce the record.
    expect(plan.chunks.join(' ')).toBe(plan.record);
    expect(plan.warnings.join(' ')).toMatch(/255-byte/);
  });

  it('refuses to flatten terms with no knowable address set', async () => {
    const dns = new FakeDns({
      TXT: {
        'e.com': [`v=spf1 exists:%{i}.e.com ${Array.from({ length: 11 }, (_, i) => `include:n${i}.com`).join(' ')} -all`],
        ...Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`n${i}.com`, ['v=spf1 ip4:192.0.2.1 -all']])),
      },
    });
    const plan = planFlattening(await evaluateSpf(dns, 'e.com'))!;
    expect(plan.flattened.join(' ')).not.toContain('exists');
  });
});
