import { describe, expect, it } from 'vitest';
import {
  checkBimi, checkMtaSts, checkTlsRpt, mxMatches, parseMtaStsPolicy,
} from '../src/lib/modern/check.js';
import { evaluateSpf } from '../src/lib/spf/evaluate.js';
import { FakeDns } from './fake-dns.js';

describe('MTA-STS policy parsing', () => {
  const good = 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.backup.example.com\nmax_age: 604800\n';

  it('parses a valid policy', () => {
    const p = parseMtaStsPolicy(good);
    expect(p.errors).toEqual([]);
    expect(p).toMatchObject({ version: 'STSv1', mode: 'enforce', maxAge: 604800 });
    expect(p.mx).toEqual(['mail.example.com', '*.backup.example.com']);
  });

  it('tolerates CRLF line endings', () => {
    expect(parseMtaStsPolicy(good.replace(/\n/g, '\r\n')).errors).toEqual([]);
  });

  it('requires version, mode and max_age', () => {
    const e = parseMtaStsPolicy('mx: a.example.com\n').errors.join(' ');
    expect(e).toMatch(/version must be STSv1/);
    expect(e).toMatch(/mode is required/);
    expect(e).toMatch(/max_age is required/);
  });

  it('rejects an invalid mode', () => {
    expect(parseMtaStsPolicy('version: STSv1\nmode: on\nmax_age: 100\nmx: a.b.com\n').errors.join(' '))
      .toMatch(/must be enforce, testing or none/);
  });

  it('requires an mx entry unless mode is none', () => {
    expect(parseMtaStsPolicy('version: STSv1\nmode: enforce\nmax_age: 100\n').errors.join(' '))
      .toMatch(/at least one mx/);
    expect(parseMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 100\n').errors)
      .toEqual([]);
  });

  it('rejects a max_age over one year', () => {
    expect(parseMtaStsPolicy('version: STSv1\nmode: enforce\nmx: a.b.com\nmax_age: 99999999\n').errors.join(' '))
      .toMatch(/one-year maximum/);
  });
});

describe('MTA-STS mx pattern matching', () => {
  it('matches exact hosts case-insensitively and ignores a trailing dot', () => {
    expect(mxMatches('mail.example.com', 'MAIL.example.com.')).toBe(true);
    expect(mxMatches('mail.example.com', 'other.example.com')).toBe(false);
  });

  it('allows a wildcard for exactly one label', () => {
    expect(mxMatches('*.example.com', 'mx1.example.com')).toBe(true);
    // Two labels deep must NOT match — this is the subtle bit of RFC 8461 §3.2.
    expect(mxMatches('*.example.com', 'a.mx1.example.com')).toBe(false);
    // The wildcard does not match the bare domain either.
    expect(mxMatches('*.example.com', 'example.com')).toBe(false);
  });
});

describe('MTA-STS record lookup', () => {
  it('reports nothing when no record is published', async () => {
    const r = await checkMtaSts(new FakeDns({}), 'e.com');
    expect(r.record).toBeNull();
    expect(r.errors).toEqual([]);
  });

  it('flags a record with no id= tag', async () => {
    const dns = new FakeDns({ TXT: { '_mta-sts.e.com': ['v=STSv1;'] } });
    const r = await checkMtaSts(dns, 'e.com');
    expect(r.errors.join(' ')).toMatch(/no id= tag/);
  });

  it('reports an unreachable policy rather than assuming it is fine', async () => {
    // Nothing is listening on mta-sts.invalid-tld-for-testing.example, so the fetch
    // fails — which is exactly the real-world failure this check exists to catch.
    const dns = new FakeDns({ TXT: { '_mta-sts.e.com': ['v=STSv1; id=20260101000000'] } });
    const r = await checkMtaSts(dns, 'e.com');
    expect(r.record).not.toBeNull();
    expect(r.policyError).toBeDefined();
  }, 20_000);
});

describe('TLS-RPT', () => {
  it('parses rua addresses', async () => {
    const dns = new FakeDns({ TXT: { '_smtp._tls.e.com': ['v=TLSRPTv1; rua=mailto:a@e.com'] } });
    const r = await checkTlsRpt(dns, 'e.com');
    expect(r.rua).toEqual(['mailto:a@e.com']);
    expect(r.errors).toEqual([]);
  });

  it('accepts https reporting endpoints', async () => {
    const dns = new FakeDns({ TXT: { '_smtp._tls.e.com': ['v=TLSRPTv1; rua=https://r.example.com/tls'] } });
    expect((await checkTlsRpt(dns, 'e.com')).errors).toEqual([]);
  });

  it('flags a record with no rua', async () => {
    const dns = new FakeDns({ TXT: { '_smtp._tls.e.com': ['v=TLSRPTv1;'] } });
    expect((await checkTlsRpt(dns, 'e.com')).errors.join(' ')).toMatch(/rua= is required/);
  });

  it('rejects an unusable URI scheme', async () => {
    const dns = new FakeDns({ TXT: { '_smtp._tls.e.com': ['v=TLSRPTv1; rua=ftp://x.com/'] } });
    expect((await checkTlsRpt(dns, 'e.com')).errors.join(' ')).toMatch(/must be a mailto: or https:/);
  });
});

describe('BIMI', () => {
  it('parses logo and VMC URLs', async () => {
    const dns = new FakeDns({
      TXT: { 'default._bimi.e.com': ['v=BIMI1; l=https://e.com/logo.svg; a=https://e.com/vmc.pem'] },
    });
    const r = await checkBimi(dns, 'e.com');
    expect(r).toMatchObject({ logoUrl: 'https://e.com/logo.svg', vmcUrl: 'https://e.com/vmc.pem' });
    expect(r.errors).toEqual([]);
  });

  it('requires https for the logo', async () => {
    const dns = new FakeDns({ TXT: { 'default._bimi.e.com': ['v=BIMI1; l=http://e.com/logo.svg'] } });
    expect((await checkBimi(dns, 'e.com')).errors.join(' ')).toMatch(/must be https/);
  });

  it('requires an SVG', async () => {
    const dns = new FakeDns({ TXT: { 'default._bimi.e.com': ['v=BIMI1; l=https://e.com/logo.png'] } });
    expect((await checkBimi(dns, 'e.com')).errors.join(' ')).toMatch(/must be an SVG/);
  });

  it('flags an empty l= tag', async () => {
    const dns = new FakeDns({ TXT: { 'default._bimi.e.com': ['v=BIMI1; l='] } });
    expect((await checkBimi(dns, 'e.com')).errors.join(' ')).toMatch(/no logo to display/);
  });
});

describe('non-sending domain detection', () => {
  it('recognises v=spf1 -all as a deliberate no-mail posture', async () => {
    const dns = new FakeDns({ TXT: { 'e.com': ['v=spf1 -all'] } });
    expect((await evaluateSpf(dns, 'e.com')).sendsNoMail).toBe(true);
  });

  it('does not treat a softfail as no-mail', async () => {
    // ~all still lets unlisted senders through as softfail, so it is not a declaration
    // that the domain sends nothing.
    const dns = new FakeDns({ TXT: { 'e.com': ['v=spf1 ~all'] } });
    expect((await evaluateSpf(dns, 'e.com')).sendsNoMail).toBe(false);
  });

  it('does not treat a domain with senders as no-mail', async () => {
    for (const record of ['v=spf1 ip4:1.2.3.4 -all', 'v=spf1 include:x.com -all', 'v=spf1 mx -all']) {
      const dns = new FakeDns({ TXT: { 'e.com': [record], 'x.com': ['v=spf1 -all'] } });
      expect((await evaluateSpf(dns, 'e.com')).sendsNoMail, record).toBe(false);
    }
  });

  it('is false when there is no SPF record at all', async () => {
    expect((await evaluateSpf(new FakeDns({}), 'e.com')).sendsNoMail).toBe(false);
  });
});
