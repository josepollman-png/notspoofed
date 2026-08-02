import { describe, expect, it } from 'vitest';
import { checkDmarc, parseDmarcRecord } from '../src/lib/dmarc/check.js';
import { FakeDns } from './fake-dns.js';

describe('tag parsing', () => {
  it('reads a full record', () => {
    const r = parseDmarcRecord(
      'v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=s; rua=mailto:a@x.com; ri=3600',
      'e.com', false,
    );
    expect(r).toMatchObject({
      policy: 'reject', subdomainPolicy: 'quarantine', pct: 50, adkim: 's', aspf: 's', ri: 3600,
    });
    expect(r.rua[0]).toMatchObject({ address: 'a@x.com', host: 'x.com' });
    expect(r.errors).toEqual([]);
  });

  it('handles the multi-string form seen on amazon.com', () => {
    // Concatenated by the resolver with no separator, which leaves no space after ';'.
    const r = parseDmarcRecord(
      'v=DMARC1;p=quarantine;pct=100;rua=mailto:report@dmarc.amazon.com;', 'amazon.com', false,
    );
    expect(r.policy).toBe('quarantine');
    expect(r.errors).toEqual([]);
  });

  it('requires v= first', () => {
    expect(parseDmarcRecord('p=reject; v=DMARC1', 'e.com', false).errors.join(' '))
      .toMatch(/must come first/);
  });

  it('requires p=', () => {
    expect(parseDmarcRecord('v=DMARC1; rua=mailto:a@x.com', 'e.com', false).errors.join(' '))
      .toMatch(/p= is required/);
  });

  it('rejects an out-of-range pct', () => {
    expect(parseDmarcRecord('v=DMARC1; p=none; pct=150', 'e.com', false).errors.join(' '))
      .toMatch(/pct=150/);
  });

  it('rejects an invalid policy value', () => {
    expect(parseDmarcRecord('v=DMARC1; p=block', 'e.com', false).errors.join(' '))
      .toMatch(/not one of none, quarantine, reject/);
  });

  it('parses a size limit on a report URI', () => {
    const r = parseDmarcRecord('v=DMARC1; p=none; rua=mailto:a@x.com!10m', 'e.com', false);
    expect(r.rua[0]).toMatchObject({ address: 'a@x.com', host: 'x.com', sizeLimit: '10m' });
  });

  it('splits multiple rua addresses', () => {
    const r = parseDmarcRecord('v=DMARC1; p=none; rua=mailto:a@x.com,mailto:b@y.com', 'e.com', false);
    expect(r.rua.map((u) => u.host)).toEqual(['x.com', 'y.com']);
  });

  it('collects unknown tags rather than failing', () => {
    const r = parseDmarcRecord('v=DMARC1; p=none; zz=1', 'e.com', false);
    expect(r.unknownTags).toEqual(['zz']);
    expect(r.errors).toEqual([]);
  });
});

describe('policy inheritance', () => {
  const zone = {
    TXT: { '_dmarc.e.com': ['v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@e.com'] },
  };

  it('applies p= at the organizational domain', async () => {
    const r = await checkDmarc(new FakeDns(zone), 'e.com');
    expect(r.record).toMatchObject({ inherited: false, effectivePolicy: 'reject' });
  });

  it('applies sp= to a subdomain with no record of its own', async () => {
    // Reporting "no DMARC" for mail.e.com here would be flatly wrong.
    const r = await checkDmarc(new FakeDns(zone), 'mail.e.com');
    expect(r.found).toBe(true);
    expect(r.record).toMatchObject({
      inherited: true, foundAt: 'e.com', effectivePolicy: 'quarantine',
    });
  });

  it('falls back to p= when sp= is absent', async () => {
    const dns = new FakeDns({ TXT: { '_dmarc.e.com': ['v=DMARC1; p=reject'] } });
    expect((await checkDmarc(dns, 'mail.e.com')).record?.effectivePolicy).toBe('reject');
  });

  it('prefers the subdomain’s own record over inheritance', async () => {
    const dns = new FakeDns({
      TXT: {
        '_dmarc.e.com': ['v=DMARC1; p=reject'],
        '_dmarc.mail.e.com': ['v=DMARC1; p=none'],
      },
    });
    const r = await checkDmarc(dns, 'mail.e.com');
    expect(r.record).toMatchObject({ inherited: false, effectivePolicy: 'none' });
  });
});

describe('external destination verification (RFC 7489 §7.1)', () => {
  it('requires no authorisation for a same-org destination', async () => {
    // amazon.com sending reports to dmarc.amazon.com needs no extra record.
    const dns = new FakeDns({ TXT: { '_dmarc.e.com': ['v=DMARC1; p=none; rua=mailto:r@reports.e.com'] } });
    const r = await checkDmarc(dns, 'e.com');
    expect(r.externalDestinations[0]).toMatchObject({ required: false, authorised: true });
  });

  it('detects an unauthorised third-party destination', async () => {
    const dns = new FakeDns({ TXT: { '_dmarc.e.com': ['v=DMARC1; p=none; rua=mailto:r@vendor.com'] } });
    const r = await checkDmarc(dns, 'e.com');
    expect(r.externalDestinations[0]).toMatchObject({
      required: true,
      authorised: false,
      expectedRecord: 'e.com._report._dmarc.vendor.com',
    });
  });

  it('accepts a destination that has published the authorisation', async () => {
    // The shape verified live against paypal.com / rua.agari.com.
    const dns = new FakeDns({
      TXT: {
        '_dmarc.e.com': ['v=DMARC1; p=none; rua=mailto:r@rua.vendor.com'],
        'e.com._report._dmarc.rua.vendor.com': ['v=DMARC1'],
      },
    });
    expect((await checkDmarc(dns, 'e.com')).externalDestinations[0]).toMatchObject({
      required: true, authorised: true,
    });
  });

  it('honours a wildcard authorisation record', async () => {
    const dns = new FakeDns({
      TXT: {
        '_dmarc.e.com': ['v=DMARC1; p=none; rua=mailto:r@vendor.com'],
        '*._report._dmarc.vendor.com': ['v=DMARC1'],
      },
    });
    expect((await checkDmarc(dns, 'e.com')).externalDestinations[0]?.authorised).toBe(true);
  });

  it('checks each distinct destination host once', async () => {
    const dns = new FakeDns({
      TXT: { '_dmarc.e.com': ['v=DMARC1; p=none; rua=mailto:a@v.com,mailto:b@v.com; ruf=mailto:c@v.com'] },
    });
    const r = await checkDmarc(dns, 'e.com');
    expect(r.externalDestinations).toHaveLength(1);
  });
});

describe('missing and duplicate records', () => {
  it('reports absence', async () => {
    const r = await checkDmarc(new FakeDns({}), 'e.com');
    expect(r.found).toBe(false);
    expect(r.record).toBeNull();
  });

  it('flags duplicates, which receivers treat as no policy at all', async () => {
    const dns = new FakeDns({ TXT: { '_dmarc.e.com': ['v=DMARC1; p=reject', 'v=DMARC1; p=none'] } });
    const r = await checkDmarc(dns, 'e.com');
    expect(r.multipleRecords).toBe(true);
    expect(r.record?.errors.join(' ')).toMatch(/no policy at all/);
  });

  it('ignores unrelated TXT records at _dmarc', async () => {
    const dns = new FakeDns({ TXT: { '_dmarc.e.com': ['some-verification=abc', 'v=DMARC1; p=reject'] } });
    expect((await checkDmarc(dns, 'e.com')).record?.policy).toBe('reject');
  });
});
