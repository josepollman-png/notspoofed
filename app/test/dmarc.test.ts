import { describe, expect, it } from 'vitest';
import { checkDmarc, parseDmarcRecord, treeWalkNames } from '../src/lib/dmarc/check.js';
import { dmarcFindings } from '../src/lib/remediate.js';
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

describe('DNS tree walk (RFC 9989 §4.10)', () => {
  it('stops at the nearest ancestor, not the organizational domain', async () => {
    // The whole reason 9989 dropped the PSL. Jumping straight to the org domain steps
    // over b.e.com and reports p=none as effective when the name is really at reject.
    const dns = new FakeDns({
      TXT: {
        '_dmarc.e.com': ['v=DMARC1; p=none'],
        '_dmarc.b.e.com': ['v=DMARC1; p=reject'],
      },
    });
    const r = await checkDmarc(dns, 'a.b.e.com');
    expect(r.record).toMatchObject({ foundAt: 'b.e.com', effectivePolicy: 'reject' });
  });

  it('walks label by label and never queries the TLD', () => {
    expect(treeWalkNames('a.b.e.com')).toEqual(['a.b.e.com', 'b.e.com', 'e.com']);
    expect(treeWalkNames('e.com')).toEqual(['e.com']);
    // A public suffix publishes no policy an ordinary owner inherits, and the root
    // servers do not need `_dmarc.com` from us on every check.
    expect(treeWalkNames('a.b.e.com')).not.toContain('com');
  });

  it('caps a deeply nested name at the query limit', () => {
    const deep = 'a.b.c.d.e.f.g.h.i.example.com';
    const names = treeWalkNames(deep);
    expect(names.length).toBeLessThanOrEqual(8);
    expect(names[0]).toBe(deep);
    expect(names.at(-1)).toBe('example.com');
  });
});

describe('np= — policy for non-existent subdomains (RFC 9989 §4.7)', () => {
  const TXT = { '_dmarc.e.com': ['v=DMARC1; p=reject; sp=none; np=reject'] };

  it('applies np= to a subdomain that is not in the DNS', async () => {
    // The case that matters: billing.e.com does not exist, which is exactly why an
    // attacker picked it. sp=none would have delivered the forgery.
    const r = await checkDmarc(new FakeDns({ TXT }), 'billing.e.com');
    expect(r.record).toMatchObject({ effectivePolicy: 'reject', appliedTag: 'np' });
  });

  it('leaves an existing subdomain under sp=', async () => {
    const dns = new FakeDns({ TXT, A: { 'mail.e.com': ['192.0.2.1'] } });
    const r = await checkDmarc(dns, 'mail.e.com');
    expect(r.record).toMatchObject({ effectivePolicy: 'none', appliedTag: 'sp' });
  });

  it('counts a name with only an MX as existing', async () => {
    // "Non-existent" means NXDOMAIN, not "has no address records".
    const dns = new FakeDns({ TXT, MX: { 'mx.e.com': [{ exchange: 'a.e.com', priority: 10 }] } });
    expect((await checkDmarc(dns, 'mx.e.com')).record?.effectivePolicy).toBe('none');
  });

  it('does not probe when there is no np= to apply', async () => {
    const dns = new FakeDns({ TXT: { '_dmarc.e.com': ['v=DMARC1; p=reject; sp=none'] } });
    await checkDmarc(dns, 'mail.e.com');
    expect(dns.log.filter((q) => q.startsWith('A '))).toEqual([]);
  });
});

describe('t= test mode (RFC 9989 §4.7)', () => {
  it('parses t=y and t=n', () => {
    expect(parseDmarcRecord('v=DMARC1; p=reject; t=y', 'e.com', false).testMode).toBe(true);
    expect(parseDmarcRecord('v=DMARC1; p=reject; t=n', 'e.com', false).testMode).toBe(false);
    expect(parseDmarcRecord('v=DMARC1; p=reject', 'e.com', false).testMode).toBe(false);
  });

  it('rejects any other value rather than guessing', () => {
    // Defaulting either way would misreport whether the domain is enforcing at all.
    expect(parseDmarcRecord('v=DMARC1; p=reject; t=25', 'e.com', false).errors.join(' '))
      .toMatch(/t=25 must be y or n/);
  });
});

describe('tag vocabulary after RFC 9989', () => {
  it('does not call the new tags typos', () => {
    // The failure this guards: the guides tell people to publish np=, and the checker
    // answers "unrecognised — usually a typo".
    const r = parseDmarcRecord('v=DMARC1; p=reject; np=reject; t=y; psd=n', 'e.com', false);
    expect(r.unknownTags).toEqual([]);
    expect(r.errors).toEqual([]);
  });

  it('reports the removed tags as deprecated, not unrecognised', () => {
    const r = parseDmarcRecord('v=DMARC1; p=reject; pct=100; rf=afrf; ri=3600', 'e.com', false);
    expect(r.deprecatedTags.sort()).toEqual(['pct', 'rf', 'ri']);
    expect(r.unknownTags).toEqual([]);
  });

  it('still flags an actual typo', () => {
    const r = parseDmarcRecord('v=DMARC1; p=reject; nq=reject', 'e.com', false);
    expect(r.unknownTags).toEqual(['nq']);
  });
});

describe('every DMARC record this tool emits is one you could actually publish', () => {
  // The invariant that was missing. The np= fix originally spliced the tag in after p=
  // and re-emitted an sp= the record already had; a duplicate tag is something this same
  // parser calls an error, so the tool would have handed out a record it then rejects.
  // Remediation is the entire product here — a broken fix is worse than no fix.
  const records = [
    'v=DMARC1; p=none; rua=mailto:d@e.com',
    'v=DMARC1; p=quarantine; rua=mailto:d@e.com',
    'v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@e.com',
    'v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:d@e.com',
    'v=DMARC1; p=reject; t=y; rua=mailto:d@e.com',
    // No-space and trailing-semicolon forms, which real records use freely.
    'v=DMARC1;p=reject;rua=mailto:d@e.com;',
  ];

  const recordFixes = async (raw: string) => {
    const dmarc = await checkDmarc(new FakeDns({ TXT: { '_dmarc.e.com': [raw] } }), 'e.com');
    // flatMap rather than map+filter: filter does not narrow Fix to its record variant,
    // and the point of the test is to read `.value` off it.
    return dmarcFindings({ domain: 'e.com', dmarc, mx: [] })
      .flatMap((f) => (f.fix?.kind === 'record' && f.fix.type === 'TXT' ? [f.fix] : []));
  };

  for (const raw of records) {
    it(`re-parses cleanly: ${raw}`, async () => {
      const fixes = await recordFixes(raw);
      // Each of these records has something wrong with it, so a fix must be offered —
      // otherwise the loop below would pass by testing nothing.
      expect(fixes.length).toBeGreaterThan(0);

      for (const fix of fixes) {
        const reparsed = parseDmarcRecord(fix.value, 'e.com', false);
        expect(reparsed.errors, `${raw} → ${fix.value}`).toEqual([]);
        expect(reparsed.policy).not.toBeNull();
      }
    });
  }

  it('offers no record to a record that is already right', async () => {
    // The other half of the contract: a finding with a fix is a claim something needs
    // changing, and a fully modern record must not be nagged into churn.
    expect(await recordFixes('v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:d@e.com'))
      .toEqual([]);
  });
});

describe('external destination verification (RFC 9990 §5.4)', () => {
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
