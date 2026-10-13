import { describe, expect, it } from 'vitest';
import { runCheck } from '../src/lib/check.js';
import type { Finding, Fix } from '../src/lib/findings.js';
import { FakeDns, type Zone } from './fake-dns.js';

/**
 * No fix may tell anyone to publish a TXT record at a name that is a CNAME.
 *
 * DNS allows nothing beside a CNAME (RFC 1034 §3.6.2, RFC 2181 §10.1). The regression:
 * homedepot.com's `_dmarc` is a CNAME into Proofpoint and salesforce.com's points at
 * `_dmarc.reject100.salesforce.com`, and the np= fix on both said "publish this TXT at
 * _dmarc.<domain>" — a record their DNS host would refuse, or one nothing would read.
 */

const noDnssec = async (domain: string) => ({ signed: false, zone: domain, unknown: true });

const check = (domain: string, zone: Zone) =>
  runCheck(domain, { dns: new FakeDns(zone), dnssec: noDnssec });

const fixOf = (findings: Finding[], id: string): Fix | undefined =>
  findings.find((f) => f.id === id)?.fix;

/** Every name in the fixture that is an alias. */
const aliases = (zone: Zone) => new Set(Object.keys(zone.CNAME ?? {}));

/** The invariant itself: no record fix anywhere is aimed at an alias. */
function expectNoRecordAtAlias(findings: Finding[], zone: Zone) {
  for (const f of findings) {
    if (f.fix?.kind === 'record') expect(aliases(zone).has(f.fix.host), `${f.id} → ${f.fix.host}`).toBe(false);
  }
}

// Shaped like homedepot.com: one hop, into the DMARC provider's zone.
const ONE_HOP: Zone = {
  TXT: {
    'example.com': ['v=spf1 ip4:192.0.2.1 -all'],
    '_dmarc.example.com.dmarc.has.pphosted.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
  },
  CNAME: { '_dmarc.example.com': ['_dmarc.example.com.dmarc.has.pphosted.com'] },
};

// Two hops, ending at a record still on p=none.
const TWO_HOPS: Zone = {
  TXT: {
    'example.com': ['v=spf1 ip4:192.0.2.1 -all'],
    'policy.dmarc-host.example.org': ['v=DMARC1; p=none; rua=mailto:d@example.com'],
  },
  CNAME: {
    '_dmarc.example.com': ['example-com.dmarc-host.example.net'],
    'example-com.dmarc-host.example.net': ['policy.dmarc-host.example.org'],
  },
};

// Shaped like salesforce.com: the alias points at a name in the same organisation.
const SAME_ORG: Zone = {
  TXT: {
    'example.com': ['v=spf1 ip4:192.0.2.1 -all'],
    '_dmarc.reject100.example.com': ['v=DMARC1;p=reject;rua=mailto:d@example.com'],
  },
  CNAME: { '_dmarc.example.com': ['_dmarc.reject100.example.com'] },
};

describe('a DMARC record behind a CNAME', () => {
  it('one hop: the np= fix names the provider target, not _dmarc.<domain>', async () => {
    const r = await check('example.com', ONE_HOP);
    const fix = fixOf(r.report.findings, 'dmarc-no-np');

    expect(fix?.kind).toBe('action');
    if (fix?.kind !== 'action') return;
    expect(fix.managedRecord).toMatchObject({
      host: '_dmarc.example.com',
      target: '_dmarc.example.com.dmarc.has.pphosted.com',
      type: 'TXT',
      value: 'v=DMARC1; p=reject; rua=mailto:d@example.com; np=reject',
    });
    expect(fix.steps[0]).toContain('is a CNAME to _dmarc.example.com.dmarc.has.pphosted.com');
    expect(fix.steps[1]).toMatch(/not in your DNS.*provider/);
    expectNoRecordAtAlias(r.report.findings, ONE_HOP);
  });

  it('two hops: the fix names the end of the chain and the hop in between', async () => {
    const r = await check('example.com', TWO_HOPS);
    const fix = fixOf(r.report.findings, 'dmarc-p-none');

    expect(fix?.kind).toBe('action');
    if (fix?.kind !== 'action') return;
    expect(fix.managedRecord?.target).toBe('policy.dmarc-host.example.org');
    expect(fix.managedRecord?.value).toContain('p=quarantine');
    expect(fix.steps[0]).toContain('(via example-com.dmarc-host.example.net)');
    expectNoRecordAtAlias(r.report.findings, TWO_HOPS);
  });

  it('a target in the same organisation is described as the user’s own DNS', async () => {
    const r = await check('example.com', SAME_ORG);
    const fix = fixOf(r.report.findings, 'dmarc-no-np');

    expect(fix?.kind).toBe('action');
    if (fix?.kind !== 'action') return;
    expect(fix.managedRecord?.target).toBe('_dmarc.reject100.example.com');
    expect(fix.steps[1]).toMatch(/in your own DNS/);
  });

  it('applies to every DMARC fix, not only np=', async () => {
    // p=quarantine, sp weaker, t=y, pct<100 and no rua — every record-building finding.
    const zone: Zone = {
      TXT: {
        'example.com': ['v=spf1 ip4:192.0.2.1 -all'],
        'managed.example.net': ['v=DMARC1; p=quarantine; sp=none; t=y; pct=50'],
      },
      CNAME: { '_dmarc.example.com': ['managed.example.net'] },
    };
    const r = await check('example.com', zone);
    const ids = ['dmarc-quarantine', 'dmarc-sp-weaker', 'dmarc-test-mode', 'dmarc-pct', 'dmarc-no-rua'];

    for (const id of ids) {
      const fix = fixOf(r.report.findings, id);
      expect(fix?.kind, id).toBe('action');
      if (fix?.kind === 'action') expect(fix.managedRecord?.target, id).toBe('managed.example.net');
    }
    expectNoRecordAtAlias(r.report.findings, zone);
  });

  it('a CNAME to nothing is not a place to publish a new record either', async () => {
    const zone: Zone = {
      TXT: { 'example.com': ['v=spf1 ip4:192.0.2.1 -all'] },
      CNAME: { '_dmarc.example.com': ['gone.former-provider.example.net'] },
    };
    const r = await check('example.com', zone);
    const fix = fixOf(r.report.findings, 'dmarc-missing');

    expect(fix?.kind).toBe('action');
    if (fix?.kind === 'action') expect(fix.managedRecord?.target).toBe('gone.former-provider.example.net');
  });

  it('a record published directly still gets a plain record fix', async () => {
    const r = await check('example.com', {
      TXT: {
        'example.com': ['v=spf1 ip4:192.0.2.1 -all'],
        '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
      },
    });
    expect(fixOf(r.report.findings, 'dmarc-no-np')).toMatchObject({ kind: 'record', host: '_dmarc.example.com' });
  });
});

describe('the other fixed names', () => {
  it('_mta-sts and _smtp._tls: an alias with no record gets no TXT suggestion there', async () => {
    const zone: Zone = {
      TXT: { 'example.com': ['v=spf1 ip4:192.0.2.1 -all'], '_dmarc.example.com': ['v=DMARC1; p=reject; np=reject; rua=mailto:d@example.com'] },
      MX: { 'example.com': [{ exchange: 'mx.example.com', priority: 10 }] },
      CNAME: {
        '_mta-sts.example.com': ['_mta-sts.example.com.provider.example.net'],
        '_smtp._tls.example.com': ['_smtp._tls.example.com.provider.example.net'],
      },
    };
    const r = await check('example.com', zone);

    for (const [id, target] of [
      ['mtasts-missing', '_mta-sts.example.com.provider.example.net'],
      ['tlsrpt-missing', '_smtp._tls.example.com.provider.example.net'],
    ] as const) {
      const fix = fixOf(r.report.findings, id);
      expect(fix?.kind, id).toBe('action');
      if (fix?.kind === 'action') expect(fix.managedRecord?.target, id).toBe(target);
    }
    expectNoRecordAtAlias(r.report.findings, zone);
  });

  it('SPF: a checked name that is itself an alias gets no SPF record fix at it', async () => {
    const zone: Zone = {
      TXT: { 'mail-host.example.net': ['v=spf1 ip4:192.0.2.1 +all'] },
      CNAME: { 'news.example.com': ['mail-host.example.net'] },
    };
    const r = await check('news.example.com', zone);
    const fix = fixOf(r.report.findings, 'spf-permissive-all');

    expect(fix?.kind).toBe('action');
    if (fix?.kind === 'action') {
      expect(fix.managedRecord).toMatchObject({ host: 'news.example.com', target: 'mail-host.example.net' });
    }
    expectNoRecordAtAlias(r.report.findings, zone);
  });
});
