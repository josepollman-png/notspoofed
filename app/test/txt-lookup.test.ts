import { describe, expect, it } from 'vitest';
import { checkDkim } from '../src/lib/dkim/check.js';
import { checkDmarc } from '../src/lib/dmarc/check.js';
import { describeLookup, lookupTxt } from '../src/lib/dns/txt-lookup.js';
import { checkBimi, checkMtaSts, checkTlsRpt } from '../src/lib/modern/check.js';
import { buildReport, dmarcFindings } from '../src/lib/remediate.js';
import { evaluateSpf } from '../src/lib/spf/evaluate.js';
import { FakeDns, type Zone } from './fake-dns.js';

/**
 * Policy records behind CNAMEs, and lookups that get no answer.
 *
 * The regression this file exists for: costco.com publishes `p=reject` behind a CNAME
 * into Proofpoint, and the report said it had no DMARC record at all. The chain was
 * being followed; what failed was a transient SERVFAIL on the cold chain, read as
 * "absent". Every case below keeps those two apart.
 */

const COSTCO_TARGET = '_dmarc.costco.com.dmarc.has.pphosted.com';
const COSTCO_RECORD =
  'v=DMARC1; p=reject; sp=reject; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com; ' +
  'ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com;';

const isDmarc = (v: string) => /^v=DMARC1/i.test(v);

describe('DMARC behind a CNAME', () => {
  it('finds a record one CNAME away, and says where it lives (costco.com)', async () => {
    const dns = new FakeDns({
      CNAME: { '_dmarc.costco.com': [COSTCO_TARGET] },
      TXT: { [COSTCO_TARGET]: [COSTCO_RECORD] },
    });
    const r = await checkDmarc(dns, 'costco.com');
    expect(r.status).toBe('found');
    expect(r.record?.policy).toBe('reject');
    expect(r.record?.cnameChain).toEqual([COSTCO_TARGET]);
    expect(describeLookup(r.lookups[0]!)).toBe(`Found at ${COSTCO_TARGET}, via a CNAME from _dmarc.costco.com.`);
    const ids = dmarcFindings({ domain: 'costco.com', dmarc: r, mx: [] }).map((f) => f.id);
    expect(ids).not.toContain('dmarc-missing');
    expect(ids).toContain('dmarc-reject');
  });

  it('follows a two-hop chain', async () => {
    const dns = new FakeDns({
      CNAME: {
        '_dmarc.example.com': ['_dmarc.example.com.hosted.example.net'],
        '_dmarc.example.com.hosted.example.net': ['record.example.org'],
      },
      TXT: { 'record.example.org': ['v=DMARC1; p=quarantine'] },
    });
    const r = await checkDmarc(dns, 'example.com');
    expect(r.status).toBe('found');
    expect(r.record?.policy).toBe('quarantine');
    expect(r.record?.cnameChain).toEqual(['_dmarc.example.com.hosted.example.net', 'record.example.org']);
  });

  it('reports a CNAME to a target with no TXT as absent, with the evidence', async () => {
    const dns = new FakeDns({
      CNAME: { '_dmarc.example.com': ['gone.example.net'] },
    });
    const r = await checkDmarc(dns, 'example.com');
    expect(r.status).toBe('absent');
    expect(r.lookups[0]).toMatchObject({ name: '_dmarc.example.com', outcome: 'NXDOMAIN', cnameChain: ['gone.example.net'] });
    const missing = dmarcFindings({ domain: 'example.com', dmarc: r, mx: [] }).find((f) => f.id === 'dmarc-missing');
    expect(missing?.detail).toContain('Queried _dmarc.example.com (a CNAME to gone.example.net): the CNAME target does not exist (NXDOMAIN).');
  });

  it('stops on a CNAME loop instead of hanging, and says it is a loop', async () => {
    const dns = new FakeDns({
      CNAME: { '_dmarc.example.com': ['a.example.net'], 'a.example.net': ['_dmarc.example.com'] },
    });
    const r = await checkDmarc(dns, 'example.com');
    expect(r.status).toBe('absent');
    expect(r.lookups[0]?.cnameProblem).toBe('loop');
    expect(describeLookup(r.lookups[0]!)).toMatch(/CNAME loop/);
    // Bounded: the walk and one retry, not a spin.
    expect(dns.queryCount).toBeLessThan(15);
  });

  it('stops walking a chain longer than five hops', async () => {
    const CNAME: Record<string, string[]> = { '_dmarc.example.com': ['h1.example.net'] };
    for (let i = 1; i < 9; i++) CNAME[`h${i}.example.net`] = [`h${i + 1}.example.net`];
    const r = await lookupTxt(new FakeDns({ CNAME, TXT: { 'h9.example.net': ['v=DMARC1; p=none'] } }), '_dmarc.example.com', isDmarc);
    expect(r.cnameProblem).toBe('too-long');
    expect(r.cnameChain).toHaveLength(5);
  });

  it('leaves a plain TXT record exactly as it was (naver.com)', async () => {
    const dns = new FakeDns({ TXT: { '_dmarc.naver.com': ['v=DMARC1; p=none; rua=mailto:dmarc_reports@worksmobile.com'] } });
    const r = await checkDmarc(dns, 'naver.com');
    expect(r.status).toBe('found');
    expect(r.record?.policy).toBe('none');
    expect(r.record?.cnameChain).toEqual([]);
    expect(r.record?.foundAt).toBe('naver.com');
  });

  it('follows a CNAME at the organizational domain during inheritance', async () => {
    const dns = new FakeDns({
      CNAME: { '_dmarc.example.com': [COSTCO_TARGET] },
      TXT: { [COSTCO_TARGET]: [COSTCO_RECORD] },
    });
    const r = await checkDmarc(dns, 'mail.example.com');
    expect(r.status).toBe('found');
    expect(r.record?.inherited).toBe(true);
    expect(r.record?.foundAt).toBe('example.com');
    expect(r.record?.effectivePolicy).toBe('reject');
  });
});

describe('a lookup that gets no answer is not an absent record', () => {
  it('retries a transient SERVFAIL once and finds the record', async () => {
    const dns = new FakeDns({
      CNAME: { '_dmarc.costco.com': [COSTCO_TARGET] },
      TXT: { [COSTCO_TARGET]: [COSTCO_RECORD] },
      ERRORS: { 'TXT _dmarc.costco.com': ['SERVFAIL'] },
    });
    const r = await checkDmarc(dns, 'costco.com');
    expect(r.status).toBe('found');
    expect(r.record?.policy).toBe('reject');
  });

  it('asks the CNAME target directly when the chain as a whole keeps failing', async () => {
    const dns = new FakeDns({
      CNAME: { '_dmarc.costco.com': [COSTCO_TARGET] },
      TXT: { [COSTCO_TARGET]: [COSTCO_RECORD] },
      ERRORS: { 'TXT _dmarc.costco.com': ['SERVFAIL', 'SERVFAIL'] },
    });
    const r = await checkDmarc(dns, 'costco.com');
    expect(r.status).toBe('found');
    expect(dns.log).toContain(`TXT ${COSTCO_TARGET}`);
  });

  it('reports "could not be checked", never "no DMARC record", when there is no answer', async () => {
    const dns = new FakeDns({ ERRORS: { 'TXT _dmarc.example.com': 'SERVFAIL' } });
    const r = await checkDmarc(dns, 'example.com');
    expect(r.status).toBe('unknown');
    const findings = dmarcFindings({ domain: 'example.com', dmarc: r, mx: [] });
    expect(findings.map((f) => f.id)).toEqual(['dmarc-lookup-failed']);
    expect(findings[0]!.detail).toContain('no answer (SERVFAIL), after a retry');
  });

  it('does not walk past an unanswered name to report an inherited policy', async () => {
    const dns = new FakeDns({
      TXT: { '_dmarc.example.com': ['v=DMARC1; p=reject'] },
      ERRORS: { 'TXT _dmarc.mail.example.com': 'TIMEOUT' },
    });
    const r = await checkDmarc(dns, 'mail.example.com');
    expect(r.status).toBe('unknown');
    expect(r.record).toBeNull();
  });

  it('names what came back when a record is absent: NXDOMAIN, NODATA, other TXT', async () => {
    const dns = new FakeDns({
      TXT: { '_dmarc.b.com': [], '_dmarc.c.com': ['google-site-verification=abc'] },
    });
    const a = await lookupTxt(dns, '_dmarc.a.com', isDmarc);
    const b = await lookupTxt(dns, '_dmarc.b.com', isDmarc);
    const c = await lookupTxt(dns, '_dmarc.c.com', isDmarc);
    expect([a.outcome, b.outcome, c.outcome]).toEqual(['NXDOMAIN', 'NODATA', 'other-txt']);
    expect(describeLookup(a)).toBe('Queried _dmarc.a.com: the name does not exist (NXDOMAIN).');
  });
});

/** A full report from fixtures, with DNSSEC stubbed — it goes over DoH, not DNS. */
async function report(zone: Zone, domain = 'example.com') {
  const dns = new FakeDns(zone);
  const [spf, dkim, dmarc, mtaSts, tlsRpt, bimi] = await Promise.all([
    evaluateSpf(dns, domain), checkDkim(dns, domain, []), checkDmarc(dns, domain),
    checkMtaSts(dns, domain), checkTlsRpt(dns, domain), checkBimi(dns, domain),
  ]);
  const mx = [{ exchange: `mx.${domain}`, priority: 10 }];
  const input = {
    domain, spf, flatten: null, dkim, dmarc, mtaSts, tlsRpt, bimi, mx, nullMx: false,
    dnssec: { signed: false, zone: domain, unknown: true },
  };
  return { ...input, report: buildReport(input) };
}

describe('the other policy lookups', () => {
  it('follows CNAMEs for TLS-RPT and BIMI and records the chain', async () => {
    const r = await report({
      TXT: {
        'example.com': ['v=spf1 -all'],
        'tlsrpt.example.net': ['v=TLSRPTv1; rua=mailto:tls@example.com'],
        'bimi.example.net': ['v=BIMI1; l=https://example.com/logo.svg'],
      },
      CNAME: { '_smtp._tls.example.com': ['tlsrpt.example.net'], 'default._bimi.example.com': ['bimi.example.net'] },
    });
    expect(r.tlsRpt.record).toMatch(/^v=TLSRPTv1/);
    expect(r.tlsRpt.lookup.cnameChain).toEqual(['tlsrpt.example.net']);
    expect(r.bimi.record).toMatch(/^v=BIMI1/);
    expect(r.bimi.lookup.cnameChain).toEqual(['bimi.example.net']);
  });

  it('follows a CNAME for MTA-STS', async () => {
    const dns = new FakeDns({
      CNAME: { '_mta-sts.example.com': ['_mta-sts.hosted.example.net'] },
      TXT: { '_mta-sts.hosted.example.net': ['v=STSv1; id=20260929'] },
    });
    const r = await lookupTxt(dns, '_mta-sts.example.com', (v) => /^v=STSv1/i.test(v));
    expect(r.status).toBe('found');
    expect(r.cnameChain).toEqual(['_mta-sts.hosted.example.net']);
  });

  it('says MTA-STS and TLS-RPT could not be checked rather than that they are missing', async () => {
    const r = await report({
      TXT: { 'example.com': ['v=spf1 -all'] },
      ERRORS: { 'TXT _mta-sts.example.com': 'TIMEOUT', 'TXT _smtp._tls.example.com': 'SERVFAIL' },
    });
    const ids = r.report.findings.map((f) => f.id);
    expect(ids).toContain('mtasts-lookup-failed');
    expect(ids).toContain('tlsrpt-lookup-failed');
    expect(ids).not.toContain('mtasts-missing');
    expect(ids).not.toContain('tlsrpt-missing');
  });

  it('says SPF could not be checked, not "No SPF record", when the apex does not answer', async () => {
    const r = await report({ ERRORS: { 'TXT example.com': 'SERVFAIL' } });
    expect(r.spf.lookupError).toBe('SERVFAIL');
    const ids = r.report.findings.map((f) => f.id);
    expect(ids).toContain('spf-lookup-failed');
    expect(ids).not.toContain('spf-missing');
  });
});
