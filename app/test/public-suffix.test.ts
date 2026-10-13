import { describe, expect, it } from 'vitest';
import { apiBody } from '../src/lib/api-body.js';
import { InvalidDomainError, runCheck } from '../src/lib/check.js';
import { FakeDns, type Zone } from './fake-dns.js';

const noDnssec = async (domain: string) => ({ signed: false, zone: domain, unknown: true });
const check = (domain: string, zone: Zone) =>
  runCheck(domain, { dns: new FakeDns(zone), dnssec: noDnssec });

// _dmarc.gov.uk and gov.uk's SPF as resolved on 13 October 2026.
const GOV_UK: Zone = {
  TXT: {
    'gov.uk': ['v=spf1 -all', 'security_contact=https://vulnerability-reporting.service.security.gov.uk'],
    '_dmarc.gov.uk': ['v=DMARC1;p=reject;sp=none;np=reject;adkim=s;aspf=s;fo=1;rua=mailto:dmarc-rua@dmarc.service.gov.uk'],
  },
};

describe('checking a public suffix', () => {
  it('checks gov.uk, which publishes SPF and DMARC', async () => {
    const r = await check('gov.uk', GOV_UK);
    expect(r.publicSuffix).toBe(true);
    expect(r.dmarc.record?.policy).toBe('reject');
    expect(apiBody(r)).toMatchObject({ domain: 'gov.uk', publicSuffix: true, dmarc: { psd: null } });

    const f = r.report.findings.find((x) => x.id === 'public-suffix');
    expect(f?.severity).toBe('info');
    expect(f?.detail).toContain('Its DMARC record has no psd=y. RFC 9989 §5.2');
  });

  it('says nothing about psd= when the record carries psd=y', async () => {
    const r = await check('gov.uk', { TXT: { 'gov.uk': ['v=spf1 -all'], '_dmarc.gov.uk': ['v=DMARC1; p=reject; psd=y'] } });
    const f = r.report.findings.find((x) => x.id === 'public-suffix');
    expect(f?.detail).not.toContain('psd=y');
    expect(f?.fix).toBeUndefined();
  });

  it('rejects a suffix that publishes neither, saying why rather than "check the spelling"', async () => {
    const run = check('co.uk', {});
    await expect(run).rejects.toThrow(InvalidDomainError);
    await expect(run).rejects.toThrow(/is a public suffix .* publishes no SPF or DMARC record/);
  });

  it('does not reject one whose lookups merely failed', async () => {
    const r = await check('gov.uk', { ERRORS: { 'TXT gov.uk': 'SERVFAIL' }, TXT: { '_dmarc.gov.uk': ['v=DMARC1; p=reject'] } });
    expect(r.spf.lookupError).toBe('SERVFAIL');
  });

  it('an ordinary domain gets no public-suffix finding', async () => {
    const r = await check('example.gov.uk', { TXT: { 'example.gov.uk': ['v=spf1 -all'] } });
    expect(r.publicSuffix).toBe(false);
    expect(r.report.findings.some((x) => x.id === 'public-suffix')).toBe(false);
  });
});
