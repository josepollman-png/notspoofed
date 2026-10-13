import { describe, expect, it } from 'vitest';
import { runCheck } from '../src/lib/check.js';
import { FakeDns, type Zone } from './fake-dns.js';

/**
 * The spf-macros note used to say "normal for Salesforce" for every macro, including
 * Proofpoint's on homedepot.com and Valimail's on usenix.org.
 */

const noDnssec = async (domain: string) => ({ signed: false, zone: domain, unknown: true });
const note = async (zone: Zone) => {
  const r = await runCheck('example.com', { dns: new FakeDns(zone), dnssec: noDnssec });
  return r.report.findings.find((f) => f.id === 'spf-macros')?.detail ?? '';
};

describe('who a macro belongs to', () => {
  it('Proofpoint (homedepot.com shape)', async () => {
    const detail = await note({
      TXT: {
        'example.com': ['v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ip4:192.0.2.1 include:mail.zendesk.com ~all'],
        'mail.zendesk.com': ['v=spf1 ip4:198.51.100.0/24 ~all'],
      },
    });
    expect(detail).toContain('Proofpoint uses macros like this by design, so no action is needed.');
    expect(detail).not.toContain('Salesforce');
    expect(detail).not.toContain('only sender');
  });

  it('Valimail, as the whole record (usenix.org shape)', async () => {
    const detail = await note({ TXT: { 'example.com': ['v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all'] } });
    expect(detail).toContain('Valimail uses macros like this by design');
    expect(detail).toContain('Here the macro is the only sender in the record, so the 1/10 lookup count is all that can be seen from outside');
  });

  it('Salesforce, reached through an include', async () => {
    const detail = await note({
      TXT: {
        'example.com': ['v=spf1 include:_spf.salesforce.com ~all'],
        '_spf.salesforce.com': ['v=spf1 exists:%{i}._spf.mta.salesforce.com -all'],
      },
    });
    expect(detail).toContain('Salesforce uses macros like this by design');
    expect(detail).not.toContain('only sender');
  });

  it('an unrecognised service gets neutral wording, not a guess', async () => {
    const detail = await note({ TXT: { 'example.com': ['v=spf1 ip4:192.0.2.1 exists:%{i}._spf.example.net ~all'] } });
    expect(detail).toContain('Some hosted SPF services use macros like this');
    expect(detail).not.toMatch(/Salesforce|Proofpoint|Valimail/);
  });

  it('a mix names the known one and flags the other', async () => {
    const detail = await note({
      TXT: {
        'example.com': ['v=spf1 include:_spf.salesforce.com exists:%{i}._spf.example.net ~all'],
        '_spf.salesforce.com': ['v=spf1 exists:%{i}._spf.mta.salesforce.com -all'],
      },
    });
    expect(detail).toContain('Salesforce uses macros like this by design');
    expect(detail).toContain('exists:%{i}._spf.example.net is not from a service we recognise');
  });

  it('does not match a provider name inside a longer label', async () => {
    const detail = await note({ TXT: { 'example.com': ['v=spf1 exists:%{i}.notsalesforce.com ~all'] } });
    expect(detail).not.toContain('Salesforce uses');
  });
});
