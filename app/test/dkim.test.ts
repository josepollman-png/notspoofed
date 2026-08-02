import { describe, expect, it } from 'vitest';
import { checkDkim, parseDkimRecord } from '../src/lib/dkim/check.js';
import { FakeDns } from './fake-dns.js';

// A real 1024-bit RSA SPKI, base64 — taken from a live published DKIM record so the
// key parser is exercised against something genuine rather than random bytes.
const RSA_1024 =
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4T1PE2vh5xqRGzOrDnkoi03N/BFQ+GLa/xF69d8K0QOZBxTJb' +
  'ttc2DxcPdpvxqQRQOheompWvzCvWw/SH/NMgq72ulPKz2nHQbU6wIucXMf/sizgnsy+Ihiw9S5c/5sBMHUVZStqh' +
  'HMuY8QOkIrM6NvwYQOK9M2rXBRHrPS2VkQIDAQAB';

describe('record validity', () => {
  it('requires a p= tag', () => {
    // This is the wildcard trap: hubspot.com and zendesk.com return exactly this for
    // any *._domainkey name. It is a valid TXT record and not remotely a DKIM key.
    expect(parseDkimRecord('v=spf1 ~all', 'google', 'x')).toBeNull();
    expect(parseDkimRecord('some random txt', 'google', 'x')).toBeNull();
  });

  it('accepts a record with no v= tag, which RFC 6376 only recommends', () => {
    const key = parseDkimRecord(`k=rsa; t=s; p=${RSA_1024}`, 'm1', 'generic');
    expect(key).not.toBeNull();
    expect(key!.versionOk).toBe(false);
    expect(key!.bits).toBe(1024);
  });

  it('rejects a wrong version outright', () => {
    expect(parseDkimRecord(`v=DKIM2; p=${RSA_1024}`, 's', 'x')).toBeNull();
  });

  it('reads the modulus size out of the key', () => {
    expect(parseDkimRecord(`v=DKIM1; k=rsa; p=${RSA_1024}`, 's', 'x')!.bits).toBe(1024);
  });

  it('tolerates base64 wrapped across the record', () => {
    const wrapped = `v=DKIM1; k=rsa; p=${RSA_1024.slice(0, 40)} ${RSA_1024.slice(40)}`;
    expect(parseDkimRecord(wrapped, 's', 'x')!.bits).toBe(1024);
  });

  it('marks an empty p= as revoked rather than broken', () => {
    const key = parseDkimRecord('v=DKIM1; p=', 's', 'x')!;
    expect(key.revoked).toBe(true);
    expect(key.parseError).toBeUndefined();
  });

  it('detects testing mode', () => {
    expect(parseDkimRecord(`v=DKIM1; t=y; p=${RSA_1024}`, 's', 'x')!.testing).toBe(true);
    expect(parseDkimRecord(`v=DKIM1; t=s; p=${RSA_1024}`, 's', 'x')!.testing).toBe(false);
  });

  it('reports an unparseable key without discarding the record', () => {
    const key = parseDkimRecord('v=DKIM1; k=rsa; p=!!!not-base64!!!', 's', 'x')!;
    expect(key).not.toBeNull();
    expect(key.parseError).toBeDefined();
  });
});

describe('wildcard domains', () => {
  it('does not invent selectors on a domain that answers everything', async () => {
    // hubspot.com's actual behaviour: a wildcard TXT serving an SPF record.
    const dns = new FakeDns({ TXT: { '*._domainkey.wild.com': ['v=spf1 ~all'] } });
    const r = await checkDkim(dns, 'wild.com');
    expect(r.wildcardDns).toBe(true);
    expect(r.keys).toHaveLength(0);
  });

  it('discards hits identical to the wildcard even when they parse as DKIM', async () => {
    // example.com's actual behaviour: a wildcard publishing a revoked DKIM key.
    // Requiring p= is not enough here — the wildcard answer *has* a p= tag.
    const dns = new FakeDns({ TXT: { '*._domainkey.wild.com': ['v=DKIM1; p='] } });
    const r = await checkDkim(dns, 'wild.com');
    expect(r.wildcardDns).toBe(true);
    expect(r.keys).toHaveLength(0);
  });

  it('still finds real selectors on a domain that also has a wildcard', async () => {
    const dns = new FakeDns({
      TXT: {
        '*._domainkey.wild.com': ['v=spf1 ~all'],
        'google._domainkey.wild.com': [`v=DKIM1; k=rsa; p=${RSA_1024}`],
      },
    });
    const r = await checkDkim(dns, 'wild.com');
    expect(r.wildcardDns).toBe(true);
    expect(r.keys.map((k) => k.selector)).toEqual(['google']);
  });
});

describe('discovery', () => {
  it('tries user-supplied selectors first and labels them', async () => {
    const dns = new FakeDns({
      TXT: { 'custom-sel._domainkey.e.com': [`v=DKIM1; p=${RSA_1024}`] },
    });
    const r = await checkDkim(dns, 'e.com', ['custom-sel']);
    expect(r.keys[0]).toMatchObject({ selector: 'custom-sel', provider: 'user-supplied' });
  });

  it('reports nothing found without claiming DKIM is absent', async () => {
    const r = await checkDkim(new FakeDns({}), 'e.com');
    expect(r.keys).toHaveLength(0);
    expect(r.wildcardDns).toBe(false);
    expect(r.triedCount).toBeGreaterThan(30);
  });
});
