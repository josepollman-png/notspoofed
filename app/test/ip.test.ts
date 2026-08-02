import { describe, expect, it } from 'vitest';
import { analyzeIp } from '../src/lib/ip/analyze.js';
import { isRefusalCode } from '../src/lib/ip/blocklists.js';
import { checkIp, isPublicIpv4, looksGeneric, reverseIpv4 } from '../src/lib/ip/check.js';
import { FakeDns } from './fake-dns.js';

const REVERSED = '5.113.0.203'; // 203.0.113.5

describe('address handling', () => {
  it('reverses octets for DNSBL and PTR queries', () => {
    expect(reverseIpv4('203.0.113.5')).toBe('5.113.0.203');
  });

  it('rejects private and reserved ranges', () => {
    // Accepting these would let the endpoint be aimed at internal infrastructure,
    // and they can never be public sending addresses anyway.
    for (const ip of ['10.0.0.1', '192.168.1.1', '127.0.0.1', '172.16.0.1', '169.254.1.1', '224.0.0.1']) {
      expect(isPublicIpv4(ip), ip).toBe(false);
    }
    expect(isPublicIpv4('203.0.113.5')).toBe(false); // documentation range
    expect(isPublicIpv4('209.85.220.41')).toBe(true);
  });
});

describe('generic reverse DNS detection', () => {
  it('spots names that embed the address', () => {
    expect(looksGeneric('203-0-113-5.dsl.example.net', '203.0.113.5')).toBe(true);
    expect(looksGeneric('5.113.0.203.in-addr.example.net', '203.0.113.5')).toBe(true);
    expect(looksGeneric('host203.0.113.5.example.net', '203.0.113.5')).toBe(true);
  });

  it('spots dynamic-pool naming', () => {
    expect(looksGeneric('dynamic-42.example.net', '198.51.100.9')).toBe(true);
    expect(looksGeneric('pool123.broadband.example.net', '198.51.100.9')).toBe(true);
  });

  it('accepts a real mail hostname', () => {
    expect(looksGeneric('mail.example.com', '203.0.113.5')).toBe(false);
    expect(looksGeneric('mx1.sendgrid.net', '198.51.100.9')).toBe(false);
  });
});

describe('refusal codes', () => {
  it('recognises 127.255.255.x as a refusal, not a listing', () => {
    expect(isRefusalCode('127.255.255.254')).toBe(true);
    expect(isRefusalCode('127.0.0.2')).toBe(false);
  });
});

describe('checkIp', () => {
  const clean = new FakeDns({
    PTR: { [`${REVERSED}.in-addr.arpa`]: ['mail.example.com'] },
    A: { 'mail.example.com': ['203.0.113.5'] },
    TXT: { [`${REVERSED}.origin.asn.cymru.com`]: ['64500 | 203.0.113.0/24 | US | arin | 2020-01-01'] },
  });

  it('confirms forward-confirmed reverse DNS', async () => {
    const r = await checkIp(clean, '203.0.113.5');
    expect(r.ptr).toEqual(['mail.example.com']);
    expect(r.forwardConfirmed).toBe(true);
    expect(r.genericPtr).toBe(false);
    expect(r.asn).toMatchObject({ number: '64500', country: 'US' });
  });

  it('detects a PTR that does not resolve back', async () => {
    const dns = new FakeDns({
      PTR: { [`${REVERSED}.in-addr.arpa`]: ['mail.example.com'] },
      A: { 'mail.example.com': ['198.51.100.1'] }, // different address
    });
    const r = await checkIp(dns, '203.0.113.5');
    expect(r.forwardConfirmed).toBe(false);
  });

  it('reports a listing with its code and reason', async () => {
    const dns = new FakeDns({
      PTR: { [`${REVERSED}.in-addr.arpa`]: ['mail.example.com'] },
      A: {
        'mail.example.com': ['203.0.113.5'],
        [`${REVERSED}.zen.spamhaus.org`]: ['127.0.0.2'],
      },
      TXT: { [`${REVERSED}.zen.spamhaus.org`]: ['https://check.spamhaus.org/query/ip/203.0.113.5'] },
    });
    const r = await checkIp(dns, '203.0.113.5');
    const hit = r.listedOn.find((h) => h.list.zone === 'zen.spamhaus.org')!;
    expect(hit.code).toBe('127.0.0.2');
    expect(hit.meaning).toMatch(/SBL/);
    expect(hit.reason).toMatch(/spamhaus/);
  });

  it('treats a refusal as unknown, never as clean', async () => {
    // The dangerous failure: reading "query refused" as "not listed" produces a false
    // all-clear on the tool people trust mid-incident.
    const dns = new FakeDns({
      A: { [`${REVERSED}.zen.spamhaus.org`]: ['127.255.255.254'] },
    });
    const r = await checkIp(dns, '203.0.113.5');
    const hit = r.blocklists.find((h) => h.list.zone === 'zen.spamhaus.org')!;
    expect(hit.status).toBe('unavailable');
    expect(r.listedOn).not.toContain(hit);
    expect(r.unavailable).toContain(hit);
  });
});

describe('findings', () => {
  const base = {
    ip: '203.0.113.5', version: 4 as const, ptr: ['mail.example.com'],
    forwardConfirmed: true, genericPtr: false, blocklists: [], listedOn: [], unavailable: [],
  };

  it('raises missing reverse DNS as critical', () => {
    const f = analyzeIp({ ...base, ptr: [], forwardConfirmed: false });
    expect(f[0]).toMatchObject({ id: 'ip-no-ptr', severity: 'critical' });
    expect(f[0]!.fix).toBeDefined();
  });

  it('distinguishes a PBL policy listing from a reputation listing', async () => {
    const pbl = new FakeDns({
      PTR: { [`${REVERSED}.in-addr.arpa`]: ['mail.example.com'] },
      A: {
        'mail.example.com': ['203.0.113.5'],
        [`${REVERSED}.zen.spamhaus.org`]: ['127.0.0.10'],
      },
    });
    const findings = analyzeIp(await checkIp(pbl, '203.0.113.5'));
    const hit = findings.find((f) => f.id === 'ip-blocklisted-major')!;
    // A PBL listing on a residential range is the system working as intended, not an
    // emergency — grading it critical would be crying wolf.
    expect(hit.severity).toBe('warning');
    expect(hit.title).toMatch(/Policy Block List/);
  });

  it('grades a real SBL listing as critical', async () => {
    const sbl = new FakeDns({
      PTR: { [`${REVERSED}.in-addr.arpa`]: ['mail.example.com'] },
      A: {
        'mail.example.com': ['203.0.113.5'],
        [`${REVERSED}.zen.spamhaus.org`]: ['127.0.0.2'],
      },
    });
    const findings = analyzeIp(await checkIp(sbl, '203.0.113.5'));
    expect(findings.find((f) => f.id === 'ip-blocklisted-major')!.severity).toBe('critical');
  });

  it('keeps UCEPROTECT out of the critical bucket', async () => {
    const uce = new FakeDns({
      PTR: { [`${REVERSED}.in-addr.arpa`]: ['mail.example.com'] },
      A: {
        'mail.example.com': ['203.0.113.5'],
        [`${REVERSED}.dnsbl-1.uceprotect.net`]: ['127.0.0.2'],
      },
    });
    const findings = analyzeIp(await checkIp(uce, '203.0.113.5'));
    expect(findings.find((f) => f.id === 'ip-blocklisted-informational')?.severity).toBe('info');
    expect(findings.some((f) => f.severity === 'critical')).toBe(false);
  });

  it('does not claim a clean result when lists were unavailable', () => {
    const f = analyzeIp({
      ...base,
      unavailable: [{ list: { zone: 'z', name: 'Z', weight: 'major', delistUrl: '' }, status: 'unavailable', reason: 'refused' }],
    });
    expect(f.map((x) => x.id)).toContain('ip-blocklist-unavailable');
    expect(f.map((x) => x.id)).not.toContain('ip-not-listed');
  });

  it('notes that IPv6 blocklist coverage is absent rather than clean', () => {
    const f = analyzeIp({ ...base, version: 6, ip: '2001:db8::1' });
    expect(f.map((x) => x.id)).toContain('ip-ipv6-limited');
    expect(f.map((x) => x.id)).not.toContain('ip-not-listed');
  });
});
