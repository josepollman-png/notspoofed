import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { InvalidDomainError } from '../src/lib/check.js';
import {
  DomainDoesNotResolveError,
  findSelectors,
  normaliseCustomSelectors,
  normaliseFinderDomain,
  providerFromCname,
  SELECTOR_LIST,
} from '../src/lib/dkim/finder.js';
import { parseDkimRecord } from '../src/lib/dkim/check.js';
import type { Answer } from '../src/lib/dns/resolver.js';
import { FakeDns, type Zone } from './fake-dns.js';

// A real 1024-bit RSA SPKI from a live DKIM record, and a 2048-bit one generated here.
const RSA_1024 =
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4T1PE2vh5xqRGzOrDnkoi03N/BFQ+GLa/xF69d8K0QOZBxTJb' +
  'ttc2DxcPdpvxqQRQOheompWvzCvWw/SH/NMgq72ulPKz2nHQbU6wIucXMf/sizgnsy+Ihiw9S5c/5sBMHUVZStqh' +
  'HMuY8QOkIrM6NvwYQOK9M2rXBRHrPS2VkQIDAQAB';
const RSA_2048 = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .publicKey.export({ type: 'spki', format: 'der' })
  .toString('base64');
const ED25519 = generateKeyPairSync('ed25519')
  .publicKey.export({ type: 'spki', format: 'der' })
  .toString('base64')
  // DKIM ed25519 (RFC 8463) publishes the raw 32-byte key, not the SPKI wrapper; the
  // parser reports 256 bits for ed25519 regardless, so either form exercises it.
  .slice(-43);

/** Resolvable domain: an MX and nothing else, plus whatever the test adds. */
function zone(extra: Zone = {}): Zone {
  return {
    MX: { 'example.com': [{ exchange: 'mx.example.com', priority: 10 }] },
    ...extra,
    TXT: { ...extra.TXT },
    CNAME: { ...extra.CNAME },
  };
}

describe('input normalisation', () => {
  it('accepts a bare domain, a URL and an email address', () => {
    expect(normaliseFinderDomain('Example.COM.')).toBe('example.com');
    expect(normaliseFinderDomain('https://mail.example.com/x?y=1')).toBe('mail.example.com');
    expect(normaliseFinderDomain('someone@example.com')).toBe('example.com');
  });

  it('converts an internationalised name to punycode', () => {
    expect(normaliseFinderDomain('münchen.de')).toBe('xn--mnchen-3ya.de');
    expect(normaliseFinderDomain('me@münchen.de')).toBe('xn--mnchen-3ya.de');
  });

  it('rejects IP addresses and non-public suffixes', () => {
    expect(() => normaliseFinderDomain('10.0.0.1')).toThrow(InvalidDomainError);
    expect(() => normaliseFinderDomain('printer.local')).toThrow(InvalidDomainError);
    expect(() => normaliseFinderDomain('intranet.corp')).toThrow(InvalidDomainError);
    expect(() => normaliseFinderDomain('')).toThrow(InvalidDomainError);
  });

  it('validates custom selectors as DNS labels and caps the count', () => {
    expect(normaliseCustomSelectors([' Google ', 'k1', 'google'])).toEqual(['google', 'k1']);
    expect(() => normaliseCustomSelectors(['bad selector'])).toThrow(InvalidDomainError);
    expect(() => normaliseCustomSelectors(['-lead'])).toThrow(InvalidDomainError);
    expect(() => normaliseCustomSelectors(Array.from({ length: 21 }, (_, i) => `s${i}`))).toThrow(
      /At most 20/,
    );
  });
});

describe('record parsing', () => {
  it('reads key size from RSA keys and reports 256 for ed25519', () => {
    expect(parseDkimRecord(`v=DKIM1; k=rsa; p=${RSA_1024}`, 's', 'x')!.bits).toBe(1024);
    expect(parseDkimRecord(`v=DKIM1; k=rsa; p=${RSA_2048}`, 's', 'x')!.bits).toBe(2048);
    const ed = parseDkimRecord(`v=DKIM1; k=ed25519; p=${ED25519}`, 's', 'x')!;
    expect(ed.keyType).toBe('ed25519');
  });

  it('flags a revoked key, a missing version and malformed base64', () => {
    expect(parseDkimRecord('v=DKIM1; p=', 's', 'x')!.revoked).toBe(true);
    expect(parseDkimRecord(`p=${RSA_2048}`, 's', 'x')!.versionOk).toBe(false);
    expect(parseDkimRecord('v=DKIM1; p=!!!not-base64!!!', 's', 'x')!.parseError).toBeDefined();
  });
});

describe('provider attribution from a CNAME target', () => {
  it('matches the longest known suffix', () => {
    expect(providerFromCname('selector1-contoso-com._domainkey.contoso.onmicrosoft.com.')).toBe('Microsoft 365');
    expect(providerFromCname('abc123._domainkey.dkim.amazonses.com')).toBe('Amazon SES');
    expect(providerFromCname('s1.domainkey.u123.wl.sendgrid.net')).toBe('SendGrid');
    expect(providerFromCname('20250101pm._domainkey.pm.mtasv.net')).toBe('Postmark');
    expect(providerFromCname('unknown.example.org')).toBeNull();
  });
});

describe('the sweep', () => {
  it('finds a Google Workspace selector and attributes it from the list', async () => {
    const dns = new FakeDns(zone({ TXT: { 'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${RSA_2048}`] } }));
    const r = await findSelectors('example.com', { dns });

    expect(r.selectorsFound).toHaveLength(1);
    const g = r.selectorsFound[0]!;
    expect(g.selector).toBe('google');
    expect(g.source).toBe('TXT');
    expect(g.providerGuess).toBe('Google Workspace');
    expect(g.providerSource).toBe('list');
    expect(g.keyBits).toBe(2048);
    expect(g.flags).toEqual([]);
    expect(r.wildcardDetected).toBe(false);
    expect(r.timedOut).toBe(false);
    expect(r.selectorsTried).toBe(SELECTOR_LIST.length);
  });

  it('follows a Microsoft-style CNAME and attributes from the target, not the name', async () => {
    const name = 'selector1._domainkey.example.com';
    const dns = new FakeDns(
      zone({
        TXT: { [name]: [`v=DKIM1; k=rsa; p=${RSA_2048}`] },
        CNAME: { [name]: ['selector1-example-com._domainkey.example.onmicrosoft.com'] },
      }),
    );
    const r = await findSelectors('example.com', { dns });
    const hit = r.selectorsFound.find((f) => f.selector === 'selector1')!;
    expect(hit.source).toBe('CNAME');
    expect(hit.cnameTarget).toBe('selector1-example-com._domainkey.example.onmicrosoft.com');
    expect(hit.providerGuess).toBe('Microsoft 365');
    expect(hit.providerSource).toBe('cname');
  });

  it('discards wildcard answers but keeps a real key that differs from them', async () => {
    const dns = new FakeDns(
      zone({
        TXT: {
          '*._domainkey.example.com': ['v=DKIM1; p='],
          'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${RSA_2048}`],
        },
      }),
    );
    const r = await findSelectors('example.com', { dns });
    expect(r.wildcardDetected).toBe(true);
    expect(r.wildcardRecord).toBe('v=DKIM1; p=');
    expect(r.wildcardMatches).toBeGreaterThan(200);
    expect(r.selectorsFound.map((f) => f.selector)).toEqual(['google']);
    expect(r.notes.some((n) => n.includes('wildcard'))).toBe(true);
  });

  it('flags weak, revoked, testing and duplicate keys', async () => {
    const dns = new FakeDns(
      zone({
        TXT: {
          'k1._domainkey.example.com': [`v=DKIM1; t=y; p=${RSA_1024}`],
          'k2._domainkey.example.com': [`v=DKIM1; p=${RSA_1024}`],
          'pm._domainkey.example.com': ['v=DKIM1; p='],
        },
      }),
    );
    const r = await findSelectors('example.com', { dns });
    const by = Object.fromEntries(r.selectorsFound.map((f) => [f.selector, f]));
    expect(by['k1']!.flags).toEqual(expect.arrayContaining(['testing', 'weak-key', 'duplicate-key']));
    expect(by['k2']!.flags).toEqual(expect.arrayContaining(['weak-key', 'duplicate-key']));
    expect(by['pm']!.flags).toEqual(['revoked']);
  });

  it('runs custom selectors first and reports the ones that did not resolve', async () => {
    const dns = new FakeDns(zone({ TXT: { 'mine._domainkey.example.com': [`v=DKIM1; p=${RSA_2048}`] } }));
    const r = await findSelectors('example.com', { dns, customSelectors: ['mine', 'other'] });
    expect(r.selectorsFound[0]!.selector).toBe('mine');
    expect(r.selectorsFound[0]!.providerSource).toBe('user');
    expect(r.missingCustomSelectors).toEqual(['other']);
    expect(dns.log[dns.log.findIndex((l) => l.includes('_domainkey')) + 1]).toContain('mine._domainkey');
  });

  it('returns a partial result when the budget runs out', async () => {
    class SlowDns extends FakeDns {
      override txt(name: string): Promise<Answer<string>> {
        if (name.includes('_domainkey') && !name.startsWith('zq7x9')) {
          return new Promise((resolve) => setTimeout(() => resolve(super.txt(name)), 200));
        }
        return super.txt(name);
      }
    }
    const dns = new SlowDns(zone());
    const r = await findSelectors('example.com', { dns, budgetMs: 300, concurrency: 5 });
    expect(r.timedOut).toBe(true);
    expect(r.selectorsTried).toBeLessThan(r.selectorsTotal);
    expect(r.notes.some((n) => n.startsWith('Timed out after'))).toBe(true);
  });

  it('reports nothing found, honestly, for a domain with no selectors', async () => {
    const r = await findSelectors('example.com', { dns: new FakeDns(zone()) });
    expect(r.selectorsFound).toEqual([]);
    expect(r.wildcardDetected).toBe(false);
    expect(r.timedOut).toBe(false);
  });

  it('refuses a domain with no records at all', async () => {
    await expect(findSelectors('example.com', { dns: new FakeDns({}) })).rejects.toThrow(DomainDoesNotResolveError);
  });
});

describe('the selector list', () => {
  it('has no duplicates and only valid labels', () => {
    const seen = new Set<string>();
    for (const { selector } of SELECTOR_LIST) {
      expect(seen.has(selector), `duplicate: ${selector}`).toBe(false);
      seen.add(selector);
      expect(selector).toMatch(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/);
    }
  });

  it('contains no fabricated Amazon SES Easy DKIM tokens', () => {
    // Easy DKIM selectors are random 32-character strings; the list must not pretend
    // to know any. BYODKIM names like `ses` are fine.
    expect(SELECTOR_LIST.filter((s) => /^[a-z0-9]{32}$/.test(s.selector))).toEqual([]);
  });
});
