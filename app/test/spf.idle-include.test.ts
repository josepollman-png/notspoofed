import { describe, expect, it } from 'vitest';
import { runCheck } from '../src/lib/check.js';
import { detectPlatforms } from '../src/lib/platform.js';
import { FakeDns, type Zone } from './fake-dns.js';

/**
 * isc.org, 13 October 2026: SPF at 9/10 lookups, one of them include:shops.shopify.com,
 * which answers `v=spf1 ~all` — it authorises nothing and can never match, but costs a
 * lookup. Nothing said so, the headroom advice was generic, and the include alone put a
 * "Setup guide for Shopify" banner on the report.
 */

const noDnssec = async (domain: string) => ({ signed: false, zone: domain, unknown: true });
const check = (zone: Zone) => runCheck('example.com', { dns: new FakeDns(zone), dnssec: noDnssec });

/** isc.org's shape: eight includes that send, plus Shopify's empty one = 9 lookups. */
function iscShape(): Zone {
  const txt: Record<string, string[]> = { 'shops.shopify.com': ['v=spf1 ~all'] };
  const terms: string[] = [];
  for (let i = 1; i <= 8; i++) {
    txt[`s${i}.example.net`] = [`v=spf1 ip4:198.51.100.${i} ~all`];
    terms.push(`include:s${i}.example.net`);
  }
  txt['example.com'] = [`v=spf1 ip4:192.0.2.0/24 include:shops.shopify.com ${terms.join(' ')} ~all`];
  return { TXT: txt };
}

describe('an include that authorises nothing', () => {
  it('gets its own finding, with its record, and leads the headroom advice', async () => {
    const r = await check(iscShape());
    expect(r.spf.lookupCount).toBe(9);

    const f = r.report.findings.find((x) => x.id === 'spf-include-authorises-nothing');
    expect(f?.title).toBe('include:shops.shopify.com costs one DNS lookup and authorises no servers');
    expect(f?.severity).toBe('warning');
    expect(f?.detail).toContain('shops.shopify.com publishes "v=spf1 ~all"');
    expect(f?.fix).toMatchObject({ kind: 'record', host: 'example.com' });
    expect(f?.fix?.kind === 'record' && f.fix.value).not.toContain('shops.shopify.com');

    const headroom = r.report.findings.find((x) => x.id === 'spf-lookup-headroom');
    expect(headroom?.fix?.kind === 'action' && headroom.fix.steps[0])
      .toBe('Start with include:shops.shopify.com: it costs a lookup and authorises no servers.');
  });

  it('is only a note when lookups are not scarce', async () => {
    const r = await check({ TXT: { 'example.com': ['v=spf1 include:shops.shopify.com -all'], 'shops.shopify.com': ['v=spf1 ~all'] } });
    expect(r.report.findings.find((x) => x.id === 'spf-include-authorises-nothing')?.severity).toBe('info');
  });

  it('does not show a provider banner on the strength of that include alone', async () => {
    const r = await check(iscShape());
    expect(detectPlatforms(r.mx, r.spf).map((p) => p.name)).toEqual([]);
  });

  it('a record that authorises something is left alone', async () => {
    for (const record of ['v=spf1 ip4:192.0.2.1 ~all', 'v=spf1 include:other.example.net -all', 'v=spf1 a -all', 'v=spf1 redirect=other.example.net', 'v=spf1 +all']) {
      const r = await check({
        TXT: { 'example.com': ['v=spf1 include:vendor.example.net -all'], 'vendor.example.net': [record], 'other.example.net': ['v=spf1 ip4:192.0.2.9 -all'] },
        A: { 'vendor.example.net': ['192.0.2.7'] },
      });
      expect(r.report.findings.some((x) => x.id === 'spf-include-authorises-nothing'), record).toBe(false);
    }
  });

  it('counts a mechanism that only ever fails as authorising nothing', async () => {
    const r = await check({ TXT: { 'example.com': ['v=spf1 include:vendor.example.net -all'], 'vendor.example.net': ['v=spf1 -ip4:192.0.2.1 -all'] } });
    expect(r.report.findings.some((x) => x.id === 'spf-include-authorises-nothing')).toBe(true);
  });
});
