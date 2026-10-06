import { describe, expect, it } from 'vitest';
import { detectPlatforms } from '../src/lib/platform.js';
import { evaluateSpf } from '../src/lib/spf/evaluate.js';
import { FakeDns } from './fake-dns.js';

const spfFor = (record: string, extra: Record<string, string[]> = {}) =>
  evaluateSpf(new FakeDns({ TXT: { 'example.com': [record], ...extra } }), 'example.com');

const names = async (mx: string[], record: string, extra: Record<string, string[]> = {}) =>
  detectPlatforms(mx.map((exchange) => ({ exchange, priority: 10 })), await spfFor(record, extra))
    .map((p) => p.name);

describe('platform guide detection', () => {
  it('spots Google Workspace by MX or by its SPF include', async () => {
    expect(await names(['aspmx.l.google.com.'], 'v=spf1 -all')).toEqual(['Google Workspace']);
    expect(await names([], 'v=spf1 include:_spf.google.com ~all', { '_spf.google.com': ['v=spf1 ip4:192.0.2.0/24 ~all'] }))
      .toEqual(['Google Workspace']);
  });

  it('spots Microsoft 365 by MX or by its SPF include', async () => {
    expect(await names(['example-com.mail.protection.outlook.com'], 'v=spf1 -all')).toEqual(['Microsoft 365']);
    expect(await names([], 'v=spf1 include:spf.protection.outlook.com -all', { 'spf.protection.outlook.com': ['v=spf1 -all'] }))
      .toEqual(['Microsoft 365']);
  });

  it('spots Shopify alongside the mail provider', async () => {
    expect(await names(['aspmx.l.google.com'], 'v=spf1 include:shops.shopify.com ~all', { 'shops.shopify.com': ['v=spf1 -all'] }))
      .toEqual(['Google Workspace', 'Shopify']);
  });

  it('matches whole labels only, and says nothing when nothing matches', async () => {
    expect(await names(['mx.notgoogle.com', 'mail.example.com'], 'v=spf1 mx -all')).toEqual([]);
  });
});
