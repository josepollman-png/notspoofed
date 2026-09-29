import { describe, expect, it } from 'vitest';
import { countSpfLookups } from '../src/lib/spf/counter.js';

/**
 * The lookup counter against the homepage's own example domains. Live DNS, so opt-in
 * (LIVE_DNS=1): these prove the counter agrees with the checker on real records, and
 * that lyft.com — the homepage's "over the lookup limit" example — still is.
 */
describe('SPF lookup counter, live', () => {
  it('shows lyft.com over the limit, with the crossing marked and a fix that gets under it', async () => {
    const r = await countSpfLookups({ domain: 'lyft.com' });
    expect(r.lookupCount).toBeGreaterThan(10);
    expect(r.status).toBe('PERMERROR');
    const flat = (ns: typeof r.root.nodes): typeof r.root.nodes => ns.flatMap((n) => [n, ...flat(n.children)]);
    expect(flat(r.root.nodes).filter((n) => n.crossesLimit)).toHaveLength(1);
    expect(r.fixes?.recordLookups).toBeLessThanOrEqual(10);
  }, 30_000);

  it('passes paypal.com', async () => {
    const r = await countSpfLookups({ domain: 'paypal.com' });
    expect(r.found).toBe(true);
    expect(r.lookupCount).toBeLessThanOrEqual(10);
  }, 30_000);

  it('reads example.com as a domain that sends no mail', async () => {
    const r = await countSpfLookups({ domain: 'example.com' });
    expect(r.lookupCount).toBe(0);
    expect(r.status).toBe('PASS');
  }, 30_000);
});
