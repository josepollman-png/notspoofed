import { describe, expect, it } from 'vitest';
import { countSpfLookups, parseDraft, statusFor, type CounterNode } from '../src/lib/spf/counter.js';
import { evaluateSpf } from '../src/lib/spf/evaluate.js';
import { FakeDns } from './fake-dns.js';

const all = (nodes: CounterNode[]): CounterNode[] => nodes.flatMap((n) => [n, ...all(n.children)]);

/** n includes at the apex, each costing one lookup and carrying one address. */
function wide(n: number, apexExtra = ''): Record<string, string[]> {
  const txt: Record<string, string[]> = {
    'e.com': [`v=spf1 ${Array.from({ length: n }, (_, i) => `include:s${i}.p.com`).join(' ')}${apexExtra} -all`],
  };
  for (let i = 0; i < n; i++) txt[`s${i}.p.com`] = [`v=spf1 ip4:10.0.${i}.0/24 -all`];
  return txt;
}

describe('SPF lookup counter', () => {
  it('counts a simple record', async () => {
    const dns = new FakeDns({
      TXT: {
        'e.com': ['v=spf1 include:_spf.a.com ip4:192.0.2.1 -all'],
        '_spf.a.com': ['v=spf1 ip4:198.51.100.0/24 -all'],
      },
    });
    const r = await countSpfLookups({ domain: 'e.com', dns });
    expect(r.lookupCount).toBe(1);
    expect(r.status).toBe('PASS');
    expect(r.summary).toBe('1 of 10 DNS lookups used');
    expect(r.root.nodes).toHaveLength(1);
    expect(r.root.nodes[0]).toMatchObject({ mechanism: 'include:_spf.a.com', target: '_spf.a.com', lookupsAfter: 1, totalCost: 1 });
    expect(r.root.freeTerms).toBe(2); // ip4 and -all
    expect(r.flags).toEqual([]);
    expect(r.fixes?.record).toBeNull();
    expect(r.explanation.length).toBeGreaterThanOrEqual(2);
    expect(r.explanation.length).toBeLessThanOrEqual(4);
  });

  it('shows nested includes with running totals in evaluation order', async () => {
    const dns = new FakeDns({
      TXT: {
        'e.com': ['v=spf1 include:x.com mx -all'],
        'x.com': ['v=spf1 include:y.com include:z.com -all'],
        'y.com': ['v=spf1 ip4:192.0.2.0/24 -all'],
        'z.com': ['v=spf1 a:host.z.com -all'],
      },
      MX: { 'e.com': [{ exchange: 'mx.e.com', priority: 10 }] },
      A: { 'host.z.com': ['192.0.2.9'], 'mx.e.com': ['192.0.2.10'] },
    });
    const r = await countSpfLookups({ domain: 'e.com', dns });
    expect(r.lookupCount).toBe(5);
    const [x, mx] = r.root.nodes;
    expect(x).toMatchObject({ mechanism: 'include:x.com', totalCost: 4, lookupsAfter: 1 });
    expect(x!.children.map((c) => [c.mechanism, c.lookupsAfter])).toEqual([['include:y.com', 2], ['include:z.com', 3]]);
    expect(x!.children[1]!.children[0]).toMatchObject({ mechanism: 'a:host.z.com', lookupsAfter: 4 });
    expect(mx).toMatchObject({ mechanism: 'mx', target: 'e.com', lookupsAfter: 5 });
  });

  it('follows redirect= and takes its all', async () => {
    const dns = new FakeDns({
      TXT: {
        'e.com': ['v=spf1 redirect=_spf.e.com'],
        '_spf.e.com': ['v=spf1 include:a.com -all'],
        'a.com': ['v=spf1 ip4:192.0.2.0/24 -all'],
      },
    });
    const r = await countSpfLookups({ domain: 'e.com', dns });
    expect(r.lookupCount).toBe(2);
    expect(r.root.nodes[0]).toMatchObject({ name: 'redirect', target: '_spf.e.com', totalCost: 2 });
    // The redirect target's -all is the policy, so no "missing all" complaint.
    expect(r.flags.map((f) => f.code)).not.toContain('no-all');
  });

  it('stops at an include loop and reports it', async () => {
    const dns = new FakeDns({
      TXT: {
        'a.com': ['v=spf1 include:b.com -all'],
        'b.com': ['v=spf1 include:a.com -all'],
      },
    });
    const r = await countSpfLookups({ domain: 'a.com', dns });
    expect(r.flags.map((f) => f.code)).toContain('loop');
    expect(r.otherPermErrors).toContain('an include loop');
    const loop = all(r.root.nodes).find((n) => n.note === 'loop detected');
    expect(loop?.mechanism).toBe('include:a.com');
  });

  it('marks where the count crosses 10, keeps walking, and flattens only what it must', async () => {
    const dns = new FakeDns({ TXT: wide(12) });
    const r = await countSpfLookups({ domain: 'e.com', dns });
    expect(r.lookupCount).toBe(12);
    expect(r.status).toBe('PERMERROR');
    expect(r.summary).toBe('12 of 10 DNS lookups used');

    const crossing = r.root.nodes.filter((n) => n.crossesLimit);
    expect(crossing.map((n) => n.mechanism)).toEqual(['include:s10.p.com']);
    expect(r.root.nodes.filter((n) => n.overLimit)).toHaveLength(2);
    // Past the limit the tree is still followed — the checker stops, the counter must not.
    expect(r.root.nodes.every((n) => n.record !== null)).toBe(true);

    const f = r.fixes!;
    expect(f.redundant).toEqual([]);
    expect(f.flatten?.flattened).toHaveLength(2);
    expect(f.flatten?.lookupsAfter).toBe(10);
    expect(f.recordLookups).toBe(10);
    expect(f.record).toMatch(/^v=spf1 /);
    expect(f.flatten?.warnings.join(' ')).toMatch(/snapshot/i);
    expect(r.explanation[1]).toMatch(/PermError/);
  });

  it('attributes void lookups and marks the third', async () => {
    const dns = new FakeDns({
      TXT: {
        'e.com': ['v=spf1 include:gone1.com include:gone2.com a:gone3.com ip4:192.0.2.1 -all'],
      },
    });
    const r = await countSpfLookups({ domain: 'e.com', dns });
    expect(r.voidCount).toBe(3);
    expect(r.root.nodes.map((n) => [n.voids, n.voidsAfter])).toEqual([[1, 1], [1, 2], [1, 3]]);
    expect(r.root.nodes.map((n) => n.crossesVoidLimit)).toEqual([false, false, true]);
    expect(r.flags.map((f) => f.code)).toContain('void-limit');
    expect(r.otherPermErrors.join(' ')).toMatch(/3 void lookups/);
    // Unresolvable includes must never be flattened: their addresses are unknown.
    expect(r.status).toBe('PASS');
  });

  it('flags two SPF records', async () => {
    const dns = new FakeDns({
      TXT: { 'e.com': ['v=spf1 ip4:192.0.2.1 -all', 'v=spf1 include:a.com ~all'] },
    });
    const r = await countSpfLookups({ domain: 'e.com', dns });
    expect(r.flags[0]).toMatchObject({ code: 'multiple-records', severity: 'error' });
    expect(r.otherPermErrors).toContain('more than one SPF record is published');
  });

  it('calls 9 and 10 a warning, 11 a PermError', () => {
    expect([8, 9, 10, 11].map(statusFor)).toEqual(['PASS', 'WARNING', 'WARNING', 'PERMERROR']);
  });

  it('removes a top-level include that another include already pulls in, before flattening anything', async () => {
    const txt = wide(10, ' include:_spf.google.com');
    txt['s0.p.com'] = ['v=spf1 include:_spf.google.com -all'];
    txt['_spf.google.com'] = ['v=spf1 include:_netblocks.google.com -all'];
    txt['_netblocks.google.com'] = ['v=spf1 ip4:172.217.0.0/19 -all'];
    const r = await countSpfLookups({ domain: 'e.com', dns: new FakeDns({ TXT: txt }) });
    // 10 providers + google nested twice (2 each) + the apex google include (2) = 14
    expect(r.lookupCount).toBe(14);
    expect(r.flags.map((f) => f.code)).toContain('duplicate-include');
    expect(r.fixes!.redundant).toEqual([
      { mechanism: 'include:_spf.google.com', alsoVia: 'include:s0.p.com', saves: 2 },
    ]);
    expect(r.fixes!.lookupsAfterRedundant).toBe(12);
    expect(r.fixes!.flatten?.lookupsAfter).toBeLessThanOrEqual(10);
    expect(r.fixes!.record).not.toContain('include:_spf.google.com');
  });

  it('suggests only the redundancy fix when that alone is enough', async () => {
    const txt = wide(8, ' include:_spf.google.com');
    txt['s0.p.com'] = ['v=spf1 include:_spf.google.com -all'];
    txt['_spf.google.com'] = ['v=spf1 include:_netblocks.google.com -all'];
    txt['_netblocks.google.com'] = ['v=spf1 ip4:172.217.0.0/19 -all'];
    const r = await countSpfLookups({ domain: 'e.com', dns: new FakeDns({ TXT: txt }) });
    expect(r.lookupCount).toBe(12);
    expect(r.fixes!.flatten).toBeNull();
    expect(r.fixes!.recordLookups).toBe(10);
    expect(r.fixes!.record).toBe(
      `v=spf1 ${Array.from({ length: 8 }, (_, i) => `include:s${i}.p.com`).join(' ')} -all`,
    );
  });

  it('flags ptr, +all and ?all', async () => {
    const dns = new FakeDns({ TXT: { 'e.com': ['v=spf1 ptr +all'], 'f.com': ['v=spf1 ip4:192.0.2.1 ?all'] } });
    const e = await countSpfLookups({ domain: 'e.com', dns });
    expect(e.flags.map((f) => f.code)).toEqual(expect.arrayContaining(['ptr', 'permissive-all']));
    const f = await countSpfLookups({ domain: 'f.com', dns });
    expect(f.flags).toEqual([expect.objectContaining({ code: 'permissive-all', severity: 'warning' })]);
  });

  it('tests a pasted draft, resolving its includes live but not the apex', async () => {
    const dns = new FakeDns({ TXT: { 'a.com': ['v=spf1 ip4:192.0.2.0/24 -all'] } });
    const r = await countSpfLookups({ record: 'v=spf1 include:a.com mx ~all', dns });
    expect(r.source).toBe('pasted');
    expect(r.lookupCount).toBe(2);
    expect(dns.log).toEqual(['TXT a.com']);
    expect(r.root.nodes[1]).toMatchObject({ mechanism: 'mx', note: 'needs the domain the record is for' });
  });

  it('reads quoted strings, joins them without spaces, and flags one over 255 bytes', () => {
    const d = parseDraft('"v=spf1 ip4:192.0.2.1" " include:a.com -all"');
    expect(d.record).toBe('v=spf1 ip4:192.0.2.1 include:a.com -all');
    expect(d.strings).toHaveLength(2);
    expect(() => parseDraft('include:a.com -all')).toThrow(/v=spf1/);
  });

  it('flags a string over 255 bytes and a record over 512', async () => {
    const ips = Array.from({ length: 40 }, (_, i) => `ip4:198.51.100.${i}`).join(' ');
    const r = await countSpfLookups({ record: `v=spf1 ${ips} -all`, dns: new FakeDns({}) });
    const codes = r.flags.map((f) => f.code);
    expect(codes).toContain('string-too-long');
    expect(codes).toContain('record-too-large');
  });

  it('leaves the checker exactly as it was: it still stops following at the limit', async () => {
    const r = await evaluateSpf(new FakeDns({ TXT: wide(12) }), 'e.com');
    expect(r.lookupCount).toBe(12);
    expect(r.tree!.children.filter((c) => c.skipped === 'beyond the 10-lookup limit')).toHaveLength(2);
  });
});
