import { describe, expect, it } from 'vitest';
import { isSpfRecord, parseSpf } from '../src/lib/spf/parse.js';

const costly = (r: ReturnType<typeof parseSpf>) => r.terms.filter((t) => t.costsLookup);

describe('record detection', () => {
  it('accepts the version token case-insensitively', () => {
    expect(isSpfRecord('v=spf1 -all')).toBe(true);
    expect(isSpfRecord('V=SPF1 -all')).toBe(true);
    expect(isSpfRecord('v=spf1')).toBe(true);
  });

  it('rejects near-misses rather than half-parsing them', () => {
    expect(isSpfRecord('v=spf10 -all')).toBe(false);
    expect(isSpfRecord('spf2.0/pra include:x.com -all')).toBe(false);
    expect(isSpfRecord('v=DKIM1; p=abc')).toBe(false);
  });
});

describe('redirect= modifier', () => {
  // The regression that motivated this file. A ':'-only tokenizer reports zero
  // costly terms here, which reads as a clean bill of health for a domain whose
  // entire policy lives behind the redirect.
  it('is recognised and counted as a lookup', () => {
    const r = parseSpf('v=spf1 redirect=_hspf.hubspot.com');
    expect(r.errors).toEqual([]);
    expect(costly(r)).toHaveLength(1);
    expect(costly(r)[0]).toMatchObject({
      kind: 'modifier',
      name: 'redirect',
      value: '_hspf.hubspot.com',
      costsLookup: true,
    });
  });

  it('does not confuse exp= (a DNS lookup that is exempt from the count)', () => {
    const r = parseSpf('v=spf1 exp=why.example.com -all');
    expect(costly(r)).toHaveLength(0);
    expect(r.terms.find((t) => t.name === 'exp')?.kind).toBe('modifier');
  });

  it('ignores unknown modifiers instead of erroring (RFC 7208 §6)', () => {
    const r = parseSpf('v=spf1 moo=cow -all');
    expect(r.errors).toEqual([]);
    expect(r.terms.find((t) => t.name === 'moo')?.kind).toBe('unknown');
  });
});

describe('mechanism forms', () => {
  it('counts only the terms that cost a DNS lookup', () => {
    const r = parseSpf(
      'v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 include:a.com a mx exists:e.com ptr -all',
    );
    // include, a, mx, exists, ptr = 5. ip4, ip6, all are free.
    expect(costly(r).map((t) => t.name)).toEqual(['include', 'a', 'mx', 'exists', 'ptr']);
  });

  it('parses bare a/mx as referring to the current domain', () => {
    const r = parseSpf('v=spf1 a mx -all');
    expect(r.terms[0]).toMatchObject({ name: 'a', value: undefined });
    expect(r.terms[1]).toMatchObject({ name: 'mx', value: undefined });
  });

  it('splits dual-cidr from the hostname', () => {
    expect(parseSpf('v=spf1 a:mail.example.com/24//64 -all').terms[0]).toMatchObject({
      name: 'a', value: 'mail.example.com', cidr4: 24, cidr6: 64,
    });
    expect(parseSpf('v=spf1 a/24 -all').terms[0]).toMatchObject({
      name: 'a', value: undefined, cidr4: 24,
    });
    expect(parseSpf('v=spf1 mx//64 -all').terms[0]).toMatchObject({
      name: 'mx', value: undefined, cidr6: 64,
    });
  });

  it('keeps ip6 colons intact', () => {
    expect(parseSpf('v=spf1 ip6:2001:4860:4864::/56 -all').terms[0]).toMatchObject({
      name: 'ip6', value: '2001:4860:4864::/56',
    });
  });

  it('captures qualifiers, defaulting to +', () => {
    const r = parseSpf('v=spf1 -all');
    expect(r.terms[0]!.qualifier).toBe('-');
    expect(parseSpf('v=spf1 all').terms[0]!.qualifier).toBe('+');
    expect(parseSpf('v=spf1 ~all').terms[0]!.qualifier).toBe('~');
    expect(parseSpf('v=spf1 ?include:x.com ~all').terms[0]!.qualifier).toBe('?');
  });
});

describe('macros', () => {
  it('flags a macro target as unresolvable but still chargeable', () => {
    // Live example from salesforce.com.
    const r = parseSpf('v=spf1 exists:%{i}._spf.corp.salesforce.com ~all');
    expect(r.terms[0]).toMatchObject({ name: 'exists', hasMacro: true, costsLookup: true });
  });

  it('does not flag ordinary percent-free targets', () => {
    expect(parseSpf('v=spf1 include:_spf.google.com ~all').terms[0]!.hasMacro).toBe(false);
  });
});

describe('authoring mistakes worth reporting', () => {
  it('reports terms stranded after all', () => {
    const r = parseSpf('v=spf1 -all include:late.example.com');
    expect(r.errors.join(' ')).toMatch(/never evaluated/);
  });

  it('does not treat a trailing exp= as stranded', () => {
    expect(parseSpf('v=spf1 -all exp=why.example.com').errors).toEqual([]);
  });

  it('reports include with no domain', () => {
    expect(parseSpf('v=spf1 include: -all').errors.join(' ')).toMatch(/requires a domain/);
  });

  it('tolerates irregular whitespace', () => {
    const r = parseSpf('  v=spf1   ip4:1.2.3.4    -all  ');
    expect(r.errors).toEqual([]);
    expect(r.terms).toHaveLength(2);
  });
});
