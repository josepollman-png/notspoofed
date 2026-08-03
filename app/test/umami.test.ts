import { describe, expect, it } from 'vitest';
import { campaignQuery } from '../src/lib/umami.js';

const q = (search: string) => campaignQuery(new URLSearchParams(search));

describe('campaign query passthrough', () => {
  it('forwards the five utm parameters', () => {
    expect(q('utm_source=reddit&utm_medium=social&utm_campaign=launch'))
      .toBe('?utm_source=reddit&utm_medium=social&utm_campaign=launch');
    expect(q('utm_term=dmarc&utm_content=sidebar')).toBe('?utm_term=dmarc&utm_content=sidebar');
  });

  it('emits a stable order regardless of the order they arrived in', () => {
    // Two identical visits must produce one url_query, or Umami reports them as two
    // separate campaign rows.
    expect(q('utm_campaign=launch&utm_source=hn')).toBe(q('utm_source=hn&utm_campaign=launch'));
  });

  it('forwards nothing else, whatever it is called', () => {
    // The load-bearing one. /check carries the looked-up domain in its query string, and
    // the site promises that is never recorded. An allow-list cannot forget a parameter;
    // a deny-list can.
    expect(q('domain=example.com')).toBe('');
    expect(q('selectors=s1,s2')).toBe('');
    expect(q('email=someone@example.com&token=abc')).toBe('');
    expect(q('domain=example.com&utm_source=reddit')).toBe('?utm_source=reddit');
  });

  it('returns an empty string when there is nothing to report', () => {
    expect(q('')).toBe('');
    expect(q('utm_source=')).toBe('');
    expect(q('utm_source=%20%20')).toBe('');
  });

  it('drops a malformed value whole rather than scrubbing it into something plausible', () => {
    expect(q('utm_source=<script>alert(1)</script>')).toBe('');
    expect(q('utm_campaign=a'.padEnd(90, 'a'))).toBe('');
    expect(q('utm_source=bad%00value')).toBe('');
    // A bad value must not take a good one down with it.
    expect(q('utm_source=reddit&utm_campaign=<bad>')).toBe('?utm_source=reddit');
  });

  it('accepts the punctuation real campaign tags use', () => {
    expect(q('utm_campaign=summer sale')).toBe('?utm_campaign=summer+sale');
    expect(q('utm_campaign=v1.2_launch-b')).toBe('?utm_campaign=v1.2_launch-b');
  });
});
