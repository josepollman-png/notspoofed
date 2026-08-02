import { describe, expect, it } from 'vitest';
import { campaignSource } from '../src/lib/stats.js';

describe('campaign source attribution', () => {
  it('recognises known channels', () => {
    expect(campaignSource('reddit')).toBe('reddit');
    expect(campaignSource('HN')).toBe('hn');
    expect(campaignSource('  Mastodon  ')).toBe('mastodon');
  });

  it('buckets unrecognised but well-formed values rather than dropping them', () => {
    // A typo in a posted link should still show up as traffic. Silently discarding it
    // is how a campaign looks dead when it is merely mislabelled.
    expect(campaignSource('reddt')).toBe('other');
    expect(campaignSource('some-newsletter')).toBe('other');
  });

  it('rejects anything that could bloat or poison the day hash', () => {
    // The value becomes a Redis hash field, so an open bucket lets a crafted URL
    // append arbitrary fields.
    expect(campaignSource('a'.repeat(50))).toBeNull();
    expect(campaignSource('bad value')).toBeNull();
    expect(campaignSource('ref:injected')).toBeNull();
    expect(campaignSource('-leading-dash')).toBeNull();
    expect(campaignSource('')).toBeNull();
    expect(campaignSource(null)).toBeNull();
  });
});
