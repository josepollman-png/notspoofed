import { describe, expect, it } from 'vitest';
import { campaignSource, trackFields } from '../src/lib/stats.js';

const CRAWLER = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const HUMAN = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';

const base = { path: '/check', selfHost: 'notspoofed.com', referrer: null };

describe('check counting: bot vs human', () => {
  it('counts a human web check', () => {
    const f = trackFields({ ...base, userAgent: HUMAN, isCheck: true });
    expect(f).toContain('checks');
    expect(f).not.toContain('checks:bot');
  });

  it('keeps a crawler web check out of the headline number', () => {
    // The landing page form is a GET, so anything that submits forms produces a valid
    // /check?domain=… . Counting those as checks made the funnel metric meaningless.
    const f = trackFields({ ...base, userAgent: CRAWLER, isCheck: true });
    expect(f).toContain('checks:bot');
    expect(f).not.toContain('checks');
  });

  it('still counts an automated JSON API call as a real check', () => {
    // A script calling the API is a user, not a crawler. Filtering by user-agent here
    // would zero out the API's own usage figure.
    const f = trackFields({ ...base, userAgent: CRAWLER, isCheck: true, viaApi: true });
    expect(f).toContain('checks');
    expect(f).toContain('api');
    expect(f).not.toContain('checks:bot');
  });

  it('does not credit a crawler with a guide conversion', () => {
    const referrer = 'https://notspoofed.com/guides/spf-too-many-dns-lookups/';
    expect(trackFields({ ...base, referrer, userAgent: HUMAN, isCheck: true }))
      .toContain('conv:guide');
    expect(trackFields({ ...base, referrer, userAgent: CRAWLER, isCheck: true }))
      .not.toContain('conv:guide');
  });

  it('separates page views the same way', () => {
    expect(trackFields({ ...base, path: '/', userAgent: CRAWLER })).toContain('bot:googlebot');
    expect(trackFields({ ...base, path: '/', userAgent: HUMAN })).toContain('view:/');
  });
});

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
