import { describe, expect, it } from 'vitest';
import { botName, campaignSource, trackFields } from '../src/lib/stats.js';

const CRAWLER = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const HUMAN = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';

const base = { path: '/check', selfHost: 'notspoofed.com', referrer: null, clientIp: '198.51.100.7' };

/** What `trafficContext` returns when the origin AS is a known hosting network. */
const HOSTED = { fromDatacenter: true };

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

  it('treats a missing user-agent as a crawler', () => {
    // Every real browser sends one. This is also why `userAgent` is a required field
    // on TrackInput: when it was optional, both check routes omitted it and every web
    // check landed in checks:bot — the same bug, mirrored.
    const f = trackFields({ ...base, userAgent: null, isCheck: true });
    expect(f).toContain('checks:bot');
    expect(f).not.toContain('checks');
  });

  it('separates page views the same way', () => {
    expect(trackFields({ ...base, path: '/', userAgent: CRAWLER })).toContain('bot:googlebot');
    expect(trackFields({ ...base, path: '/', userAgent: HUMAN })).toContain('view:/');
  });
});

describe('datacenter traffic', () => {
  // The case user-agent matching cannot reach: a plausible browser string from a rented
  // machine. This was the majority of the first weeks of "visitors".
  it('keeps a hosted page view out of the view counts', () => {
    const f = trackFields({ ...base, path: '/', userAgent: HUMAN }, HOSTED);
    expect(f).toContain('bot:datacenter');
    expect(f).not.toContain('view:/');
  });

  it('keeps a hosted web check out of the headline number', () => {
    const f = trackFields({ ...base, userAgent: HUMAN, isCheck: true }, HOSTED);
    expect(f).toContain('checks:bot');
    expect(f).not.toContain('checks');
  });

  it('still counts a hosted API call — a script on a server is a real user', () => {
    // The whole point of publishing a JSON API is that other people's software calls it,
    // and that software runs in exactly these networks. Filtering here would zero out
    // the API's own usage figure.
    const f = trackFields({ ...base, userAgent: HUMAN, isCheck: true, viaApi: true }, HOSTED);
    expect(f).toContain('checks');
    expect(f).toContain('api');
    expect(f).not.toContain('checks:bot');
  });

  it('suppresses referrer and source attribution for hosted traffic', () => {
    // The self-referred traffic that inflated the visitor count claimed our own host as
    // its referrer on a first pageview. Whatever it claims, it is not attribution.
    const f = trackFields(
      { ...base, path: '/', userAgent: HUMAN, referrer: 'https://news.ycombinator.com/x', utmSource: 'hn' },
      HOSTED,
    );
    expect(f).not.toContain('ref:news.ycombinator.com');
    expect(f).not.toContain('src:hn');
    expect(f).not.toContain('src:direct');
  });

  it('names the two filters separately so the newer one can be audited', () => {
    // A self-identified crawler that also happens to sit in a datacenter — which is all
    // of them — must still be counted under its own name, or the ASN filter would
    // swallow the indexing signal that says the SEO strategy is working.
    expect(trackFields({ ...base, path: '/', userAgent: CRAWLER }, HOSTED)).toContain('bot:googlebot');
  });

  it('treats an unresolvable origin AS as human', () => {
    // Unknown is unknown. A Cymru outage must stop filtering, not reclassify everyone —
    // the same rule the checker follows for a refused blocklist query.
    const f = trackFields({ ...base, path: '/', userAgent: HUMAN }, { fromDatacenter: false });
    expect(f).toContain('view:/');
    expect(f).not.toContain('bot:datacenter');
  });
});

describe('user-agents that cannot exist', () => {
  const cases: Array<[string, string]> = [
    ['IE 11 on Windows 7', 'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko'],
    ['Chrome 140 on Windows 7', 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36'],
    ['Chrome on Vista', 'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0 Safari/537.36'],
    ['headless Chrome', 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0 Safari/537.36'],
  ];

  for (const [name, ua] of cases) {
    it(`flags ${name}`, () => {
      expect(botName(ua)).toBe('impossible-agent');
    });
  }

  it('does not flag genuinely old but possible browsers', () => {
    // Someone on a Windows 7 machine running the last Chrome that supported it is a real
    // person. Version-independent patterns only, so nobody's old laptop gets libelled.
    expect(botName('Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0 Safari/537.36')).toBeNull();
    expect(botName(HUMAN)).toBeNull();
    expect(botName('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15')).toBeNull();
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
