import type { APIRoute } from 'astro';
import { absoluteUrl } from '../lib/site.js';

/**
 * `/check` is disallowed, and that is the whole point of this file.
 *
 * Result pages take a domain from the query string, so the URL space is unbounded —
 * a crawler can generate them forever. Each one costs ~48 outbound DNS queries, and
 * the per-IP rate limiter starts returning 429 to the crawler, which search engines
 * read as an unhealthy site and respond to by crawling *less*. Left alone this
 * actively suppresses the pages we do want ranked.
 *
 * Disallowing here stops the crawl before the cost is incurred. Because a disallowed
 * URL can still be indexed without content if something links to it, /check also
 * sends `X-Robots-Tag: noindex` — that covers crawlers which ignore this file.
 */
export const GET: APIRoute = () =>
  new Response(
    [
      'User-agent: *',
      'Disallow: /check',
      // Same reasoning as /check — the JSON endpoint is the same unbounded, expensive
      // work with a different Content-Type. /api (the docs page) stays crawlable.
      'Disallow: /api/check',
      // Prefix match on the query string only: /ip?ip=… is an unbounded result space,
      // while bare /ip is a landing page we want indexed.
      'Disallow: /ip?',
      // Saved results from the tools app. Same reasoning as /check — unbounded URL
      // space, every entry a one-off — and they already send noindex via X-Robots-Tag
      // for the crawlers that ignore this file.
      'Disallow: /result/',
      'Allow: /',
      '',
      // A sitemap index. It references this app's own /sitemap-site.xml and the tools
      // application's /tools/sitemap.xml, so one entry covers both halves of the
      // hostname — and anything added later.
      `Sitemap: ${absoluteUrl('/sitemap.xml')}`,
      '',
    ].join('\n'),
    { headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
  );
