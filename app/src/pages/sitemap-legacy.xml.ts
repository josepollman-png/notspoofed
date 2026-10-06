import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { absoluteUrl } from '../lib/site.js';
import { urlset } from '../lib/sitemap.js';

/**
 * TEMPORARY: remove after 2026-11-06 once the old /guides/ URLs drop out of the index.
 *
 * Every guide that existed before the move from `/guides/<slug>/` to `/guide/<slug>` on
 * 2026-09-08, at its old address. Each answers a single 301 to its new home (see
 * `pages/guides/[...slug].astro`), but Google had not re-crawled the old URLs a month
 * later, so it had not seen the redirects either. Listing them with a fresh lastmod asks
 * it to come back and follow them.
 *
 * The list comes from the same place the redirects do — the guides collection — limited
 * to guides published before the move, since a guide written after it never had an old
 * URL. Kept out of /sitemap.xml: a sitemap of canonical pages must not list redirects.
 *
 * When this goes, take the `Sitemap:` line for it out of robots.txt too.
 */
const MOVED_ON = new Date('2026-09-08T00:00:00Z');
/** The day this sitemap was published — a fixed date, not "now", so it does not churn. */
const LASTMOD = '2026-10-06';

export const GET: APIRoute = async () => {
  const guides = (await getCollection('guides'))
    .filter((g) => g.data.published < MOVED_ON)
    .sort((a, b) => a.id.localeCompare(b.id));

  return new Response(
    urlset(guides.map((g) => ({ loc: absoluteUrl(`/guides/${g.id}/`), lastmod: LASTMOD }))),
    { headers: { 'Content-Type': 'application/xml; charset=utf-8' } },
  );
};
