import type { APIRoute } from 'astro';
import { siteEntries, toolsEntries, urlset } from '../lib/sitemap.js';
import { absoluteUrl } from '../lib/site.js';

/**
 * The one sitemap: every indexable URL on notspoofed.com, both applications, merged.
 *
 * It used to be a sitemap *index* pointing at two child sitemaps. That was correct but
 * indirect, and Bing demonstrated the cost: it read one child and never the other, and
 * sat on 19 indexed URLs for weeks. A flat list leaves a crawler nothing to skip.
 *
 * The tools application stays the only authority on its own URLs — they are read from
 * its sitemap over the internal network, not retyped here (see lib/sitemap.ts). If that
 * read has never succeeded since this process started, the response falls back to the
 * index form, which is complete by construction. A half-sitemap is never served.
 */
export const GET: APIRoute = async () => {
  const own = await siteEntries();
  const tools = await toolsEntries();

  if (tools === null) {
    const index =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      `  <sitemap>\n    <loc>${absoluteUrl('/sitemap-site.xml')}</loc>\n  </sitemap>\n` +
      `  <sitemap>\n    <loc>${absoluteUrl('/tools/sitemap.xml')}</loc>\n  </sitemap>\n` +
      `</sitemapindex>\n`;
    return new Response(index, { headers: { 'Content-Type': 'application/xml; charset=utf-8' } });
  }

  // De-duplicated by URL, this app's entry winning, in case a page ever appears in both.
  const seen = new Set(own.map((e) => e.loc));
  const merged = [...own, ...tools.filter((e) => !seen.has(e.loc))];

  return new Response(urlset(merged), {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
