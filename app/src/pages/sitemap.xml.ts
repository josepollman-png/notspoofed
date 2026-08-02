import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { absoluteUrl, INDEXABLE_PAGES } from '../lib/site.js';

/**
 * Hand-rolled rather than @astrojs/sitemap, because that integration enumerates every
 * route at build time and would happily list /check and /api/check — the two routes
 * that must never be crawled. Listing only what we want indexed is the safer default.
 */
export const GET: APIRoute = async () => {
  const today = new Date().toISOString().slice(0, 10);

  const entries = [
    ...INDEXABLE_PAGES.map((p) => ({
      loc: absoluteUrl(p.path),
      lastmod: today,
      changefreq: p.changefreq as string,
      priority: p.priority as string,
    })),
    ...(await getCollection('guides')).map((guide) => ({
      loc: absoluteUrl(`/guides/${guide.id}/`),
      // The guide's own updated date, not today's — claiming everything changed
      // daily is exactly the signal that gets a sitemap's dates ignored.
      lastmod: guide.data.updated.toISOString().slice(0, 10),
      changefreq: 'monthly',
      priority: '0.8',
    })),
  ];

  const urls = entries
    .map(
      (e) =>
        `  <url>\n` +
        `    <loc>${e.loc}</loc>\n` +
        `    <lastmod>${e.lastmod}</lastmod>\n` +
        `    <changefreq>${e.changefreq}</changefreq>\n` +
        `    <priority>${e.priority}</priority>\n` +
        `  </url>`,
    )
    .join('\n');

  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`,
    { headers: { 'Content-Type': 'application/xml; charset=utf-8' } },
  );
};
