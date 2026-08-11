import type { APIRoute } from 'astro';
import { absoluteUrl } from '../lib/site.js';

/**
 * A sitemap index, not a list of pages.
 *
 * `notspoofed.com` is served by two applications: this one, and the tools app under
 * /tools. Each knows its own routes and neither can enumerate the other's, so there are
 * two sitemaps. Left as two flat files advertised only in robots.txt, submitting
 * "the sitemap" in Search Console covered half the site and silently missed the rest —
 * which is exactly what happened: the tools section's 47 URLs were absent from the one
 * sitemap anybody would think to submit.
 *
 * An index solves it properly. Submit /sitemap.xml and both are discovered, now and
 * whenever a third is added.
 */
export const GET: APIRoute = () => {
  const sitemaps = [
    absoluteUrl('/sitemap-site.xml'),
    // Owned by the tools application. Proxied by Caddy, so it is same-origin and a
    // valid entry here — a sitemap index may only reference its own host.
    absoluteUrl('/tools/sitemap.xml'),
  ];

  const today = new Date().toISOString().slice(0, 10);
  const body =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    sitemaps
      .map((loc) => `  <sitemap>\n    <loc>${loc}</loc>\n    <lastmod>${today}</lastmod>\n  </sitemap>`)
      .join('\n') +
    `\n</sitemapindex>\n`;

  return new Response(body, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
