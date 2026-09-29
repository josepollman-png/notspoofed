import type { APIRoute } from 'astro';
import { siteEntries, urlset } from '../lib/sitemap.js';

/**
 * This application's pages only.
 *
 * `/sitemap.xml` is the entry point and already includes everything here. This file
 * stays valid because it is registered in Search Console and Bing Webmaster Tools, and
 * a submitted sitemap that starts returning 404 or redirecting is reported as an error
 * there. Listing a URL in two sitemaps is harmless; losing a submitted one is noise.
 *
 * Hand-rolled rather than @astrojs/sitemap, which would enumerate /check and
 * /api/check — the two routes that must never be crawled.
 */
export const GET: APIRoute = async () =>
  new Response(urlset(await siteEntries()), {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
