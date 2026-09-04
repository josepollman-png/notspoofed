/**
 * The site's public origin, resolved at *runtime*.
 *
 * Astro bakes `site` from astro.config into the bundle at build time, but the image is
 * built without PUBLIC_SITE_URL — it arrives from compose when the container starts.
 * Reading the baked value would emit canonical and og:url tags pointing at
 * http://localhost:3000 in production, which is worse than emitting none.
 */

const FALLBACK = 'http://localhost:3000';

export function siteOrigin(): string {
  const raw = process.env.PUBLIC_SITE_URL?.trim();
  if (!raw) return FALLBACK;
  try {
    return new URL(raw).origin;
  } catch {
    return FALLBACK;
  }
}

export function absoluteUrl(path: string): string {
  return new URL(path, `${siteOrigin()}/`).href;
}

/**
 * Static pages worth indexing. Guides are appended from the content collection.
 * `/check` and `/api/check` are deliberately absent — see robots.txt.ts.
 */
/**
 * `lastmod` is the date the page's content last changed, maintained by hand. It used to
 * be "today" on every request, which told crawlers that every static page changed daily;
 * that is exactly the signal that gets a sitemap's dates ignored altogether. Pages that
 * list the collection (`/`, `/guides`) take the newest entry date instead — see the
 * sitemap route.
 */
export const INDEXABLE_PAGES = [
  { path: '/', changefreq: 'weekly', priority: '1.0', lastmod: 'collection' },
  { path: '/headers', changefreq: 'monthly', priority: '0.9', lastmod: '2026-08-03' },
  { path: '/ip', changefreq: 'monthly', priority: '0.9', lastmod: '2026-08-03' },
  { path: '/guides', changefreq: 'weekly', priority: '0.9', lastmod: 'collection' },
  // Original research. Listed here rather than coming from the collection because the
  // study is a hand-ported HTML document, not a markdown entry — the dataset page and the
  // derivatives are added by the sitemap route straight from the collection.
  { path: '/research/yc-email-spoofing-study', changefreq: 'monthly', priority: '1.0', lastmod: '2026-09-03' },
  { path: '/api', changefreq: 'monthly', priority: '0.7', lastmod: '2026-08-03' },
  { path: '/about', changefreq: 'monthly', priority: '0.6', lastmod: '2026-09-04' },
] as const;
