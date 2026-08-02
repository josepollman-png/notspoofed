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
export const INDEXABLE_PAGES = [
  { path: '/', changefreq: 'weekly', priority: '1.0' },
  { path: '/headers', changefreq: 'monthly', priority: '0.9' },
  { path: '/ip', changefreq: 'monthly', priority: '0.9' },
  { path: '/guides', changefreq: 'weekly', priority: '0.9' },
  { path: '/api', changefreq: 'monthly', priority: '0.7' },
  { path: '/about', changefreq: 'monthly', priority: '0.6' },
] as const;
