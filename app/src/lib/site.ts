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
/**
 * Guides that live in the tools application, linked from this one.
 *
 * `notspoofed.com` is two applications, and this half cannot enumerate the other half's
 * routes — so the pages worth linking are named here, once, and shared by the home page
 * and the guides hub. A wrong slug is a 404 no build can catch, which is why
 * `scripts/check-links.mjs` fetches every one of them.
 *
 * The six bounce guides are the ones Search Console shows between positions 10 and 32:
 * close enough that internal links can move them. The rest of the set is one click on
 * from the decoder.
 */
export const BOUNCE_GUIDES = [
  { href: '/guide/bounce/microsoft-5-7-606-banned-sending-ip', title: 'Microsoft 5.7.606 — your sending IP is blocked' },
  { href: '/guide/bounce/mimecast-rejected', title: 'Mimecast rejected your message' },
  { href: '/guide/bounce/outlook-s3150-block-list', title: 'Outlook S3150 — blocked by reputation' },
  { href: '/guide/bounce/microsoft-5-7-23-spf-violation', title: 'Microsoft 5.7.23 — SPF validation failed' },
  { href: '/guide/bounce/5-1-2-domain-not-found', title: '5.1.2 — the recipient domain does not resolve' },
  { href: '/guide/bounce/550-5-1-1-user-unknown', title: '550 5.1.1 — no such user' },
] as const;

/**
 * The other application's guide collections, as hubs rather than 40 hardcoded links.
 *
 * The guides hub listed this app's 17 markdown guides and none of the other 40, so two
 * thirds of the site's guides were reachable only from /tools. Linking each one here
 * would be 40 slugs to keep correct; linking the indexes that already list them in full
 * is one link each and cannot rot.
 */
export const GUIDE_COLLECTIONS = [
  {
    href: '/tools/bounce-decoder',
    title: 'Bounce guides',
    description: 'Twenty-one guides, one per SMTP error worth its own page: what it means, whose problem it is, and the fix. Paste a bounce and it finds the right one.',
  },
  {
    href: '/tools/tls-rpt-analyzer',
    title: 'TLS-RPT result guides',
    description: 'Every failure type RFC 8460 defines, explained one page at a time — and whether it means inbound mail was refused or merely sent unencrypted.',
  },
  {
    href: '/tools',
    title: 'Deliverability tool guides',
    description: 'One-click unsubscribe, MTA-STS, TLS-RPT setup, Postmaster Tools and the Gmail and Yahoo requirements, each alongside the tool that checks it.',
  },
] as const;

// No changefreq or priority: Google has said publicly that it ignores both, and Bing
// weighs them lightly at most. A field nobody reads is a field that drifts untended.
// The study moved to 2026-09-11 when its citation block was added; /about to
// 2026-09-22 for the affiliate-links paragraph.
export const INDEXABLE_PAGES = [
  { path: '/', lastmod: 'collection' },
  { path: '/headers', lastmod: '2026-08-03' },
  { path: '/ip', lastmod: '2026-08-03' },
  { path: '/guides', lastmod: 'collection' },
  // Original research. Listed here rather than coming from the collection because the
  // study is a hand-ported HTML document, not a markdown entry — the dataset page and the
  // derivatives are added by the sitemap route straight from the collection.
  { path: '/research/yc-email-spoofing-study', lastmod: '2026-09-11' },
  { path: '/api', lastmod: '2026-08-03' },
  { path: '/about', lastmod: '2026-09-22' },
] as const;
