import { getCollection } from 'astro:content';
import { absoluteUrl, INDEXABLE_PAGES } from './site.js';

/**
 * The sitemap, built from one place per application.
 *
 * notspoofed.com is two applications behind one hostname. This one owns `/`, the
 * guides written in markdown and the research pages; the Next.js app owns `/tools/*`
 * and the bounce, TLS-RPT and tool guides. Neither can enumerate the other's routes, so
 * "a single source of truth" cannot mean one list in one repository. It means each
 * application is the only authority on its own URLs and the other one never retypes
 * them: this file lists this app's pages, the tools app's `/tools/sitemap.xml` lists
 * its pages, and `/sitemap.xml` is the two merged at request time.
 *
 * Every entry has a real `lastmod` — the date the content last changed in a way a
 * reader would notice — and nothing else. `changefreq` and `priority` are gone: Google
 * has said it ignores both.
 */

export interface SitemapEntry {
  loc: string;
  lastmod: string;
}

const iso = (d: Date) => d.toISOString().slice(0, 10);

export async function siteEntries(): Promise<SitemapEntry[]> {
  const guides = await getCollection('guides');
  const research = (await getCollection('research')).filter((entry) => !entry.data.draft);

  // The pages that list the collection changed when the newest thing in it did.
  const newest = [...guides, ...research].map((e) => iso(e.data.updated)).sort().at(-1)!;

  return [
    ...INDEXABLE_PAGES.map((p) => ({
      loc: absoluteUrl(p.path),
      lastmod: p.lastmod === 'collection' ? newest : p.lastmod,
    })),
    ...guides.map((guide) => ({
      loc: absoluteUrl(`/guide/${guide.id}`),
      lastmod: iso(guide.data.updated),
    })),
    // Drafts send noindex, so listing one would contradict the page.
    ...research.map((entry) => ({
      loc: absoluteUrl(entry.data.path),
      lastmod: iso(entry.data.updated),
    })),
  ];
}

export function urlset(entries: readonly SitemapEntry[]): string {
  const urls = entries
    .map((e) => `  <url>\n    <loc>${e.loc}</loc>\n    <lastmod>${e.lastmod}</lastmod>\n  </url>`)
    .join('\n');
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`
  );
}

/**
 * The tools application's entries, read from its own sitemap over the internal network.
 *
 * Cached, because a crawler fetching /sitemap.xml should not wait on a second service,
 * and last-good, because a sitemap that silently shrinks by half when the other
 * container is restarting is worse than a slightly stale one. `null` means there has
 * never been a successful read — the caller then falls back to a sitemap index, which
 * is complete by construction.
 */
const TOOLS_ORIGIN = () => process.env.EMAILTOOLS_ORIGIN?.trim() || 'http://emailtools:3000';
const FRESH_MS = 10 * 60 * 1000;
let cache: { entries: SitemapEntry[]; at: number } | null = null;

export async function toolsEntries(): Promise<SitemapEntry[] | null> {
  if (cache && Date.now() - cache.at < FRESH_MS) return cache.entries;

  try {
    const res = await fetch(`${TOOLS_ORIGIN()}/tools/sitemap.xml`, {
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) throw new Error(`tools sitemap answered ${res.status}`);
    const xml = await res.text();
    const entries = [...xml.matchAll(/<url>([\s\S]*?)<\/url>/g)].map(([, block]) => ({
      loc: /<loc>([^<]+)<\/loc>/.exec(block!)?.[1] ?? '',
      lastmod: /<lastmod>([^<]+)<\/lastmod>/.exec(block!)?.[1] ?? '',
    }));
    // Every tools entry must carry a date; one that does not is a bug over there, and
    // publishing it here would reintroduce the undated URL this file exists to prevent.
    const usable = entries.filter((e) => e.loc && e.lastmod);
    if (usable.length === 0) throw new Error('tools sitemap had no dated entries');
    cache = { entries: usable, at: Date.now() };
    return usable;
  } catch (error) {
    console.error('sitemap: could not read the tools sitemap', { error: String(error) });
    return cache?.entries ?? null;
  }
}
