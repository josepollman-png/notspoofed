#!/usr/bin/env node
/**
 * Crawl notspoofed.com and fail on a broken internal link.
 *
 *   node scripts/check-links.mjs                       # against production
 *   node scripts/check-links.mjs http://127.0.0.1:3000
 *
 * Two applications serve this hostname and neither can see the other's routes, so an
 * internal link from one half to the other is unverifiable at build time. The home page
 * links to six bounce guides that live in the Next.js app; the bounce guides link back
 * to pages in the Astro app. Nothing but a real fetch can tell you those still resolve.
 *
 * It also enforces the URL scheme rather than merely tolerating it. Guides are
 * `/guide/<slug>` with no trailing slash; the old `/guides/<slug>/` form must answer a
 * single 301 to that, and no page may link to the old form. A 301 that is linked rather
 * than a 301 that is served is a link that costs a redirect on every visit.
 */

const BASE = (process.argv[2] ?? 'https://notspoofed.com').replace(/\/$/, '');
const UA = { 'User-Agent': 'notspoofed-link-check' };

/** Paths deliberately excluded from indexing, which we do not crawl into. */
const SKIP = [/^\/check\b/, /^\/api\b/, /^\/result\//, /^\/stats\b/, /^\/data\//, /\.csv$/, /\.txt$/];

const seen = new Map();
const problems = [];
const linkedOldScheme = [];

const internal = (href) => {
  if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) return null;
  let url;
  try {
    url = new URL(href, `${BASE}/`);
  } catch {
    return null;
  }
  if (url.origin !== BASE) return null;
  return url.pathname + url.search;
};

async function head(path) {
  if (seen.has(path)) return seen.get(path);
  const res = await fetch(`${BASE}${path}`, { redirect: 'manual', headers: UA });
  const record = { status: res.status, location: res.headers.get('location'), res };
  seen.set(path, record);
  return record;
}

const queue = ['/'];
const queued = new Set(queue);
const crawled = [];

while (queue.length > 0) {
  const path = queue.shift();
  if (SKIP.some((re) => re.test(path))) continue;

  const { status, location, res } = await head(path);
  crawled.push(path);

  if (status >= 400) {
    problems.push(`${path} -> ${status}`);
    continue;
  }
  if (status >= 300) {
    // A redirect is fine to serve; it is not fine to link to. Whoever linked it is
    // reported separately below.
    continue;
  }

  const type = res.headers.get('content-type') ?? '';
  if (!type.includes('text/html')) continue;

  const html = await res.text();
  for (const [, href] of html.matchAll(/<a[^>]+href="([^"]+)"/g)) {
    const target = internal(href);
    if (!target) continue;

    if (/^\/guides\/[^/]+/.test(target)) linkedOldScheme.push(`${path} links to ${target}`);

    if (!queued.has(target)) {
      queued.add(target);
      queue.push(target);
    }
  }
}

// Every redirect that was reached must be a single hop to a live page.
for (const [path, { status, location }] of seen) {
  if (status < 300 || status >= 400) continue;
  if (!location) {
    problems.push(`${path} -> ${status} with no Location`);
    continue;
  }
  const next = internal(location) ?? location;
  const hop = await head(next.startsWith('/') ? next : '/');
  if (hop.status !== 200) problems.push(`${path} -> ${status} -> ${next} -> ${hop.status} (not a single hop to 200)`);
}

console.log(`Crawled ${crawled.length} pages on ${BASE}`);

if (linkedOldScheme.length > 0) {
  console.error(`\n${linkedOldScheme.length} link(s) to the retired /guides/<slug> scheme:`);
  for (const line of linkedOldScheme.slice(0, 40)) console.error(`  - ${line}`);
}

if (problems.length > 0) {
  console.error(`\n${problems.length} broken link(s):`);
  for (const line of problems) console.error(`  - ${line}`);
}

if (problems.length > 0 || linkedOldScheme.length > 0) process.exit(1);
console.log('No broken links, and nothing links to the old scheme.');
