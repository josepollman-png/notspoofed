#!/usr/bin/env node
/**
 * Validate the structured data on notspoofed.com.
 *
 *   node scripts/check-jsonld.mjs                      # against production
 *   node scripts/check-jsonld.mjs http://127.0.0.1:3000
 *
 * The hostname is served by two applications — the Astro app owns `/`, `/guides` and
 * `/about`, the Next.js app owns `/tools/*` and `/guide/*` — and their structured data
 * has to agree about who publishes the site and who writes it. Nothing in either build
 * can catch a disagreement, because neither app can see the other's output. This script
 * is that check, and it is the reason the identifiers are written down in two places
 * rather than inferred.
 *
 * What it asserts, per page:
 *   1. Every ld+json block parses. A block that does not parse is invisible, and the
 *      failure is silent everywhere else.
 *   2. The types the page is supposed to carry are present.
 *   3. Every `@id` referenced as an author or publisher is DEFINED on the same page.
 *      A reference to a node a crawler has not fetched resolves to nothing, and a page
 *      reached from a search result may be the only page it ever fetches.
 *   4. Articles carry both dates, in ISO form, and neither is in the future.
 *
 * Exit code is non-zero if anything fails, so it can gate a deploy.
 */

const BASE = (process.argv[2] ?? 'https://notspoofed.com').replace(/\/$/, '');

/** The canonical Organization spelling. Must match the header, the title suffix and og:site_name. */
const ORG_NAME = 'notspoofed.com';

/** The Person's sameAs, byte for byte, as it must appear on all five of Jose Pollman's sites. */
const SAME_AS = [
  'https://medium.com/@josepollman',
  'https://knowyourmouth.com/about.html',
  'https://whattofixfirst.com/about',
  'https://vetthisvendor.com/about',
  'https://subcovered.com/about',
];

/** `expect` lists the @type values that must appear somewhere in the page's blocks. */
const PAGES = [
  { path: '/', expect: ['Organization', 'SoftwareApplication', 'FAQPage'] },
  { path: '/about', expect: ['Person'] },
  { path: '/guide/dkim-selectors', expect: ['TechArticle'] },
  { path: '/guide/spf-too-many-dns-lookups', expect: ['TechArticle'] },
  { path: '/guide/spf-dkim-dmarc-results', expect: ['TechArticle', 'BreadcrumbList', 'FAQPage', 'Person', 'Organization'] },
  { path: '/guides', expect: [] },
  { path: '/tools', expect: ['Organization', 'Person', 'WebSite'] },
  { path: '/tools/bounce-decoder', expect: ['SoftwareApplication', 'FAQPage', 'Organization', 'Person'] },
  { path: '/tools/unsubscribe-checker', expect: ['SoftwareApplication', 'FAQPage'] },
  { path: '/tools/tls-rpt-analyzer', expect: ['SoftwareApplication', 'FAQPage'] },
  { path: '/tools/gmail-yahoo-compliance', expect: ['SoftwareApplication', 'FAQPage'] },
  { path: '/tools/dkim-selector-finder', expect: ['SoftwareApplication', 'FAQPage', 'BreadcrumbList', 'Person', 'Organization'] },
  { path: '/tools/spf-lookup-counter', expect: ['SoftwareApplication', 'FAQPage', 'BreadcrumbList', 'Person', 'Organization'] },
  { path: '/guide/bounce/mimecast-rejected', expect: ['TechArticle', 'BreadcrumbList', 'Person', 'Organization'] },
  { path: '/guide/hard-vs-soft-bounce', expect: ['TechArticle', 'BreadcrumbList'] },
  { path: '/guide/google-yahoo-sender-requirements', expect: ['TechArticle', 'BreadcrumbList'] },
  { path: '/research/yc-email-spoofing-study', expect: ['Article', 'Dataset'] },
];

const failures = [];
const fail = (path, message) => failures.push(`${path}: ${message}`);

/** Every JSON object in the document, flattened out of @graph wrappers. */
function nodesFrom(html, path) {
  const blocks = [...html.matchAll(/<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)];
  const nodes = [];

  for (const [, raw] of blocks) {
    let parsed;
    try {
      // `<` is escaped as < on the way out; JSON.parse handles that natively.
      parsed = JSON.parse(raw.trim());
    } catch (error) {
      fail(path, `unparseable ld+json block: ${error.message}`);
      continue;
    }
    const top = Array.isArray(parsed) ? parsed : [parsed];
    for (const node of top) {
      if (node && Array.isArray(node['@graph'])) nodes.push(...node['@graph']);
      else if (node) nodes.push(node);
    }
  }
  return { nodes, blockCount: blocks.length };
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const today = new Date().toISOString().slice(0, 10);

async function checkPage({ path, expect }) {
  const url = `${BASE}${path}`;
  let res;
  try {
    res = await fetch(url, { redirect: 'manual', headers: { 'User-Agent': 'notspoofed-jsonld-check' } });
  } catch (error) {
    fail(path, `request failed: ${error.message}`);
    return;
  }

  if (res.status !== 200) {
    fail(path, `expected 200, got ${res.status}${res.headers.get('location') ? ` -> ${res.headers.get('location')}` : ''}`);
    return;
  }

  const html = await res.text();
  const { nodes, blockCount } = nodesFrom(html, path);

  if (expect.length > 0 && blockCount === 0) {
    fail(path, 'no ld+json blocks at all');
    return;
  }

  const types = new Set(nodes.flatMap((n) => (Array.isArray(n['@type']) ? n['@type'] : [n['@type']])));
  for (const wanted of expect) {
    if (!types.has(wanted)) fail(path, `missing @type ${wanted} (found: ${[...types].join(', ') || 'none'})`);
  }

  const defined = new Set(nodes.map((n) => n['@id']).filter(Boolean));

  /**
   * Every reference, not just author and publisher.
   *
   * A bare `{ "@id": "..." }` is a pointer: it says "the thing described elsewhere".
   * If nothing on the page defines that id, the pointer resolves to nothing and the
   * property is silently dropped — which is how an entity graph ends up asserting less
   * than its source code appears to. `worksFor`, `founder` and `isPartOf` fail the same
   * way `author` does, so the check walks the whole tree rather than a list of keys.
   */
  const walkRefs = (node, where) => {
    if (Array.isArray(node)) return node.forEach((n) => walkRefs(n, where));
    if (!node || typeof node !== 'object') return;
    const keys = Object.keys(node);
    if (keys.length === 1 && keys[0] === '@id') {
      if (!defined.has(node['@id'])) {
        fail(path, `${where} references ${node['@id']}, which no node on this page defines`);
      }
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === '@id') continue;
      walkRefs(v, `${node['@type'] ?? where}.${k}`);
    }
  };
  walkRefs(nodes, 'page');

  // One spelling of the Organization, everywhere. A near-miss splits the entity.
  for (const node of nodes) {
    if (node['@type'] === 'Organization' && node.name && node.name !== ORG_NAME) {
      fail(path, `Organization name is "${node.name}", expected "${ORG_NAME}"`);
    }
  }

  for (const node of nodes) {

    if (node['@type'] === 'TechArticle' || node['@type'] === 'Article') {
      for (const key of ['datePublished', 'dateModified']) {
        const value = node[key];
        if (!value) fail(path, `${node['@type']} has no ${key}`);
        else if (!ISO_DATE.test(value)) fail(path, `${node['@type']} ${key} is not a plain ISO date: ${value}`);
        else if (value > today) fail(path, `${node['@type']} ${key} is in the future: ${value}`);
      }
    }
  }

  for (const node of nodes) {
    if (node['@type'] !== 'Person') continue;
    const got = JSON.stringify(node.sameAs ?? []);
    if (got !== JSON.stringify(SAME_AS)) {
      fail(path, `Person sameAs differs from the shared list: ${got}`);
    }
  }

  // og:site_name is one of the five surfaces the Organization name has to match on, and
  // it is the one a framework silently drops when a page overrides its openGraph object.
  const siteName = /<meta property="og:site_name" content="([^"]*)"/.exec(html)?.[1];
  if (!siteName) fail(path, 'no og:site_name');
  else if (siteName !== ORG_NAME) fail(path, `og:site_name is "${siteName}", expected "${ORG_NAME}"`);

  const label = expect.length ? [...types].join(', ') : 'no types required';
  console.log(`  ok  ${path.padEnd(42)} ${label}`);
}

console.log(`Validating structured data on ${BASE}\n`);
for (const page of PAGES) await checkPage(page);

if (failures.length > 0) {
  console.error(`\n${failures.length} problem(s):`);
  for (const line of failures) console.error(`  - ${line}`);
  process.exit(1);
}

console.log(`\nAll ${PAGES.length} pages valid.`);
