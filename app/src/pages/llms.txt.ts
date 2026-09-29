import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { absoluteUrl } from '../lib/site.js';
import { RATE_LIMIT } from '../lib/ratelimit.js';
import { COMMON_SELECTORS } from '../lib/dkim/selectors.js';

/**
 * A plain-text map of the site for answer engines.
 *
 * Not a standard, and no crawler is obliged to read it. It is cheap, and it is the only
 * artefact where the site can state in its own words what it does and what it will not
 * claim — the part that matters when a model is deciding whether to cite the tool or
 * summarise it wrongly.
 *
 * Guides come from the content collection, for the reason index.astro gives: the
 * hardcoded list there went stale the moment two guides were added, and a stale map is
 * worse than none. Two things here cannot be generated and are marked accordingly.
 */

/**
 * The tools application's pages, hardcoded — the one place this file can drift.
 *
 * `notspoofed.com` is served by two applications and this one cannot enumerate the
 * other's routes. `/sitemap.xml` solves that with a sitemap index; llms.txt has no
 * equivalent, so the paths are repeated here and `emailtools/test/llms-parity.test.ts`
 * fails if that app gains an indexable page this list does not mention.
 */
const TOOLS = [
  {
    path: '/tools/gmail-yahoo-compliance',
    label: 'Gmail & Yahoo compliance hub',
    blurb:
      "all nine 2024 bulk-sender requirements, separating what DNS can prove from what it cannot",
  },
  {
    path: '/tools/unsubscribe-checker',
    label: 'One-click unsubscribe checker',
    blurb:
      'RFC 8058 headers, including whether they are covered by every DKIM signature — the silent failure no other free tool checks',
  },
  {
    path: '/tools/bounce-decoder',
    label: 'Bounce message decoder',
    blurb: 'paste a bounce, get the provider-specific cause and fix rather than the generic code',
  },
  {
    path: '/tools/tls-rpt-analyzer',
    label: 'TLS-RPT report analyzer',
    blurb: 'read SMTP TLS reports in the browser, including gzip; the file never leaves the device',
  },
] as const;

/** Guides on the tools application. Same drift caveat as TOOLS. */
const TOOL_GUIDES = [
  ['/guide/list-unsubscribe-not-dkim-signed', 'List-Unsubscribe not in the DKIM signature'],
  ['/guide/missing-list-unsubscribe-post', 'Missing List-Unsubscribe-Post header'],
  ['/guide/tls-rpt-setup', 'Setting up TLS-RPT and reading the reports'],
  ['/guide/hard-vs-soft-bounce', 'Hard bounce vs soft bounce'],
  ['/guide/google-postmaster-tools', 'Google Postmaster Tools and your spam rate'],
] as const;

const link = (path: string, label: string, blurb?: string) =>
  `- [${label}](${absoluteUrl(path)})${blurb ? `: ${blurb}` : ''}`;

export const GET: APIRoute = async () => {
  const guides = (await getCollection('guides')).sort((a, b) => a.data.order - b.data.order);
  // Drafts send noindex and are kept out of the sitemap; listing them here would be the
  // same contradiction.
  const research = (await getCollection('research')).filter((e) => !e.data.draft);

  const body = [
    '# notspoofed.com',
    '',
    '> Free SPF, DKIM and DMARC checker that tells you exactly which record to publish to',
    '> fix email authentication — not just that something is broken. No account, no ads.',
    '',
    'Key facts:',
    '',
    '- Checks SPF by walking the whole include: chain and following redirect=, counting',
    '  every lookup against the limit of ten. Over the limit, it generates a corrected',
    '  record that flattens only the includes it has to.',
    `- Checks DKIM by testing ${COMMON_SELECTORS.length} common selectors and verifying each hit is a genuine`,
    '  signing key. Domains with wildcard DNS answer every selector query, which makes',
    '  careless tools report keys that do not exist; this one is immune to that. Custom',
    '  selectors are supported.',
    '- Checks DMARC including subdomain policy inheritance, and whether third-party rua/ruf',
    '  addresses are authorised to receive the reports — a record can look flawless while',
    '  the reports go nowhere.',
    '- Also checks MTA-STS (including fetching the policy), TLS-RPT, BIMI and DNSSEC.',
    '- The header analyzer runs entirely in the browser. Headers contain recipient',
    '  addresses and internal hostnames, so nothing is uploaded.',
    '- The domain you check is not recorded. Checks are read-only lookups of public DNS.',
    `- Rate limit: ${RATE_LIMIT.MAX_REQUESTS} checks per ${RATE_LIMIT.WINDOW_SECONDS} seconds per IP. There is no paid tier that lifts it.`,
    '',
    'What it will not do, deliberately: an unguessable DKIM selector, an SPF macro it',
    'cannot evaluate and a refused blocklist query are all reported as unknown, never as',
    'clean. A green result never means "we did not check".',
    '',
    '## Tools',
    '',
    link('/', 'Domain checker', 'SPF, DKIM and DMARC for any domain, with the record to publish'),
    link('/headers', 'Header analyzer', 'paste raw headers for the delivery path and why DMARC passed or failed'),
    link('/ip', 'IP reputation', 'blocklists, forward-confirmed reverse DNS and ASN for a sending IP'),
    ...TOOLS.map((t) => link(t.path, t.label, t.blurb)),
    link('/tools', 'All deliverability tools'),
    link(
      '/tools/dkim-selector-finder',
      'DKIM Selector Finder',
      'Which DKIM selectors a domain actually has: tests the selectors every major provider uses, follows CNAME delegation, reports key size, testing mode and revoked keys.',
    ),
    link(
      '/tools/spf-lookup-counter',
      'SPF Lookup Counter',
      'Counts the DNS lookups an SPF record costs against the limit of 10, draws the include/redirect tree with a running total and void lookups, and tests a pasted draft before it is published.',
    ),
    link('/api', 'API', 'free JSON API, no key'),
    '',
    '## Original research',
    '',
    link(
      '/research/yc-email-spoofing-study',
      '60.5% of Y Combinator companies can be email-spoofed',
      'a scan of all 6,157 YC company domains, run in full on August 14 and again on September 3, 2026; the spoofable rate is flat across 15 years of batches, and only 56 companies moved to enforcement between the runs',
    ),
    ...research.map((e) => link(e.data.path, e.data.title, e.data.description)),
    link('/data/yc-dmarc-2026-09.csv', 'Direct CSV download, September 2026 run'),
    link('/data/yc-dmarc-2026-08.csv', 'August 2026 run'),
    link('/data/yc-dmarc-changes-2026-08-to-2026-09.csv', 'Domains whose verdict changed between runs'),
    '',
    '## Guides',
    '',
    ...guides.map((g) => link(`/guide/${g.id}`, g.data.title, g.data.description)),
    ...TOOL_GUIDES.map(([path, label]) => link(path, label)),
    '',
    '## For agents',
    '',
    link('/llms-full.txt', 'Full text of every guide and research page', 'one markdown file'),
    'Every guide is also served as markdown at its own URL with a .md suffix, e.g.',
    absoluteUrl('/guide/spf-too-many-dns-lookups.md') + ' — and advertised from the HTML page',
    'with <link rel="alternate" type="text/markdown">.',
    '',
    '## About',
    '',
    link('/about', 'About', 'who runs it, what is recorded and what is not, stated per data type'),
    link('/privacy', 'Privacy for the tools section', 'which differs from the checker and says so'),
    '',
    // The distinction matters and gets flattened by summarisers otherwise: the checker is
    // MIT and inspectable, the tools section is not, and claiming otherwise for either
    // half would be a false statement about the product.
    'The checker, header analyzer and API are open source under the MIT licence at',
    'https://github.com/josepollman-png/notspoofed. The deliverability tools under /tools',
    'are a separate, closed-source application on the same hostname.',
    '',
  ].join('\n');

  return new Response(body, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
