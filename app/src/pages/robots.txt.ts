import type { APIRoute } from 'astro';
import { absoluteUrl } from '../lib/site.js';

/**
 * `/check` is disallowed, and that is the whole point of this file.
 *
 * Result pages take a domain from the query string, so the URL space is unbounded —
 * a crawler can generate them forever. Each one costs ~48 outbound DNS queries, and
 * the per-IP rate limiter starts returning 429 to the crawler, which search engines
 * read as an unhealthy site and respond to by crawling *less*. Left alone this
 * actively suppresses the pages we do want ranked.
 *
 * Disallowing here stops the crawl before the cost is incurred. Because a disallowed
 * URL can still be indexed without content if something links to it, /check also
 * sends `X-Robots-Tag: noindex` — that covers crawlers which ignore this file.
 */
const DISALLOW = [
  'Disallow: /check',
  // Same reasoning as /check — the JSON endpoint is the same unbounded, expensive
  // work with a different Content-Type. /api (the docs page) stays crawlable.
  'Disallow: /api/check',
  // The DKIM selector finder's own endpoint. Same-origin only — it answers 403 to
  // anything else — but a crawler that finds the URL in page source should not spend
  // its budget learning that.
  'Disallow: /api/dkim-selectors',
  // The SPF lookup counter's endpoint: same-origin POST only, same reasoning.
  'Disallow: /api/spf-lookups',
  // Prefix match on the query string only: /ip?ip=… is an unbounded result space,
  // while bare /ip is a landing page we want indexed.
  'Disallow: /ip?',
  // Saved results from the tools app. Same reasoning as /check — unbounded URL
  // space, every entry a one-off — and they already send noindex via X-Robots-Tag
  // for the crawlers that ignore this file.
  'Disallow: /result/',
  'Allow: /',
  // Content Signals (contentsignals.org): a machine-readable statement of what the
  // crawled content may be used for. Not a standard every crawler reads, but the ones
  // that do treat its absence as ambiguity. The site's position is unambiguous — cite
  // it, feed it to a model, train on it — so it is stated in each group.
  'Content-Signal: search=yes, ai-input=yes, ai-train=yes',
];

/**
 * Answer engines get their own groups, and every one repeats the rules above.
 *
 * This is the trap in the format: robots.txt groups are **not** merged. A crawler obeys
 * the single most specific group that names it and ignores `User-agent: *` entirely, so
 * a well-meant `User-agent: GPTBot / Allow: /` would hand exactly these crawlers the
 * unbounded /check space that every other rule in this file exists to protect. Repeating
 * `DISALLOW` in each group is what makes naming them safe.
 *
 * The site is already permissive to everything, so none of this grants new access. It
 * states the position explicitly, which is the part an operator can point at.
 *
 * Two of these are not crawlers. `Google-Extended` and `Applebot-Extended` are usage
 * controls — they govern whether already-crawled pages may feed Gemini and Apple
 * Intelligence, and honour no fetch of their own. They belong here anyway: the answer is
 * yes, and the token is the only way to say it.
 */
const ANSWER_ENGINES = [
  // OpenAI publishes three, and they do different jobs. GPTBot crawls for training;
  // OAI-SearchBot builds the ChatGPT search index; ChatGPT-User fetches a page live when
  // someone asks about it. Naming only GPTBot — as most guides do — leaves the two that
  // actually produce citations unaddressed.
  'GPTBot',
  'OAI-SearchBot',
  'ChatGPT-User',
  'ClaudeBot',
  'Claude-SearchBot',
  'PerplexityBot',
  'Google-Extended',
  'Applebot-Extended',
];

export const GET: APIRoute = () =>
  new Response(
    [
      ...ANSWER_ENGINES.flatMap((agent) => [`User-agent: ${agent}`, ...DISALLOW, '']),

      // Last, and deliberately so. The wildcard group is the fallback for everything not
      // named above; order carries no meaning to a parser, but it reads correctly.
      'User-agent: *',
      ...DISALLOW,
      '',
      // A sitemap index. It references this app's own /sitemap-site.xml and the tools
      // application's /tools/sitemap.xml, so one entry covers both halves of the
      // hostname — and anything added later.
      `Sitemap: ${absoluteUrl('/sitemap.xml')}`,
      // TEMPORARY, with the route: the pre-move /guides/ URLs, so crawlers follow their
      // redirects. Remove both after 2026-11-06.
      `Sitemap: ${absoluteUrl('/sitemap-legacy.xml')}`,
      // No Llms-txt line. It is not a robots.txt directive, Lighthouse fails the file for
      // it, and /llms.txt is found at its well-known path without one.
      '',
    ].join('\n'),
    { headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
  );
