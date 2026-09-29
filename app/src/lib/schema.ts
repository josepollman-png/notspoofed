import { absoluteUrl } from './site.js';

/**
 * The site's identity nodes, emitted on every page.
 *
 * ## Why every page and not just the home page
 *
 * Every guide's `TechArticle` names an author and a publisher by `@id`. Those
 * identifiers used to be defined in exactly two places — the Organization on `/` and the
 * Person on `/about` — so on a guide page the references resolved to nothing. A crawler
 * that arrives from a search result may fetch that page and no other, and a reference to
 * a node it has not seen is not an authorship signal; it is a dangling pointer.
 *
 * `scripts/check-jsonld.mjs` is what found that, and it fails if it happens again.
 *
 * ## Why the values are duplicated in the other repository
 *
 * `notspoofed.com` is served by two applications, and the Next.js one publishes the same
 * two nodes under the same two identifiers — see `emailtools/src/lib/schema.ts`. They
 * must agree character for character: two Organizations under different `@id`s describe
 * two organisations, which is worse than describing none. Change one, change both.
 */

export const ORG_ID = () => absoluteUrl('/#organization');
export const PERSON_ID = () => absoluteUrl('/about#author');
export const WEBSITE_ID = () => absoluteUrl('/#website');

export const AUTHOR_NAME = 'Jose Pollman';

/**
 * Profiles that identify the same person elsewhere.
 *
 * Byte-identical on all five sites Jose Pollman publishes, minus whichever site is
 * serving it — that is the whole mechanism. An entity resolver deciding whether five
 * small domains are one credible author or five unrelated thin sites is comparing these
 * arrays; one that differs by a trailing slash, an ordering or a missing entry is weaker
 * evidence than one that matches exactly.
 *
 * `knowyourmouth.com` publishes its author page at `/about.html`, not `/about`. The
 * Medium profile answers 403 to non-browser clients, which is Medium's bot handling
 * rather than a dead page; it was verified through its RSS feed.
 *
 * This is not a ranking lever and nothing here should be expected to move a position.
 */
export const AUTHOR_SAME_AS = [
  'https://medium.com/@josepollman',
  'https://knowyourmouth.com/about.html',
  'https://whattofixfirst.com/about',
  'https://vetthisvendor.com/about',
  'https://subcovered.com/about',
];

export function organizationNode(): Record<string, unknown> {
  return {
    '@type': 'Organization',
    '@id': ORG_ID(),
    name: 'notspoofed.com',
    url: absoluteUrl('/'),
    logo: absoluteUrl('/og-default.png'),
    email: 'hello@notspoofed.com',
    sameAs: ['https://github.com/josepollman-png/notspoofed'],
    founder: { '@id': PERSON_ID() },
  };
}

export function personNode(): Record<string, unknown> {
  return {
    '@type': 'Person',
    '@id': PERSON_ID(),
    name: AUTHOR_NAME,
    url: absoluteUrl('/about'),
    jobTitle: 'Builder and maintainer of notspoofed.com',
    worksFor: { '@id': ORG_ID() },
    sameAs: AUTHOR_SAME_AS,
    knowsAbout: [
      // This site's subject areas only. Listing all five sites' topics on one Person
      // would claim expertise in dentistry and invoice fraud alongside email
      // authentication, which reads as less authoritative on each, not more.
      'SPF',
      'DKIM',
      'DMARC',
      'email authentication',
      'email deliverability',
      'SMTP bounce codes',
      'DNS',
    ],
  };
}

export function webSiteNode(): Record<string, unknown> {
  return {
    '@type': 'WebSite',
    '@id': WEBSITE_ID(),
    name: 'notspoofed.com',
    url: absoluteUrl('/'),
    publisher: { '@id': ORG_ID() },
    inLanguage: 'en',
  };
}

/** One block, rendered by the base layout on every page. */
export function siteGraph(): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@graph': [organizationNode(), personNode(), webSiteNode()],
  };
}
