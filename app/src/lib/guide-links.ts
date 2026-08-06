/**
 * Findings → the guide that explains them.
 *
 * A result page that says "SPF needs 14 DNS lookups" while a page explaining exactly
 * that sits one directory away, unlinked, is wasting the only content the site has.
 *
 * Kept as plain data with no imports beyond a type, because it is consumed from both
 * sides of the boundary: `FindingCard.astro` renders server-side, and `/headers` builds
 * its cards in the browser. Reading titles from the content collection would work in the
 * first and not the second — `astro:content` is server-only — so the titles are
 * duplicated here and `test/guide-links.test.ts` fails if either the slug or the title
 * drifts from the markdown.
 *
 * `Partial` is load-bearing: adding a finding id with no guide must stay a non-event,
 * while a typo in an id that does exist stays a compile error.
 */

import type { FindingId } from './findings.js';

export interface GuideLink {
  slug: string;
  title: string;
}

const G = {
  spoofing: { slug: 'someone-is-spoofing-my-domain', title: 'Someone is sending email as my domain' },
  lookups: { slug: 'spf-too-many-dns-lookups', title: 'SPF: too many DNS lookups' },
  softfail: { slug: 'spf-softfail-vs-hardfail', title: 'SPF: should it end in ~all or -all?' },
  pNone: { slug: 'dmarc-p-none', title: 'What DMARC p=none actually does' },
  alignment: { slug: 'dmarc-fails-when-spf-passes', title: 'Why DMARC fails when SPF and DKIM pass' },
  reports: { slug: 'dmarc-reports-not-arriving', title: 'Your DMARC reports may be going nowhere' },
  bulk: { slug: 'google-yahoo-sender-requirements', title: "Google and Yahoo's sender requirements" },
  selectors: { slug: 'dkim-selectors', title: 'Finding your DKIM selector' },
  selectorList: { slug: 'dkim-selector-list', title: 'DKIM selectors by provider' },
} as const satisfies Record<string, GuideLink>;

export const FINDING_GUIDES: Partial<Record<FindingId, GuideLink>> = {
  // SPF
  'spf-missing': G.bulk,
  'spf-lookup-limit': G.lookups,
  'spf-lookup-headroom': G.lookups,
  'spf-permissive-all': G.softfail,
  'spf-no-all': G.softfail,
  'spf-neutral-all': G.softfail,

  // DKIM. Not dkim-weak-key — key length is a different subject and the guide would
  // not answer the question the finding raises.
  //
  // "No DKIM found" goes to the provider table rather than the explainer. Someone
  // reading that finding has two questions — is this a real absence, and what should I
  // try instead — and the table answers both: its "unguessable by design" section is
  // precisely why the finding is so often wrong on SES and SparkPost domains. Only one
  // link renders per finding, but the table's first sentence links to the explainer, so
  // the reader can still get there. The wildcard trap stays with the explainer, which
  // is where it is worked through in depth.
  'dkim-none-found': G.selectorList,
  'dkim-wildcard-dns': G.selectors,

  // DMARC
  'dmarc-missing': G.spoofing,
  'dmarc-sp-weaker': G.spoofing,
  // np= is the subdomain-forgery tag, and the spoofing guide is where that attack is
  // explained; the rollout tags belong with the guide about getting to enforcement.
  'dmarc-no-np': G.spoofing,
  'dmarc-p-none': G.pNone,
  'dmarc-pct': G.pNone,
  'dmarc-test-mode': G.pNone,
  'dmarc-deprecated-tags': G.pNone,
  'dmarc-no-rua': G.reports,
  'dmarc-rua-undeliverable': G.reports,
  'dmarc-external-unauthorised': G.reports,

  // Header analyzer. These only ever render in the browser, from /headers.
  'header-dmarc-fail': G.alignment,
  'header-spf-not-aligned': G.alignment,
  'header-dkim-not-aligned': G.alignment,
};

export function guideFor(id: FindingId): GuideLink | undefined {
  return FINDING_GUIDES[id];
}

export function guideHref(guide: GuideLink): string {
  return `/guides/${guide.slug}/`;
}
