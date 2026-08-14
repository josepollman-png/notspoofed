import { glob } from 'astro/loaders';
import { defineCollection } from 'astro:content';
// Imported directly rather than via the `z` re-export from `astro:content`, which is
// deprecated. Astro validates with `zod/v4` internally, so this is pinned to the same
// entry point to keep schema instances interchangeable.
import { z } from 'zod/v4';

/**
 * Explainer guides — the part of the site that is actually meant to rank.
 *
 * The checker itself cannot win on "spf checker"; MXToolbox has two decades of domain
 * authority on those terms. What nobody covers well is the *fix*, so every guide here
 * targets a problem-shaped query ("SPF too many DNS lookups") and ends by handing the
 * reader a record, not a definition.
 *
 * `updated` is required because email authentication advice rots — receiver policies
 * change, and a page with no visible date is one a reader cannot trust.
 */
const guides = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/guides' }),
  schema: z.object({
    title: z.string(),
    /** Used verbatim as the meta description, so write it for a search result. */
    description: z.string().max(180),
    /** The question the reader typed into a search engine. */
    question: z.string(),
    /**
     * Grouping label shown on the index. A closed union rather than a free string, so a
     * typo is a build error instead of a category of one — the index groups by exact
     * match, and "Providers" vs "providers" would silently split a section in two.
     */
    category: z.enum([
      'Getting started',
      'SPF',
      'DKIM',
      'DMARC',
      'Error messages',
      'Providers',
      'Bulk senders',
    ]),
    // Coerced rather than z.string().date(): YAML parses an unquoted 2026-07-31 into
    // a Date, so a string schema fails unless every author remembers the quotes.
    published: z.coerce.date(),
    updated: z.coerce.date(),
    order: z.number().default(100),
    /** Rendered as an FAQPage schema block when present. */
    faq: z
      .array(z.object({ q: z.string(), a: z.string() }))
      .optional(),
  }),
});

/**
 * Original research and the pages derived from it.
 *
 * Separate from `guides` because the constraints differ. A guide is ours to revise; these
 * carry verified figures that reconcile against a published dataset, so the body is
 * imported verbatim and never edited. The head metadata arrives with the source rather
 * than being written here, which is why `titleTag` is its own field: the `<title>` and
 * the on-page `<h1>` are deliberately different strings.
 *
 * `draft` exists because these publish on a schedule after the study lands. A draft still
 * resolves at its URL so it can be reviewed, but sends `noindex` and is kept out of the
 * sitemap and llms.txt.
 */
const research = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/research' }),
  schema: z.object({
    /** The on-page <h1>. */
    title: z.string(),
    /** The <title> element. Written for a search result, not for the page. */
    titleTag: z.string(),
    description: z.string(),
    /** Canonical path. Explicit rather than derived — these do not share a prefix. */
    path: z.string(),
    published: z.coerce.date(),
    updated: z.coerce.date(),
    draft: z.boolean().default(false),
  }),
});

export const collections = { guides, research };
