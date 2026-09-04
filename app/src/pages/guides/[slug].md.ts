import type { APIRoute } from 'astro';
import { getEntry } from 'astro:content';
import { absoluteUrl } from '../../lib/site.js';

/**
 * A guide as plain markdown, at the HTML page's URL plus `.md`.
 *
 * Agents and answer engines increasingly fetch a markdown twin when a page advertises one
 * (`<link rel="alternate" type="text/markdown">`, which the guide template emits), and
 * what they get here is the authored source rather than a rendering of it — no chrome,
 * no CTA, no styles to strip.
 *
 * `noindex` because it duplicates the HTML page word for word. Search engines should
 * rank the canonical page; this one exists to be read by machines, not listed.
 */
export const GET: APIRoute = async ({ params }) => {
  const guide = params.slug ? await getEntry('guides', params.slug) : undefined;
  if (!guide) {
    return new Response('Guide not found', { status: 404 });
  }

  const date = (d: Date) => d.toISOString().slice(0, 10);
  const body = [
    `# ${guide.data.title}`,
    '',
    `> ${guide.data.description}`,
    '',
    `Canonical: ${absoluteUrl(`/guides/${guide.id}/`)}`,
    `Question answered: ${guide.data.question}`,
    `Published: ${date(guide.data.published)}. Last checked: ${date(guide.data.updated)}.`,
    'Author: Jose Pollman, notspoofed.com.',
    '',
    (guide.body ?? '').trim(),
    '',
    ...(guide.data.faq
      ? ['## Frequently asked', '', ...guide.data.faq.flatMap((f) => [`**${f.q}**`, '', f.a, ''])]
      : []),
  ].join('\n');

  return new Response(body + '\n', {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'X-Robots-Tag': 'noindex',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
