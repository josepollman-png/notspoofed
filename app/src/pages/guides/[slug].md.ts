import type { APIRoute } from 'astro';
import { getEntry } from 'astro:content';

/**
 * The old markdown-twin URLs, redirected to their new home under /guide/.
 *
 * Advertised in an earlier /llms.txt and linked from the HTML pages as
 * `rel="alternate"`, so agents have the old form cached. See guides/[...slug].astro
 * for why the scheme moved.
 */
export const GET: APIRoute = async ({ params }) => {
  const slug = params.slug;
  // Same rule as the HTML route: only a real guide redirects, anything else 404s here.
  if (!slug || !(await getEntry('guides', slug))) {
    return new Response('Guide not found', { status: 404 });
  }

  return new Response(null, {
    status: 301,
    headers: { Location: `/guide/${slug}.md` },
  });
};
