import type { APIRoute } from 'astro';

/**
 * Liveness probe for the container healthcheck.
 *
 * Exists because the healthcheck used to fetch `/`, which meant every 30 seconds it
 * rendered the full landing page *and* — once stats were added — recorded a page view.
 * That put 1,116 fake views on `/` in the first nine hours and made the metric
 * worthless. Probes belong on their own endpoint, and that endpoint should be cheap.
 *
 * Returns text/plain, so the middleware's HTML check skips it even if the path filter
 * is ever changed.
 */
export const GET: APIRoute = () =>
  new Response('ok', {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  });
