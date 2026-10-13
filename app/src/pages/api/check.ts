import type { APIRoute } from 'astro';
import { apiBody } from '../../lib/api-body.js';
import { InvalidDomainError, runCheck } from '../../lib/check.js';
import { clientIp, rateLimit, RATE_LIMIT } from '../../lib/ratelimit.js';
import { siteOrigin } from '../../lib/site.js';
import { track } from '../../lib/stats.js';

/**
 * Public JSON API. The response body is built in `lib/api-body.ts`.
 *
 * Same rate limit and the same crawl exclusion as the HTML route: this is the same
 * expensive, unbounded work with a different Content-Type.
 */

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      // Open CORS: the whole point is that other people's tools can call it.
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'X-Robots-Tag': 'noindex, nofollow',
      'Cache-Control': 'public, max-age=60',
      ...extra,
    },
  });

export const OPTIONS: APIRoute = () => json({}, 204);

export const GET: APIRoute = async ({ request, url, clientAddress }) => {
  const domain = url.searchParams.get('domain')?.trim() ?? '';
  if (domain === '') {
    return json({ error: 'missing_domain', message: 'Pass ?domain=example.com' }, 400);
  }

  const selectors = (url.searchParams.get('selectors') ?? '')
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^[a-z0-9._-]{1,63}$/.test(s))
    .slice(0, 5);

  const limit = await rateLimit(clientIp(request, clientAddress));
  if (!limit.allowed) {
    return json(
      {
        error: 'rate_limited',
        message: `Limit is ${RATE_LIMIT.MAX_REQUESTS} requests per ${RATE_LIMIT.WINDOW_SECONDS}s.`,
        retryAfter: limit.resetIn,
      },
      429,
      { 'Retry-After': String(limit.resetIn) },
    );
  }

  try {
    const r = await runCheck(domain, { selectors });

    track({
      path: '/api/check',
      referrer: request.headers.get('referer'),
      userAgent: request.headers.get('user-agent'),
      clientIp: clientIp(request, clientAddress),
      selfHost: new URL(siteOrigin()).hostname,
      isCheck: true,
      viaApi: true,
    });

    return json(apiBody(r));
  } catch (err) {
    if (err instanceof InvalidDomainError) {
      return json({ error: 'invalid_domain', message: err.message }, 400);
    }
    console.error('api check failed', { domain, err });
    return json(
      { error: 'check_failed', message: 'The check could not be completed, usually a DNS timeout.' },
      502,
    );
  }
};
