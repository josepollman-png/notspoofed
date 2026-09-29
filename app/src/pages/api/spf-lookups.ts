import type { APIRoute } from 'astro';
import { InvalidDomainError } from '../../lib/check.js';
import { clientIp, rateLimit, RATE_LIMIT } from '../../lib/ratelimit.js';
import { isSameOrigin } from '../../lib/same-origin.js';
import { siteOrigin } from '../../lib/site.js';
import { countSpfLookups, InvalidRecordError } from '../../lib/spf/counter.js';
import { track } from '../../lib/stats.js';

/**
 * The SPF lookup counter's endpoint. Internal, for the same reason as
 * `/api/dkim-selectors`: it resolves a name the caller chooses, so it answers only the
 * tool page on this hostname and is rate limited with everything else.
 *
 * POST, not GET, because a pasted draft can run to a few kilobytes and has no business
 * in a URL. The page's own `?domain=` link is what gets shared; the draft never is.
 *
 * Nothing is stored and nothing is logged about the input: no cache keyed on the domain,
 * and the error log below carries the error alone. Someone re-checking after editing DNS
 * wants the live answer anyway.
 */

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Robots-Tag': 'noindex, nofollow',
      'Cache-Control': 'private, no-store',
      ...extra,
    },
  });

export const POST: APIRoute = async ({ request, clientAddress }) => {
  if (!isSameOrigin(request)) {
    return json({ error: 'forbidden', message: 'This endpoint serves the SPF lookup counter page only.' }, 403);
  }

  let body: { domain?: unknown; record?: unknown };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'bad_request', message: 'Send JSON: {"domain": "example.com"} or {"record": "v=spf1 …"}.' }, 400);
  }
  const domain = typeof body.domain === 'string' ? body.domain : '';
  const record = typeof body.record === 'string' ? body.record : '';
  if (domain.trim() === '' && record.trim() === '') {
    return json({ error: 'missing_input', message: 'Enter a domain, or paste a record.' }, 400);
  }

  const ip = clientIp(request, clientAddress);
  const limit = await rateLimit(`spf:${ip}`);
  if (!limit.allowed) {
    return json(
      {
        error: 'rate_limited',
        message: `That is ${RATE_LIMIT.MAX_REQUESTS} checks in a minute. Wait ${limit.resetIn}s and try again.`,
        retryAfter: limit.resetIn,
      },
      429,
      { 'Retry-After': String(limit.resetIn) },
    );
  }

  try {
    const result = await countSpfLookups({ domain, record });

    track({
      path: '/api/spf-lookups',
      referrer: request.headers.get('referer'),
      userAgent: request.headers.get('user-agent'),
      clientIp: ip,
      selfHost: new URL(siteOrigin()).hostname,
      isCheck: true,
      viaApi: false,
    });

    return json(result);
  } catch (err) {
    if (err instanceof InvalidDomainError) return json({ error: 'invalid_domain', message: err.message }, 400);
    if (err instanceof InvalidRecordError) return json({ error: 'invalid_record', message: err.message }, 400);
    // The error only: checked domains and records are never logged.
    console.error('spf lookup counter failed', { err: String(err) });
    return json({ error: 'check_failed', message: 'The lookup could not be completed, usually a DNS timeout. Try again.' }, 502);
  }
};
