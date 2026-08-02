import { defineMiddleware } from 'astro:middleware';
import { clientIp } from './lib/ratelimit.js';
import { siteOrigin } from './lib/site.js';
import { botName, track } from './lib/stats.js';
import { sendUmami } from './lib/umami.js';

/** Requests that are not page views: assets, machine endpoints, and the check routes
 *  (which record themselves from the handler, where success is actually known). */
const IGNORED = /^\/(_astro|_image|favicon|robots\.txt|sitemap\.xml|check|api\/check|stats|healthz)/;

export const onRequest = defineMiddleware(async (context, next) => {
  const response = await next();

  // Only count successfully served HTML. Counting 404s and redirects would make
  // "views" a measure of crawler noise rather than readers.
  if (
    context.request.method === 'GET' &&
    response.status === 200 &&
    !IGNORED.test(context.url.pathname) &&
    (response.headers.get('content-type') ?? '').includes('text/html')
  ) {
    const referrer = context.request.headers.get('referer');
    const userAgent = context.request.headers.get('user-agent');
    const selfHost = new URL(siteOrigin()).hostname;

    track({
      path: context.url.pathname,
      referrer,
      userAgent,
      utmSource: context.url.searchParams.get('utm_source'),
      selfHost,
    });

    // Umami gets the same visit for the richer dashboard. The two are independent:
    // the Redis counters hold the funnel metric and survive Umami being down.
    //
    // Crawlers are withheld. Umami does its own user-agent filtering, but it only
    // catches bots that identify themselves — scanners presenting a plausible Chrome
    // string sail straight through and inflate the visitor count on a new domain,
    // which is exactly when the number is most likely to be believed. Applying the
    // same filter the Redis counters use keeps the two in agreement.
    if (!botName(userAgent)) sendUmami({
      // Path only — the query string can carry a checked domain or an email address.
      url: context.url.pathname,
      referrer,
      userAgent,
      clientIp: clientIp(context.request, context.clientAddress),
      hostname: selfHost,
    });
  }

  return response;
});
