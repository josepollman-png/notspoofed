import { defineMiddleware } from 'astro:middleware';
import { clientIp } from './lib/ratelimit.js';
import { siteOrigin } from './lib/site.js';
import { botName, track, trafficContext } from './lib/stats.js';
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
    const ip = clientIp(context.request, context.clientAddress);

    // Detached: resolving the origin AS is a DNS query — cached per /24 for a week, but
    // still not something a visitor should wait behind for a number nobody reads in real
    // time. Resolved once here and handed to both consumers, so a request costs at most
    // one lookup no matter how many things want the verdict.
    void (async () => {
      const traffic = await trafficContext(ip);

      track(
        {
          path: context.url.pathname,
          referrer,
          userAgent,
          clientIp: ip,
          utmSource: context.url.searchParams.get('utm_source'),
          selfHost,
        },
        traffic,
      );

      // Umami gets the same visit for the richer dashboard. The two are independent:
      // the Redis counters hold the funnel metric and survive Umami being down.
      //
      // Crawlers are withheld by both filters. Umami has user-agent matching of its own,
      // but it never runs — the page loads no script, so the event is posted from here
      // and whatever this gate decides *is* what the dashboard shows. It has to apply
      // the same test the counters do, or the two stop agreeing.
      if (!botName(userAgent) && !traffic.fromDatacenter) {
        sendUmami({
          // Path only — the query string can carry a checked domain or an email address.
          url: context.url.pathname,
          referrer,
          userAgent,
          clientIp: ip,
          hostname: selfHost,
        });
      }
    })();
  }

  return response;
});
