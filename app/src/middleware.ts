import { defineMiddleware } from 'astro:middleware';
import { clientIp } from './lib/ratelimit.js';
import { siteOrigin } from './lib/site.js';
import { botName, track, trafficContext } from './lib/stats.js';
import { campaignQuery, sendUmami } from './lib/umami.js';

/** Requests that are not page views: assets, machine endpoints, and the check routes
 *  (which record themselves from the handler, where success is actually known). */
const IGNORED = /^\/(_astro|_image|favicon|robots\.txt|sitemap\.xml|check|api\/check|stats|healthz)/;

/**
 * One URL per page: strip a trailing slash with a single 301.
 *
 * Astro's default `trailingSlash: 'ignore'` served `/about` and `/about/` — and every
 * other page — as two live 200s. The canonical tag named one of them, but a canonical is
 * a hint; two crawlable URLs per page is still two URLs splitting one page's signals.
 * The Next app on this hostname already 308s the same shape, so this makes the two
 * halves agree.
 *
 * `/guides/<slug>/` is deliberately left alone. Its route redirects straight to
 * `/guide/<slug>` in one hop; stripping the slash here first would turn that into
 * `/guides/x/` → `/guides/x` → `/guide/x`, a chain.
 */
function withoutTrailingSlash(pathname: string): string | null {
  if (pathname === '/' || !pathname.endsWith('/')) return null;
  if (/^\/guides\/[^/]+\/$/.test(pathname)) return null;
  return pathname.replace(/\/+$/, '') || '/';
}

export const onRequest = defineMiddleware(async (context, next) => {
  const stripped = withoutTrailingSlash(context.url.pathname);
  if (stripped && (context.request.method === 'GET' || context.request.method === 'HEAD')) {
    return new Response(null, {
      status: 301,
      headers: { Location: `${stripped}${context.url.search}` },
    });
  }

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
          // Path, plus campaign tags and nothing else — `campaignQuery` allow-lists the
          // five utm_* parameters, so the raw query string never reaches the dashboard.
          url: `${context.url.pathname}${campaignQuery(context.url.searchParams)}`,
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
