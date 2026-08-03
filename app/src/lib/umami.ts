/**
 * Server-side page views for Umami.
 *
 * Umami normally works by loading a script in the browser. We don't, because
 * `/about` tells visitors the site loads no JavaScript except the header analyzer,
 * and quietly breaking that on a page arguing for privacy would be worse than having
 * no dashboard.
 *
 * Its collect endpoint takes the same payload from a server, so the middleware posts
 * it directly. The visitor's IP and user-agent are forwarded because Umami hashes them
 * (with a daily-rotating salt) to count unique visitors — it does not store them raw,
 * and the whole thing lives on the same box, so nothing leaves the server either way.
 *
 * Disabled unless both env vars are set, so a missing website ID is a no-op rather
 * than an error on every request.
 */

const TIMEOUT_MS = 2000;

/**
 * The only query parameters ever forwarded, in the only order they are ever emitted.
 *
 * Umami parses these out of the URL into dedicated columns and its campaign reporting is
 * built on them, so without a passthrough a tagged link is indistinguishable from direct
 * traffic on the dashboard. The Redis counters see `utm_source` already, but one bucket
 * per source is not a campaign breakdown.
 *
 * An allow-list rather than a filter, because the alternative fails open: `/check`
 * carries the domain someone looked up in its query string, and a "strip the sensitive
 * ones" approach is one forgotten parameter away from publishing exactly the thing the
 * site promises it never records. Fixed order so two identical visits produce an
 * identical `url_query` and group together.
 */
const FORWARDED_PARAMS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'] as const;

/** Comfortably inside Umami's 255-char columns, and longer than any real campaign tag. */
const MAX_VALUE_LENGTH = 64;

/**
 * Campaign tags are labels someone typed into a link, so spaces, dots and slashes are all
 * ordinary. Anything outside this set means the value is not a campaign tag, and a
 * malformed one is dropped whole rather than scrubbed into something that looks real.
 */
const VALUE_PATTERN = /^[A-Za-z0-9 ._~+/-]+$/;

/**
 * Builds the query string to report, or `''`. Exported for tests: the allow-list is the
 * only thing standing between the analytics database and a checked domain.
 */
export function campaignQuery(params: URLSearchParams): string {
  const out = new URLSearchParams();

  for (const key of FORWARDED_PARAMS) {
    const raw = params.get(key)?.trim();
    if (!raw || raw.length > MAX_VALUE_LENGTH || !VALUE_PATTERN.test(raw)) continue;
    out.set(key, raw);
  }

  const query = out.toString();
  return query === '' ? '' : `?${query}`;
}

/**
 * Referrer with the query string removed.
 *
 * The `Referer` header is a whole URL, and Umami splits it into `referrer_path` and
 * `referrer_query` and stores both. A visitor reading a result at
 * `/check?domain=acme.com` who then clicks through to a guide sends that entire URL —
 * so the domain they looked up ends up in the analytics database, which is the one thing
 * the site promises never happens. It did: `domain=roundup-tracker.org&selectors=` was
 * sitting in `referrer_query` before this existed.
 *
 * Stripping only our own `/check` would be enough for that case and wrong in general:
 * an external referrer's query string can carry a search term, a session token, or a
 * webmail URL. Nothing downstream needs a query string to attribute a referral, so none
 * is ever sent. Origin and path only.
 */
export function safeReferrer(referrer: string | null): string | null {
  if (!referrer) return null;
  try {
    const url = new URL(referrer);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return `${url.origin}${url.pathname}`;
  } catch {
    // Not a URL we can reason about, so not a URL we forward.
    return null;
  }
}

export interface UmamiEvent {
  /** Path, plus at most the campaign tags from `campaignQuery`. Never the raw query
   *  string — it can carry a checked domain or an address. */
  url: string;
  referrer: string | null;
  userAgent: string | null;
  clientIp: string | null;
  hostname: string;
  title?: string;
}

export function umamiConfigured(): boolean {
  return Boolean(process.env.UMAMI_URL && process.env.UMAMI_WEBSITE_ID);
}

/**
 * Fire-and-forget. Never awaited by a request handler: analytics must not add latency
 * to a page, and an unreachable dashboard must not surface as an error to a visitor.
 */
export function sendUmami(event: UmamiEvent): void {
  const base = process.env.UMAMI_URL?.replace(/\/$/, '');
  const website = process.env.UMAMI_WEBSITE_ID;
  if (!base || !website) return;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    // Umami rejects collect requests without a User-Agent, and uses it for the
    // visitor hash and device breakdown.
    'User-Agent': event.userAgent ?? 'Mozilla/5.0 (unknown)',
  };
  // Without this Umami attributes every visit to the container's own address and
  // reports one visitor forever.
  if (event.clientIp) headers['X-Forwarded-For'] = event.clientIp;

  void fetch(`${base}/api/send`, {
    method: 'POST',
    headers,
    signal: controller.signal,
    body: JSON.stringify({
      type: 'event',
      payload: {
        website,
        hostname: event.hostname,
        url: event.url,
        // Sanitised here rather than at the call site: this is the only place a referrer
        // leaves the process, so it is the only place the guarantee can be enforced.
        referrer: safeReferrer(event.referrer) ?? '',
        title: event.title ?? '',
      },
    }),
  })
    .catch(() => {
      // Swallowed on purpose — see the note above.
    })
    .finally(() => clearTimeout(timer));
}
