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

export interface UmamiEvent {
  /** Path only — never the query string, which can carry personal data. */
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
        referrer: event.referrer ?? '',
        title: event.title ?? '',
      },
    }),
  })
    .catch(() => {
      // Swallowed on purpose — see the note above.
    })
    .finally(() => clearTimeout(timer));
}
