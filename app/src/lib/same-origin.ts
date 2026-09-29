import { siteOrigin } from './site.js';

/**
 * Same-origin, three ways.
 *
 * `Sec-Fetch-Site` is what modern browsers send and cannot be set by a page. `Origin`
 * is sent on cross-origin requests and by `fetch` from our own page. `Referer` is the
 * fallback for anything older. Any one of them naming this site is enough; none of them
 * naming anything is not — a bare `curl` is exactly the caller this is meant to refuse.
 */
export function isSameOrigin(request: Request): boolean {
  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite === 'same-origin') return true;
  if (fetchSite && fetchSite !== 'none') return false;

  const self = new URL(siteOrigin()).hostname;
  for (const header of ['origin', 'referer']) {
    const value = request.headers.get(header);
    if (!value) continue;
    try {
      return new URL(value).hostname === self;
    } catch {
      return false;
    }
  }
  return false;
}
