import type { APIRoute } from 'astro';
import { InvalidDomainError } from '../../lib/check.js';
import {
  DomainDoesNotResolveError,
  findSelectors,
  normaliseCustomSelectors,
  normaliseFinderDomain,
  type FinderResult,
} from '../../lib/dkim/finder.js';
import { clientIp, rateLimit, RATE_LIMIT } from '../../lib/ratelimit.js';
import { markRedisDead, redis } from '../../lib/redis.js';
import { isSameOrigin } from '../../lib/same-origin.js';
import { siteOrigin } from '../../lib/site.js';
import { track } from '../../lib/stats.js';

/**
 * The DKIM selector finder's endpoint. Internal, and deliberately so.
 *
 * `/api/check` is a public API with open CORS because other people's tools calling it
 * is the point. This is different: a 273-selector sweep is a few hundred DNS queries
 * against a name the caller chooses, which is a DNS scanner if anyone can drive it. So
 * it answers only the tool page on this hostname — anything without our own Origin or
 * Referer gets a 403, not a 429, because it is not a client that has exceeded a limit,
 * it is a client that was never invited.
 *
 * The shape (path, `domain` and `selectors` query parameters, the JSON keys) is kept
 * stable and clean so it could be opened later behind a key without a rewrite. There is
 * no key handling here now, and there are no CORS headers. Do not add either casually.
 *
 * Results are cached for an hour per domain, in the Redis the stack already runs, with
 * an in-process fallback so a Redis outage degrades to "less caching" rather than
 * "no tool". The response says how old a cached result is, and `refresh=1` bypasses
 * the cache — through the same rate limit, so a re-check is bounded like a check.
 */

const CACHE_TTL_SECONDS = 3600;
const CACHE_PREFIX = 'mailcheck:dkimfinder:v1:';

interface Cached {
  result: FinderResult;
  storedAt: number;
}

/** In-process fallback. Bounded so a flood of distinct domains cannot exhaust memory. */
const memory = new Map<string, Cached>();
const MEMORY_MAX = 500;

function memoryGet(key: string): Cached | null {
  const hit = memory.get(key);
  if (!hit) return null;
  if (Date.now() - hit.storedAt > CACHE_TTL_SECONDS * 1000) {
    memory.delete(key);
    return null;
  }
  return hit;
}

function memorySet(key: string, value: Cached): void {
  if (memory.size >= MEMORY_MAX) {
    // Oldest first — Map iterates in insertion order.
    const oldest = memory.keys().next().value;
    if (oldest !== undefined) memory.delete(oldest);
  }
  memory.set(key, value);
}

async function cacheGet(key: string): Promise<Cached | null> {
  const r = redis();
  if (r) {
    try {
      const raw = await r.get(CACHE_PREFIX + key);
      if (raw) return JSON.parse(raw) as Cached;
      return null;
    } catch {
      markRedisDead();
    }
  }
  return memoryGet(key);
}

async function cacheSet(key: string, value: Cached): Promise<void> {
  const r = redis();
  if (r) {
    try {
      await r.set(CACHE_PREFIX + key, JSON.stringify(value), 'EX', CACHE_TTL_SECONDS);
      return;
    } catch {
      markRedisDead();
    }
  }
  memorySet(key, value);
}

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Robots-Tag': 'noindex, nofollow',
      // Our own cache carries the hour; the browser must not keep a copy that hides a
      // re-check.
      'Cache-Control': 'private, no-store',
      ...extra,
    },
  });

export const GET: APIRoute = async ({ request, url, clientAddress }) => {
  if (!isSameOrigin(request)) {
    return json({ error: 'forbidden', message: 'This endpoint serves the DKIM selector finder page only.' }, 403);
  }

  const domain = url.searchParams.get('domain')?.trim() ?? '';
  if (domain === '') return json({ error: 'missing_domain', message: 'Pass ?domain=example.com' }, 400);

  const customSelectors = (url.searchParams.get('selectors') ?? '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const refresh = url.searchParams.get('refresh') === '1';

  const ip = clientIp(request, clientAddress);
  const limit = await rateLimit(`dkim:${ip}`);
  if (!limit.allowed) {
    return json(
      {
        error: 'rate_limited',
        message: `That is ${RATE_LIMIT.MAX_REQUESTS} runs in a minute. Wait ${limit.resetIn}s and try again — results are cached for an hour, so a re-check of the same domain is rarely needed.`,
        retryAfter: limit.resetIn,
      },
      429,
      { 'Retry-After': String(limit.resetIn) },
    );
  }

  try {
    // Normalise first so the cache key is the canonical domain, not what was typed.
    const probe = await findSelectorsCached(domain, customSelectors, refresh);

    track({
      path: '/api/dkim-selectors',
      referrer: request.headers.get('referer'),
      userAgent: request.headers.get('user-agent'),
      clientIp: ip,
      selfHost: new URL(siteOrigin()).hostname,
      isCheck: true,
      viaApi: false,
    });

    return json(probe);
  } catch (err) {
    if (err instanceof InvalidDomainError) return json({ error: 'invalid_domain', message: err.message }, 400);
    if (err instanceof DomainDoesNotResolveError) return json({ error: 'unresolvable', message: err.message }, 400);
    // No domain: checked domains are never logged.
    console.error('dkim finder failed', { err });
    return json({ error: 'check_failed', message: 'The lookup could not be completed, usually a DNS timeout.' }, 502);
  }
};

async function findSelectorsCached(domain: string, customSelectors: string[], refresh: boolean) {
  // The finder normalises and validates; run it on the cache path too so an invalid
  // input never becomes a cache key.
  const canonical = normaliseFinderDomain(domain);
  const custom = normaliseCustomSelectors(customSelectors);
  const key = custom.length ? `${canonical}|${[...custom].sort().join(',')}` : canonical;

  if (!refresh) {
    const hit = await cacheGet(key);
    if (hit) {
      return { ...hit.result, cache: { hit: true, ageSeconds: Math.floor((Date.now() - hit.storedAt) / 1000) } };
    }
  }

  const result = await findSelectors(canonical, { customSelectors: custom });
  // A timed-out sweep is not worth an hour of authority.
  if (!result.timedOut) await cacheSet(key, { result, storedAt: Date.now() });
  return { ...result, cache: { hit: false, ageSeconds: 0 } };
}
