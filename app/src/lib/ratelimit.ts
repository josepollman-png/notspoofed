import { markRedisDead, redis } from './redis.js';

/**
 * Fixed-window rate limiting, backed by the Redis already running in the stack.
 *
 * This endpoint issues up to ~60 outbound DNS queries per request on a name the
 * caller chooses. Unlimited, that is a free DNS scanner with our IP on it. The limit
 * is the difference between a public tool and an open relay.
 *
 * If Redis is unreachable we fall back to an in-process counter rather than failing
 * open. That is weaker across multiple workers, but "degraded" beats "unlimited".
 */

const WINDOW_SECONDS = 60;
const MAX_REQUESTS = 10;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  /** Seconds until the window resets. */
  resetIn: number;
}

/** Fallback store. Bounded so a flood of distinct IPs cannot exhaust memory. */
const memory = new Map<string, { count: number; expiresAt: number }>();
const MEMORY_MAX_KEYS = 10_000;

function memoryLimit(key: string, now: number): RateLimitResult {
  if (memory.size > MEMORY_MAX_KEYS) {
    for (const [k, v] of memory) if (v.expiresAt <= now) memory.delete(k);
    if (memory.size > MEMORY_MAX_KEYS) memory.clear();
  }

  const entry = memory.get(key);
  if (!entry || entry.expiresAt <= now) {
    memory.set(key, { count: 1, expiresAt: now + WINDOW_SECONDS * 1000 });
    return { allowed: true, remaining: MAX_REQUESTS - 1, resetIn: WINDOW_SECONDS };
  }

  entry.count++;
  return {
    allowed: entry.count <= MAX_REQUESTS,
    remaining: Math.max(0, MAX_REQUESTS - entry.count),
    resetIn: Math.ceil((entry.expiresAt - now) / 1000),
  };
}

export async function rateLimit(identifier: string): Promise<RateLimitResult> {
  const now = Date.now();
  const window = Math.floor(now / (WINDOW_SECONDS * 1000));
  const key = `mailcheck:rl:${identifier}:${window}`;

  const r = redis();
  if (!r) return memoryLimit(identifier, now);

  try {
    const [[, count]] = (await r
      .multi()
      .incr(key)
      .expire(key, WINDOW_SECONDS)
      .exec()) as [[Error | null, number], unknown];

    return {
      allowed: count <= MAX_REQUESTS,
      remaining: Math.max(0, MAX_REQUESTS - count),
      resetIn: WINDOW_SECONDS - Math.floor((now / 1000) % WINDOW_SECONDS),
    };
  } catch {
    markRedisDead();
    return memoryLimit(identifier, now);
  }
}

/**
 * The caller's address. Behind Caddy the socket address is always the proxy, so the
 * forwarded header is authoritative — but only because Caddy sets it itself and
 * overwrites anything the client sent. Exposed directly to the internet this would
 * be trivially spoofable.
 */
export function clientIp(request: Request, fallback?: string): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded.split(',')[0]?.trim();
    if (first) return first;
  }
  return request.headers.get('x-real-ip') ?? fallback ?? 'unknown';
}

export const RATE_LIMIT = { WINDOW_SECONDS, MAX_REQUESTS };
