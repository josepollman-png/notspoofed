import Redis from 'ioredis';

/**
 * One lazily-created Redis connection shared by rate limiting and stats.
 *
 * Both callers must survive Redis being unavailable — a metrics backend outage should
 * never take down a checker — so this returns null rather than throwing, and marks the
 * connection dead on first error instead of retrying on every request.
 */

let client: Redis | null = null;
let dead = false;

export function redis(): Redis | null {
  if (dead) return null;
  if (client) return client;

  const url = process.env.REDIS_URL;
  if (!url) { dead = true; return null; }

  client = new Redis(url, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    connectTimeout: 1000,
    retryStrategy: () => null,
  });
  client.on('error', () => { dead = true; });
  return client;
}

export function markRedisDead(): void {
  dead = true;
}
