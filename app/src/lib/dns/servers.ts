import { lookup } from 'node:dns/promises';

/**
 * Which nameservers the checker talks to.
 *
 * Public resolvers are fine for ordinary record lookups but not for DNSBLs: Spamhaus
 * refuses queries arriving via an open resolver and answers `127.255.255.254`
 * ("Error: open resolver") instead of a verdict. That silently removes the two most
 * important blocklists from the results.
 *
 * The fix is a recursive resolver of our own. `setServers` takes IP addresses, not
 * hostnames, so the container name has to be resolved through the system resolver
 * first — Docker's embedded DNS handles that from inside the network.
 */

const PUBLIC_FALLBACK = ['1.1.1.1', '8.8.8.8'];

let cached: Promise<string[]> | null = null;

async function discover(): Promise<string[]> {
  const host = process.env.DNS_RESOLVER_HOST?.trim();
  if (!host) return PUBLIC_FALLBACK;

  try {
    const { address } = await lookup(host, { family: 4 });
    // Public resolvers stay on the list as backups. c-ares moves to the next server
    // when one is unreachable, so a dead Unbound degrades the blocklist checks
    // rather than taking the whole site down.
    return [address, ...PUBLIC_FALLBACK];
  } catch {
    return PUBLIC_FALLBACK;
  }
}

/** Resolved once per process; the container's address does not change under it. */
export function resolverAddresses(): Promise<string[]> {
  cached ??= discover();
  return cached;
}
