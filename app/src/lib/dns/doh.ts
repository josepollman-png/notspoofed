/**
 * Minimal DNS-over-HTTPS client, used only for record types Node cannot query.
 *
 * `dns.Resolver.resolve()` supports A, AAAA, ANY, CAA, CNAME, MX, NAPTR, NS, PTR,
 * SOA, SRV and TXT — and nothing else. DNSSEC detection needs DS records, which live
 * in the *parent* zone and have no Node binding, so this is the only way to reach
 * them without shelling out to dig or pulling in a full DNS library.
 *
 * Everything else in the app deliberately stays on native UDP DNS: it is faster, it
 * needs no third party in the path, and it counts lookups the way a real evaluator
 * would.
 */

const ENDPOINT = 'https://cloudflare-dns.com/dns-query';

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  /** DNS RCODE. 0 = NOERROR, 3 = NXDOMAIN. */
  Status: number;
  /** Authenticated Data — the resolver DNSSEC-validated this answer. */
  AD: boolean;
  Answer?: DohAnswer[];
}

export const RR = { DS: 43, DNSKEY: 48 } as const;

export async function dohQuery(
  name: string,
  type: number,
  timeoutMs = 5000,
): Promise<DohResponse | null> {
  const url = `${ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return (await res.json()) as DohResponse;
  } catch {
    // A DoH outage must degrade one optional check, never fail the whole report.
    return null;
  } finally {
    clearTimeout(timer);
  }
}
