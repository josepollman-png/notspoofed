/**
 * DNSBL registry.
 *
 * Every zone here was verified to answer correctly for `127.0.0.2` (the standard
 * "always listed" probe) *and* to stay silent for `127.0.0.1`. A list that answers for
 * everything, or for nothing, is worse than no list — and `dnsbl.sorbs.net`, which is
 * still shipped by half the blocklist checkers on the internet, was retired in 2024 and
 * answers nothing. It is deliberately absent.
 *
 * `weight` matters as much as membership. Being on Spamhaus SBL is a genuine
 * deliverability emergency; being on UCEPROTECT level 1 often just means you share a /24
 * with someone careless, and they charge to remove you. Reporting both as "blacklisted"
 * in red manufactures alarm and teaches people to ignore the tool.
 */

export type BlocklistWeight = 'major' | 'secondary' | 'informational';

export interface Blocklist {
  zone: string;
  name: string;
  weight: BlocklistWeight;
  /** Where a human goes to request removal. */
  delistUrl: string;
  /** Shown alongside a hit when the listing needs interpreting. */
  note?: string;
}

export const BLOCKLISTS: readonly Blocklist[] = [
  {
    zone: 'zen.spamhaus.org',
    name: 'Spamhaus ZEN',
    weight: 'major',
    delistUrl: 'https://check.spamhaus.org/',
    note: 'The most widely used list in existence. A listing here affects delivery almost everywhere.',
  },
  {
    zone: 'b.barracudacentral.org',
    name: 'Barracuda',
    weight: 'major',
    delistUrl: 'https://www.barracudacentral.org/rbl/removal-request',
  },
  {
    zone: 'bl.spamcop.net',
    name: 'SpamCop',
    weight: 'major',
    delistUrl: 'https://www.spamcop.net/bl.shtml',
    note: 'Listings expire automatically, usually within 24 hours of the reports stopping.',
  },
  {
    zone: 'cbl.abuseat.org',
    name: 'CBL (Abuseat)',
    weight: 'major',
    delistUrl: 'https://www.abuseat.org/lookup.cgi',
    note: 'Indicates the machine appears compromised or is running a spam-sending process.',
  },
  {
    zone: 'psbl.surriel.com',
    name: 'PSBL',
    weight: 'secondary',
    delistUrl: 'https://psbl.org/remove',
  },
  {
    zone: 'truncate.gbudb.net',
    name: 'GBUdb Truncate',
    weight: 'secondary',
    delistUrl: 'https://www.gbudb.com/truncate/index.jsp',
  },
  {
    zone: 'all.s5h.net',
    name: 's5h.net',
    weight: 'secondary',
    delistUrl: 'https://www.usenix.org.uk/content/rbl.html',
  },
  {
    zone: 'dnsbl-1.uceprotect.net',
    name: 'UCEPROTECT Level 1',
    weight: 'informational',
    delistUrl: 'https://www.uceprotect.net/en/rblcheck.php',
    note:
      'UCEPROTECT lists aggressively, sometimes whole network ranges, and charges for ' +
      'expedited removal. Many mail providers ignore it. Treat a listing here as a hint, ' +
      'not an emergency.',
  },
];

/**
 * Spamhaus encodes the *reason* in the returned address. The distinction that matters
 * to a human is PBL versus everything else: PBL is a policy statement ("this range
 * should not be sending mail directly"), not an accusation. A home broadband connection
 * is PBL-listed by design, and the fix is to relay through your provider rather than to
 * request removal.
 */
export function describeSpamhausCode(address: string): string | null {
  switch (address) {
    case '127.0.0.2': return 'SBL — the address is on Spamhaus’s spam source list.';
    case '127.0.0.3': return 'SBL CSS — snowshoe or low-reputation bulk sending detected.';
    case '127.0.0.4':
    case '127.0.0.5':
    case '127.0.0.6':
    case '127.0.0.7': return 'XBL — the machine appears compromised or is running an open proxy.';
    case '127.0.0.9': return 'SBL DROP — the whole netblock is considered hijacked or spam-only.';
    case '127.0.0.10':
    case '127.0.0.11':
      return 'PBL — a *policy* listing: this range is not meant to send mail directly. ' +
        'Normal for home and mobile connections. Relay through your provider rather than requesting removal.';
    default: return null;
  }
}

/** 127.255.255.x is not a listing — it is the list telling you the query was rejected. */
export function isRefusalCode(address: string): boolean {
  return address.startsWith('127.255.255.');
}

export function describeRefusal(address: string): string {
  switch (address) {
    case '127.255.255.252': return 'the query was malformed';
    case '127.255.255.254': return 'queries from public DNS resolvers are not permitted';
    case '127.255.255.255': return 'the query volume limit was exceeded';
    default: return 'the list refused the query';
  }
}
