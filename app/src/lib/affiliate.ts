/**
 * The one affiliate slot on the checker, off unless deliberately switched on.
 *
 * DMARC report monitoring is the single place this site's advice genuinely ends in "a
 * paid service does this better than a spreadsheet": we do not read aggregate reports
 * for anyone, and the reports are XML nobody should parse by hand. So when a domain is
 * at `p=none` (collecting reports but acting on nothing) or publishes no `rua=` address
 * at all, one line under the DMARC result names a service that does.
 *
 * The rules this file enforces rather than trusts:
 * - Off by default. Both `DMARC_AFFILIATE_ENABLED=1` and an https `DMARC_AFFILIATE_URL`
 *   are required; either missing and nothing renders.
 * - One line per result, never one per finding. A domain at p=none with no rua gets it
 *   once, under the p=none finding.
 * - A plain link, labelled as affiliate in words, with rel="sponsored noopener". No
 *   script, no pixel, no redirect through this site — the "no third-party scripts" rule
 *   holds with the slot switched on.
 * - Presentation only. Which findings exist is decided by the checker and is untouched;
 *   this reads the finding ids after the fact.
 */

export interface AffiliateLink {
  url: string;
}

export function dmarcAffiliate(): AffiliateLink | null {
  if (process.env.DMARC_AFFILIATE_ENABLED?.trim() !== '1') return null;
  const raw = process.env.DMARC_AFFILIATE_URL?.trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' ? { url: url.href } : null;
  } catch {
    return null;
  }
}

/** The finding the line sits under: p=none first, then a missing rua, else none. */
export function affiliateFindingId(ids: readonly string[]): string | null {
  if (ids.includes('dmarc-p-none')) return 'dmarc-p-none';
  if (ids.includes('dmarc-no-rua')) return 'dmarc-no-rua';
  return null;
}
