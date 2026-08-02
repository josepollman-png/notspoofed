import type { Finding } from '../findings.js';
import { bySeverity } from '../findings.js';
import type { BlocklistHit, IpCheckResult } from './check.js';

/**
 * Turns the raw IP check into findings.
 *
 * Two judgements do most of the work here, and both are about *not* crying wolf:
 *
 *   - A UCEPROTECT listing is not the same event as a Spamhaus SBL listing. Rendering
 *     both as "blacklisted" in red is how these tools train people to ignore them.
 *   - A Spamhaus PBL listing on a home connection is the system working as intended,
 *     not a reputation problem. The fix is to stop sending directly, not to appeal.
 */

function listingDetail(hit: BlocklistHit): string {
  return [
    hit.meaning,
    hit.reason && hit.reason !== hit.meaning ? `The list says: “${hit.reason}”` : null,
    hit.list.note,
  ]
    .filter(Boolean)
    .join(' ');
}

export function analyzeIp(result: IpCheckResult): Finding[] {
  const findings: Finding[] = [];
  const { ip, ptr, forwardConfirmed, genericPtr, listedOn, unavailable } = result;

  // --- Reverse DNS ---
  if (ptr.length === 0) {
    findings.push({
      id: 'ip-no-ptr',
      severity: 'critical',
      title: 'No reverse DNS',
      detail:
        `${ip} has no PTR record. Google and Yahoo both require a valid reverse DNS ` +
        'entry on sending addresses, and many other providers reject or heavily penalise ' +
        'mail from an address without one. This is one of the few requirements that is ' +
        'checked before your message content is even considered.',
      fix: {
        kind: 'action',
        steps: [
          'Reverse DNS is set by whoever owns the IP address — your hosting provider or ISP, not in your own DNS.',
          'Ask them to set a PTR record for this address pointing at your mail hostname, e.g. mail.yourdomain.com.',
          'Then make sure that hostname has a forward A record pointing back to this same IP.',
        ],
      },
    });
  } else if (!forwardConfirmed) {
    findings.push({
      id: 'ip-ptr-not-confirmed',
      severity: 'warning',
      title: 'Reverse DNS does not confirm forward',
      detail:
        `${ip} points at ${ptr.join(', ')}, but that name does not resolve back to this ` +
        'address. Receivers check both directions — a PTR on its own proves nothing, ' +
        'since anyone can point one anywhere. Only a matching pair counts.',
      fix: {
        kind: 'action',
        steps: [
          `Add an A record for ${ptr[0]} pointing to ${ip}.`,
          'If the hostname belongs to someone else, ask your provider to change the PTR to a name you control.',
        ],
      },
    });
  } else if (genericPtr) {
    findings.push({
      id: 'ip-ptr-generic',
      severity: 'warning',
      title: 'Reverse DNS looks auto-generated',
      detail:
        `${ptr.join(', ')} looks like a default name assigned by the network rather than ` +
        'a mail hostname you chose — it embeds the IP address or advertises a dynamic ' +
        'pool. Receivers treat that as a strong signal the address is not a legitimate ' +
        'mail server, and it is a common reason mail from an otherwise clean IP lands in spam.',
      fix: {
        kind: 'action',
        steps: [
          'Ask your provider to set the PTR to a real hostname, e.g. mail.yourdomain.com.',
          'Point that hostname at this IP with an A record so it forward-confirms.',
          'Use the same name in your mail server’s HELO/EHLO greeting.',
        ],
      },
    });
  } else {
    findings.push({
      id: 'ip-ptr-ok',
      severity: 'pass',
      title: 'Reverse DNS is set and forward-confirmed',
      detail: `${ip} resolves to ${ptr.join(', ')}, which resolves back to this address.`,
    });
  }

  // --- Blocklists ---
  const major = listedOn.filter((h) => h.list.weight === 'major');
  const secondary = listedOn.filter((h) => h.list.weight === 'secondary');
  const informational = listedOn.filter((h) => h.list.weight === 'informational');

  // A PBL listing is a policy statement about the range, not a reputation problem.
  const pblOnly =
    major.length > 0 &&
    major.every((h) => h.code === '127.0.0.10' || h.code === '127.0.0.11');

  if (major.length > 0 && !pblOnly) {
    findings.push({
      id: 'ip-blocklisted-major',
      severity: 'critical',
      title: `Listed on ${major.map((h) => h.list.name).join(', ')}`,
      detail:
        `${ip} appears on ${major.length === 1 ? 'a major blocklist' : 'major blocklists'} ` +
        'used by a large share of the world’s mail servers. Mail from this address is ' +
        'being rejected or filed as spam right now. ' +
        major.map(listingDetail).join(' '),
      fix: {
        kind: 'action',
        steps: [
          'Find and stop the cause first — a compromised account, an open relay, or a mailing list sent without consent. Delisting before fixing it gets you relisted within days.',
          ...major.map((h) => `Request removal from ${h.list.name}: ${h.list.delistUrl}`),
          'If this is shared hosting, the listing may belong to a neighbour on the same IP. Ask your provider, or move to a dedicated sending address.',
        ],
      },
    });
  } else if (pblOnly) {
    findings.push({
      id: 'ip-blocklisted-major',
      severity: 'warning',
      title: 'Listed on the Spamhaus Policy Block List (PBL)',
      detail:
        'This is a policy listing, not an accusation. Spamhaus PBL marks address ranges ' +
        'whose owner has stated they should not be sending mail directly — home broadband, ' +
        'mobile and most cloud ranges are listed by default. It is expected here; what it ' +
        'means is that this address should relay through a proper mail service rather than ' +
        'delivering to the internet itself.',
      fix: {
        kind: 'action',
        steps: [
          'Send through your provider’s outbound relay or a transactional mail service instead of connecting to recipients directly.',
          'Only request PBL removal if this genuinely is a dedicated mail server on a static address — and expect to justify it.',
        ],
      },
    });
  }

  if (secondary.length > 0) {
    findings.push({
      id: 'ip-blocklisted-secondary',
      severity: 'warning',
      title: `Listed on ${secondary.map((h) => h.list.name).join(', ')}`,
      detail:
        'These lists have narrower adoption than Spamhaus or Barracuda, so the impact is ' +
        'smaller — but a listing is still a signal that something sent from this address ' +
        'was reported. ' + secondary.map(listingDetail).join(' '),
      fix: {
        kind: 'action',
        steps: secondary.map((h) => `${h.list.name} removal: ${h.list.delistUrl}`),
      },
    });
  }

  if (informational.length > 0) {
    findings.push({
      id: 'ip-blocklisted-informational',
      severity: 'info',
      title: `Listed on ${informational.map((h) => h.list.name).join(', ')}`,
      detail: informational.map(listingDetail).join(' '),
    });
  }

  if (unavailable.length > 0) {
    findings.push({
      id: 'ip-blocklist-unavailable',
      severity: 'info',
      title: `${unavailable.length} list${unavailable.length === 1 ? '' : 's'} could not be queried`,
      detail:
        `${unavailable.map((h) => `${h.list.name} (${h.reason})`).join('; ')}. ` +
        'This is not a clean result for those lists — we simply could not get an answer, ' +
        'so treat their status as unknown rather than assuming you are not listed.',
    });
  }

  if (result.version === 4 && listedOn.length === 0 && unavailable.length === 0) {
    findings.push({
      id: 'ip-not-listed',
      severity: 'pass',
      title: `Not listed on any of the ${result.blocklists.length} blocklists checked`,
      detail:
        'No listing found on the major lists. Bear in mind that dozens of smaller and ' +
        'private blocklists exist, and a mailbox provider’s own internal reputation ' +
        'scoring is invisible from outside — a clean result here does not guarantee delivery.',
    });
  }

  if (result.version === 6) {
    findings.push({
      id: 'ip-ipv6-limited',
      severity: 'info',
      title: 'Blocklist checks are IPv4 only',
      detail:
        'Most DNSBLs do not carry IPv6 data, so querying them with this address would ' +
        'return silence that is indistinguishable from a clean result. Reverse DNS has ' +
        'still been checked above. If you send over both, check the IPv4 address too.',
    });
  }

  return findings.sort(bySeverity);
}
