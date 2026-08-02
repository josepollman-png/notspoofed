import { getDomain } from 'tldts';
import type { Finding } from '../findings.js';
import { bySeverity } from '../findings.js';
import type { AuthMethod, ParsedHeaders } from './parse.js';
import { domainOf } from './parse.js';

/**
 * Alignment analysis — the reason this tool exists.
 *
 * Every header viewer shows you `spf=pass dkim=pass dmarc=fail` and leaves you to work
 * out how all three can be true at once. The answer is alignment, and it is the single
 * most misunderstood thing in email authentication:
 *
 *   Passing SPF is not enough. The domain that *passed* SPF must also match the domain
 *   in the From: header your recipient actually sees.
 *
 * A vendor sending on your behalf with their own envelope domain passes SPF for
 * themselves, shows your name in From:, and fails DMARC — with no obvious error
 * anywhere. This module names that situation explicitly.
 */

export type Alignment = 'strict' | 'relaxed' | 'none';

export interface AlignmentCheck {
  /** The domain that authenticated, e.g. the SPF envelope domain or DKIM d=. */
  authenticatedDomain?: string;
  fromDomain?: string;
  result?: string;
  alignment: Alignment;
}

export interface HeaderAnalysis {
  spf: AlignmentCheck;
  dkim: AlignmentCheck[];
  dmarcResult?: string;
  /** True when no Authentication-Results header was present at all. */
  unverified: boolean;
  findings: Finding[];
}

/** RFC 7489 §3.1 — strict requires an exact match, relaxed only the org domain. */
export function alignmentOf(authDomain?: string, fromDomain?: string): Alignment {
  if (!authDomain || !fromDomain) return 'none';
  const a = authDomain.toLowerCase().replace(/\.$/, '');
  const f = fromDomain.toLowerCase().replace(/\.$/, '');
  if (a === f) return 'strict';

  const orgA = getDomain(a);
  const orgF = getDomain(f);
  return orgA && orgF && orgA === orgF ? 'relaxed' : 'none';
}

const methodNamed = (methods: AuthMethod[], name: string): AuthMethod | undefined =>
  methods.find((m) => m.method === name);

/** A single hop taking longer than this is worth pointing at. */
const SLOW_HOP_SECONDS = 60;

export function analyzeHeaders(parsed: ParsedHeaders): HeaderAnalysis {
  const findings: Finding[] = [];
  const methods = parsed.auth.flatMap((a) => a.methods);
  const unverified = parsed.auth.length === 0;

  const from = parsed.fromDomain;

  // --- SPF ---
  const spfMethod = methodNamed(methods, 'spf');
  const spfDomain =
    domainOf(spfMethod?.properties['smtp.mailfrom']) ??
    spfMethod?.properties['smtp.helo'] ??
    parsed.returnPathDomain;

  const spf: AlignmentCheck = {
    authenticatedDomain: spfDomain,
    fromDomain: from,
    result: spfMethod?.result,
    alignment: alignmentOf(spfDomain, from),
  };

  // --- DKIM ---
  const dkimMethods = methods.filter((m) => m.method === 'dkim');
  const dkim: AlignmentCheck[] = dkimMethods.length
    ? dkimMethods.map((m) => {
        const d = m.properties['header.d'] ?? domainOf(m.properties['header.i']);
        return {
          authenticatedDomain: d,
          fromDomain: from,
          result: m.result,
          alignment: alignmentOf(d, from),
        };
      })
    : // No verdicts available: fall back to the signatures themselves, which tell us
      // what was *claimed* but not whether it verified.
      parsed.dkim.map((sig) => ({
        authenticatedDomain: sig.domain,
        fromDomain: from,
        result: undefined,
        alignment: alignmentOf(sig.domain, from),
      }));

  const dmarcResult = methodNamed(methods, 'dmarc')?.result;

  // -------------------------------------------------------------------------

  if (unverified) {
    findings.push({
      id: 'header-no-auth-results',
      severity: 'warning',
      title: 'No Authentication-Results header',
      detail:
        'Nothing in these headers records whether SPF, DKIM or DMARC actually passed — ' +
        'that verdict is added by the *receiving* server. You are most likely looking at ' +
        'a copy from your Sent folder rather than one that was delivered. Send a message ' +
        'to an address you can open and use the headers from there instead.',
      fix: {
        kind: 'action',
        steps: [
          'Send a test message to a mailbox you control at a different provider.',
          'Open the delivered copy and use "Show original" (Gmail) or "View source" to copy its headers.',
        ],
      },
    });
  }

  if (parsed.hops.length === 0) {
    findings.push({
      id: 'header-no-received',
      severity: 'info',
      title: 'No Received headers',
      detail:
        'Without a Received chain there is no delivery path to trace. This usually means ' +
        'the headers were truncated when copied, or came from a message that was never sent.',
    });
  }

  const alignedDkim = dkim.filter((d) => d.alignment !== 'none' && d.result !== 'fail');
  const spfAligned = spf.alignment !== 'none' && spf.result === 'pass';

  if (dmarcResult === 'pass') {
    findings.push({
      id: 'header-dmarc-pass',
      severity: 'pass',
      title: 'DMARC passed',
      detail:
        `The receiving server accepted this message as genuinely from ${from ?? 'the From domain'}` +
        (alignedDkim.length > 0 && spfAligned
          ? ', authenticated by both SPF and DKIM.'
          : alignedDkim.length > 0
            ? ', authenticated by an aligned DKIM signature.'
            : spfAligned
              ? ', authenticated by an aligned SPF pass.'
              : '.'),
    });
  } else if (dmarcResult && dmarcResult !== 'none') {
    findings.push({
      id: 'header-dmarc-fail',
      severity: 'critical',
      title: `DMARC ${dmarcResult}`,
      detail:
        'The receiving server could not confirm this message genuinely came from ' +
        `${from ?? 'the From domain'}. Depending on that domain's policy, mail like this ` +
        'is delivered to spam or rejected outright. The findings below explain which ' +
        'part of the chain broke.',
    });
  }

  // The heart of it: SPF passed, but for the wrong domain.
  if (spf.result === 'pass' && spf.alignment === 'none' && spfDomain && from) {
    findings.push({
      id: 'header-spf-not-aligned',
      severity: alignedDkim.length > 0 ? 'info' : 'critical',
      title: 'SPF passed, but not for the From domain',
      detail:
        `SPF authenticated ${spfDomain}, which is the envelope sender. Your recipient ` +
        `sees ${from} in the From: header. DMARC requires those to match, so this SPF ` +
        'pass does nothing for DMARC — this is the single most common reason a domain ' +
        'that "has SPF" still fails.' +
        (alignedDkim.length > 0
          ? ' It is not causing a failure here, because an aligned DKIM signature is carrying the message.'
          : ' Nothing else is carrying the message, so DMARC fails.'),
      fix: {
        kind: 'action',
        steps: [
          `Set up DKIM signing at whoever sends this mail, using d=${from} rather than their own domain.`,
          'DKIM alignment is the reliable fix — it also survives forwarding, which SPF never does.',
          'Alternatively, configure a custom return-path (sometimes called a custom bounce domain) on your sending platform.',
        ],
      },
    });
  } else if (spf.result === 'fail' || spf.result === 'softfail') {
    findings.push({
      id: 'header-spf-fail',
      severity: alignedDkim.length > 0 ? 'warning' : 'critical',
      title: `SPF ${spf.result}`,
      detail:
        `The sending server was not authorised by the SPF record for ${spfDomain ?? 'the envelope domain'}. ` +
        'Either the sender is not listed, or the message was forwarded — forwarding breaks ' +
        'SPF by design, because the forwarding server is not in the original SPF record.',
    });
  }

  const misalignedDkim = dkim.filter((d) => d.alignment === 'none' && d.authenticatedDomain);
  if (misalignedDkim.length > 0 && alignedDkim.length === 0) {
    findings.push({
      id: 'header-dkim-not-aligned',
      severity: 'warning',
      title: 'DKIM signature does not match the From domain',
      detail:
        `The message is signed by ${misalignedDkim.map((d) => d.authenticatedDomain).join(', ')}, ` +
        `but the From: header says ${from}. A valid signature from someone else's domain ` +
        'does not satisfy DMARC — the signing domain has to be yours.',
    });
  }

  if (dkim.some((d) => d.result === 'fail')) {
    findings.push({
      id: 'header-dkim-fail',
      severity: 'warning',
      title: 'A DKIM signature failed to verify',
      detail:
        'The signature did not match the message body or headers. The usual causes are a ' +
        'mailing list or gateway modifying the message in transit, a key rotated before ' +
        'the message was delivered, or a revoked selector.',
    });
  }

  if (parsed.dkim.length === 0 && dkimMethods.length === 0) {
    findings.push({
      id: 'header-no-dkim',
      severity: 'warning',
      title: 'Message is not DKIM signed',
      detail:
        'There is no DKIM-Signature header. That leaves SPF as the only thing that can ' +
        'authenticate this mail, and SPF breaks whenever a message is forwarded. Google ' +
        'and Yahoo both expect DKIM from bulk senders.',
    });
  }

  if (methods.some((m) => m.method === 'arc')) {
    findings.push({
      id: 'header-arc-present',
      severity: 'info',
      title: 'ARC headers present',
      detail:
        'This message passed through an intermediary — typically a mailing list or a ' +
        'forwarder — that sealed the original authentication results with ARC. If SPF ' +
        'fails but ARC is intact, forwarding is the likely explanation rather than forgery.',
    });
  }

  const slowest = [...parsed.hops].sort((a, b) => (b.delaySeconds ?? 0) - (a.delaySeconds ?? 0))[0];
  if (slowest?.delaySeconds && slowest.delaySeconds > SLOW_HOP_SECONDS) {
    findings.push({
      id: 'header-slow-hop',
      severity: 'info',
      title: `A single hop took ${formatDuration(slowest.delaySeconds)}`,
      detail:
        `Hop ${slowest.index}${slowest.by ? ` (${slowest.by})` : ''} held the message for ` +
        `${formatDuration(slowest.delaySeconds)}. Long single-hop delays usually mean greylisting ` +
        'or a queue backlog at that server, not a problem with your DNS records.',
    });
  }

  if (parsed.replyTo && parsed.from && parsed.replyTo !== parsed.from) {
    const replyDomain = domainOf(parsed.replyTo);
    findings.push({
      id: 'header-reply-to-differs',
      severity: alignmentOf(replyDomain, from) === 'none' ? 'warning' : 'info',
      title: 'Reply-To points somewhere else',
      detail:
        `Replies go to ${parsed.replyTo}, not ${parsed.from}. This is legitimate for ` +
        'ticketing systems and mailing lists, but a Reply-To on an unrelated domain is ' +
        'also a standard phishing technique — worth confirming it is expected.',
    });
  }

  return { spf, dkim, dmarcResult, unverified, findings: findings.sort(bySeverity) };
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
