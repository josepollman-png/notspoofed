import type { DkimResult } from './dkim/check.js';
import { UNGUESSABLE_PROVIDERS } from './dkim/selectors.js';
import type { DmarcResult } from './dmarc/check.js';
import type { MxRecord } from './dns/resolver.js';
import type { BimiResult, DnssecResult, MtaStsResult, TlsRptResult } from './modern/check.js';
import type { Finding, FindingId } from './findings.js';
import { bySeverity } from './findings.js';
import type { SpfEvaluation } from './spf/evaluate.js';
import { LOOKUP_LIMIT } from './spf/evaluate.js';
import type { FlattenPlan } from './spf/flatten.js';

/**
 * Turns raw check output into findings a non-expert can act on.
 *
 * The rule this file follows: **every finding ends in something the user can do.**
 * If we cannot say what to do about a condition, we do not raise it — an unactionable
 * warning is just anxiety. Where the fix is a DNS record, it is emitted complete and
 * ready to paste, because "your SPF record exceeds the lookup limit" is the part
 * everyone already gets right and "here is the record that fixes it" is the part
 * nobody does.
 *
 * Where a recommendation could break live mail, it carries a caveat. We would rather
 * lose the upsell than be the reason someone's invoices stop arriving.
 */

export interface CheckInput {
  domain: string;
  spf: SpfEvaluation;
  flatten: FlattenPlan | null;
  dkim: DkimResult;
  dmarc: DmarcResult;
  mtaSts: MtaStsResult;
  tlsRpt: TlsRptResult;
  bimi: BimiResult;
  dnssec: DnssecResult;
  mx: MxRecord[];
  nullMx: boolean;
}

/**
 * A domain publishing `v=spf1 -all` with no senders, and often a null MX, is not
 * misconfigured — it is deliberately declaring that it neither sends nor receives.
 * Parked domains, brand-protection registrations and web-only domains should all
 * look like this. Warning them about missing DKIM is a false alarm, and false alarms
 * are how a checker teaches people to ignore it.
 */
function isNonSending(input: CheckInput): boolean {
  return input.spf.sendsNoMail;
}

// ---------------------------------------------------------------------------
// SPF
// ---------------------------------------------------------------------------

function spfFindings({ domain, spf, flatten }: CheckInput): Finding[] {
  const out: Finding[] = [];

  if (!spf.found) {
    out.push({
      id: 'spf-missing',
      severity: 'critical',
      title: 'No SPF record',
      detail:
        `${domain} does not tell receiving servers which systems may send mail as it. ` +
        'Anyone can put your domain in the From address and it will not fail SPF. ' +
        'Google and Yahoo both require SPF for bulk senders.',
      fix: {
        kind: 'action',
        steps: [
          'List every system that sends mail as this domain — your mail provider, ' +
            'plus marketing, invoicing, ticketing and CRM tools.',
          'Collect the SPF include: value each vendor documents.',
          'Publish a TXT record at the domain root combining them, ending in ~all, ' +
            'for example: v=spf1 include:_spf.google.com include:sendgrid.net ~all',
          'Watch reports for a week or two, then tighten ~all to -all once you are ' +
            'confident nothing legitimate is missing.',
        ],
      },
    });
    return out;
  }

  if (spf.limitExceeded) {
    const base: Finding = {
      id: 'spf-lookup-limit',
      severity: 'critical',
      title: `SPF needs ${spf.lookupCount} DNS lookups — the limit is ${LOOKUP_LIMIT}`,
      detail:
        'Receivers stop evaluating at ten lookups and return a permanent error. In ' +
        'practice your SPF is being ignored, so mail from some of your senders is ' +
        'already failing authentication even though the record looks correct.',
    };

    if (flatten) {
      base.fix = {
        kind: 'record',
        host: domain,
        type: 'TXT',
        value: flatten.record,
        caveat:
          `This replaces ${flatten.flattened.join(', ')} with the addresses they ` +
          'resolve to right now, bringing you to ' +
          `${flatten.lookupsAfter} lookups. ` + flatten.warnings.join(' '),
      };
    } else {
      base.fix = {
        kind: 'action',
        steps: [
          'Remove senders you no longer use — this is the only fix with no downside.',
          'Ask remaining vendors whether they publish a narrower include.',
          'Flatten the largest include to raw ip4/ip6 ranges, and re-check monthly.',
        ],
      };
    }
    out.push(base);
  } else if (spf.lookupCount >= LOOKUP_LIMIT - 1) {
    // Being legal but at the ceiling is a genuine operational risk: the next vendor
    // your marketing team signs up breaks SPF, and nobody connects the two events.
    out.push({
      id: 'spf-lookup-headroom',
      severity: 'warning',
      title: `SPF uses ${spf.lookupCount} of ${LOOKUP_LIMIT} DNS lookups`,
      detail:
        'This is currently valid but has no headroom. Adding one more sending tool, ' +
        'or a vendor expanding their own include, pushes you over the limit and ' +
        'silently breaks SPF for every message.',
      fix: {
        kind: 'action',
        steps: [
          'Audit the list for senders you no longer use.',
          'Before adding any new sending tool, re-run this check.',
        ],
      },
    });
  }

  const all = spf.allQualifier;
  if (all === '+') {
    out.push({
      id: 'spf-permissive-all',
      severity: 'critical',
      title: 'SPF ends in +all, which authorises the entire internet',
      detail:
        'Any server anywhere passes SPF for your domain. This is worse than having no ' +
        'SPF record, because it actively vouches for forgeries.',
      fix: {
        kind: 'record',
        host: domain,
        type: 'TXT',
        value: (spf.record ?? '').replace(/\+?all\s*$/, '~all'),
        caveat: 'Change +all to ~all, then to -all once you have confirmed your senders are listed.',
      },
    });
  } else if (all === null) {
    out.push({
      id: 'spf-no-all',
      severity: 'warning',
      title: 'SPF has no all mechanism',
      detail:
        'Without a closing all, unlisted senders get a neutral result, which receivers ' +
        'treat almost identically to having no SPF record. The record is doing much ' +
        'less than it appears to.',
      fix: {
        kind: 'record',
        host: domain,
        type: 'TXT',
        value: `${spf.record} ~all`,
        caveat: 'Start with ~all (softfail). Move to -all only once reports confirm every legitimate sender is covered.',
      },
    });
  } else if (all === '?') {
    out.push({
      id: 'spf-neutral-all',
      severity: 'warning',
      title: 'SPF ends in ?all (neutral)',
      detail: 'A neutral result tells receivers nothing, so the record provides no protection against forgery.',
      fix: {
        kind: 'record',
        host: domain,
        type: 'TXT',
        value: (spf.record ?? '').replace(/\?all\s*$/, '~all'),
        caveat: 'Verify all your senders are listed before tightening further to -all.',
      },
    });
  }

  if (spf.macroTerms.length > 0) {
    out.push({
      id: 'spf-macros',
      severity: 'info',
      title: `${spf.macroTerms.length} macro term${spf.macroTerms.length > 1 ? 's' : ''} could not be evaluated`,
      detail:
        `${spf.macroTerms.map((t) => t.raw).join(', ')} expand using the connecting ` +
        'server\'s IP address, so their result depends on who is sending. They are ' +
        'counted toward your lookup total but cannot be checked from here. This is ' +
        'normal for Salesforce and some large senders — no action needed.',
    });
  }

  for (const p of spf.problems) {
    const map: Record<string, { id: FindingId; severity: Finding['severity']; title: string }> = {
      'multiple-records': { id: 'spf-multiple-records', severity: 'critical', title: 'More than one SPF record' },
      'void-limit': { id: 'spf-void-limit', severity: 'warning', title: 'Too many dead lookups in SPF' },
      'ptr-deprecated': { id: 'spf-ptr', severity: 'warning', title: 'SPF uses the deprecated ptr mechanism' },
      'loop': { id: 'spf-loop', severity: 'critical', title: 'SPF include loop' },
      'mx-fanout': { id: 'spf-mx-fanout', severity: 'warning', title: 'An mx mechanism returns too many hosts' },
      'syntax': { id: 'spf-syntax', severity: 'warning', title: 'SPF syntax problem' },
    };
    const meta = map[p.code];
    if (!meta) continue;
    out.push({
      ...meta,
      detail: p.domain === domain ? p.message : `${p.message} (in the record for ${p.domain})`,
      fix: meta.id === 'spf-multiple-records'
        ? {
            kind: 'action',
            steps: [
              'Merge the records into one by combining their mechanisms.',
              'Delete the extras. Receivers treat multiple SPF records as a permanent ' +
                'error and ignore all of them.',
            ],
          }
        : undefined,
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------

function dkimFindings(input: CheckInput): Finding[] {
  const { domain, dkim } = input;
  const out: Finding[] = [];

  // A domain that has declared it sends nothing has no business signing anything.
  if (dkim.keys.length === 0 && isNonSending(input)) {
    return [{
      id: 'non-sending-domain',
      severity: 'pass',
      title: 'This domain is configured to send no mail',
      detail:
        `${domain} publishes v=spf1 -all, which tells receivers that no server is ` +
        'authorised to send mail as it' +
        (input.nullMx ? ', and a null MX record declaring it accepts none either' : '') +
        '. DKIM is not expected here — there is nothing to sign. This is the correct ' +
        'setup for a domain used only for a website.',
    }];
  }

  if (dkim.wildcardDns) {
    out.push({
      id: 'dkim-wildcard-dns',
      severity: 'info',
      title: 'This domain has a wildcard DNS record',
      detail:
        `Any name under ${domain} returns an answer, including selectors that do not ` +
        'exist. We only counted records that are genuinely DKIM keys, but be aware ' +
        'that tools which simply check whether a record exists will report imaginary ' +
        'DKIM selectors for this domain.',
    });
  }

  if (dkim.keys.length === 0) {
    out.push({
      id: 'dkim-none-found',
      severity: 'warning',
      title: 'No DKIM key found',
      detail:
        `We tried ${dkim.triedCount} common selectors and found none. DKIM selectors ` +
        'cannot be listed from DNS, so this is not proof that DKIM is missing — your ' +
        'provider may use a name we did not guess. Some are unguessable by design: ' +
        `${UNGUESSABLE_PROVIDERS.join('; ')}.`,
      fix: {
        kind: 'action',
        steps: [
          'Check your mail provider\'s admin console for the DKIM or "email authentication" section.',
          'If DKIM is off, enable it — the provider will give you records to publish.',
          'If it is on, note the selector name and re-run this check with it entered manually.',
        ],
      },
    });
    return out;
  }

  const weak = dkim.keys.filter((k) => k.bits !== undefined && k.bits < 2048 && !k.revoked);
  if (weak.length > 0) {
    out.push({
      id: 'dkim-weak-key',
      severity: 'warning',
      title: `${weak.length} DKIM key${weak.length > 1 ? 's are' : ' is'} shorter than 2048 bits`,
      detail:
        `${weak.map((k) => `${k.selector} (${k.bits}-bit)`).join(', ')}. 1024-bit RSA is ` +
        'still accepted everywhere but is no longer considered strong, and some ' +
        'receivers have begun downgrading it. Rotation is handled by your provider, ' +
        'not by editing DNS directly.',
      fix: {
        kind: 'action',
        steps: [
          `Ask the provider behind ${weak.map((k) => k.provider).join(', ')} to reissue at 2048 bits.`,
          'Publish the new key on a fresh selector, then remove the old one once mail is signing with it.',
        ],
      },
    });
  }

  const revoked = dkim.keys.filter((k) => k.revoked);
  if (revoked.length > 0) {
    out.push({
      id: 'dkim-revoked',
      severity: 'warning',
      title: `${revoked.length} DKIM selector${revoked.length > 1 ? 's have' : ' has'} an empty key`,
      detail:
        `${revoked.map((k) => k.selector).join(', ')} publish an empty p= value, which ` +
        'means the key is revoked. If anything still signs with these selectors, that ' +
        'mail fails DKIM.',
      fix: {
        kind: 'action',
        steps: [
          'Confirm nothing still signs with these selectors.',
          'Delete the records once you are sure — leaving revoked keys published is untidy but harmless.',
        ],
      },
    });
  }

  const testing = dkim.keys.filter((k) => k.testing);
  if (testing.length > 0) {
    out.push({
      id: 'dkim-testing',
      severity: 'info',
      title: 'A DKIM key is in testing mode',
      detail:
        `${testing.map((k) => k.selector).join(', ')} set t=y, which tells receivers to ` +
        'treat signature failures as if the message were unsigned. Fine during setup, ' +
        'but it should be removed once signing works.',
    });
  }

  const healthy = dkim.keys.filter((k) => !k.revoked && !k.parseError);
  if (healthy.length > 0 && weak.length === 0 && revoked.length === 0) {
    out.push({
      id: 'dkim-ok',
      severity: 'pass',
      title: `DKIM found on ${healthy.length} selector${healthy.length > 1 ? 's' : ''}`,
      detail: healthy.map((k) => `${k.selector} (${k.provider}, ${k.bits ?? k.keyType})`).join(', '),
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// DMARC
// ---------------------------------------------------------------------------

function dmarcFindings({ domain, dmarc, mx }: CheckInput): Finding[] {
  const out: Finding[] = [];

  if (!dmarc.found || !dmarc.record) {
    out.push({
      id: 'dmarc-missing',
      severity: 'critical',
      title: 'No DMARC record',
      detail:
        'Without DMARC you have no say in what receivers do with mail that fails ' +
        'authentication, and no visibility into who is sending as you. Google and ' +
        'Yahoo have required DMARC for bulk senders since February 2024.',
      fix: {
        kind: 'record',
        host: `_dmarc.${domain}`,
        type: 'TXT',
        value: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`,
        caveat:
          'p=none changes nothing about how your mail is treated — it only turns on ' +
          'reporting, so it is safe to publish today. Make sure the mailbox exists; ' +
          'it will receive daily XML reports. Move to p=quarantine once those reports ' +
          'show your legitimate senders passing.',
      },
    });
    return out;
  }

  const r = dmarc.record;

  if (r.inherited) {
    out.push({
      id: 'dmarc-inherited',
      severity: 'info',
      title: `Policy inherited from ${r.foundAt}`,
      detail:
        `${domain} has no DMARC record of its own, so the policy at ${r.foundAt} ` +
        `applies${r.subdomainPolicy ? ` via its sp=${r.subdomainPolicy} tag` : ''}. ` +
        'This is normal and usually intended.',
    });
  }

  if (r.effectivePolicy === 'none') {
    out.push({
      id: 'dmarc-p-none',
      severity: 'warning',
      title: 'DMARC is set to p=none — monitoring only',
      detail:
        'Your DMARC record collects reports but asks receivers to take no action, so ' +
        'forged mail is still delivered. This is the correct place to start, but it ' +
        'is not protection, and it does not satisfy bulk sender requirements on its own.',
      fix: {
        kind: 'record',
        host: `_dmarc.${domain}`,
        type: 'TXT',
        value: r.raw.replace(/\bp\s*=\s*none\b/i, 'p=quarantine'),
        caveat:
          'Only publish this once your reports show legitimate mail passing SPF or ' +
          'DKIM with alignment. Moving to quarantine while a real sender is still ' +
          'failing will send that mail to spam.',
      },
    });
  } else if (r.effectivePolicy === 'quarantine') {
    out.push({
      id: 'dmarc-quarantine',
      severity: 'info',
      title: 'DMARC is at p=quarantine',
      detail:
        'Failing mail goes to spam rather than being rejected. This is real protection. ' +
        'p=reject is the end state once you are confident in your reports.',
      fix: {
        kind: 'record',
        host: `_dmarc.${domain}`,
        type: 'TXT',
        value: r.raw.replace(/\bp\s*=\s*quarantine\b/i, 'p=reject'),
        caveat: 'Move only after a sustained period with no legitimate mail failing in your reports.',
      },
    });
  } else if (r.effectivePolicy === 'reject') {
    out.push({
      id: 'dmarc-reject',
      severity: 'pass',
      title: 'DMARC is at p=reject',
      detail: 'The strongest policy. Mail failing authentication is rejected outright.',
    });
  }

  if (r.pct < 100) {
    out.push({
      id: 'dmarc-pct',
      severity: 'warning',
      title: `Policy applies to only ${r.pct}% of mail`,
      detail:
        `pct=${r.pct} means receivers apply your policy to ${r.pct}% of failing ` +
        'messages and treat the rest more leniently. Useful during a rollout, but it ' +
        'leaves a gap if left in place.',
      fix: {
        kind: 'record',
        host: `_dmarc.${domain}`,
        type: 'TXT',
        value: r.raw.replace(/;?\s*pct\s*=\s*\d+/i, ''),
        caveat: 'Removing pct= defaults it to 100. Do this once the rollout is complete.',
      },
    });
  }

  if (r.rua.length === 0) {
    out.push({
      id: 'dmarc-no-rua',
      severity: 'warning',
      title: 'DMARC collects no reports',
      detail:
        'With no rua= address you get no aggregate reports, so you cannot see who is ' +
        'sending as your domain or whether your own mail is passing. You are enforcing ' +
        'a policy blind.',
      fix: {
        kind: 'record',
        host: `_dmarc.${domain}`,
        type: 'TXT',
        value: `${r.raw.replace(/;\s*$/, '')}; rua=mailto:dmarc@${domain}`,
        caveat: 'The mailbox must exist and will receive daily XML attachments from mailbox providers.',
      },
    });
  }

  // A report address on your own domain is only useful if that domain can actually
  // receive mail. With no MX, delivery falls back to the A record — which for a
  // web-only domain is a web server that speaks no SMTP, so every report bounces.
  // The record looks flawless while you receive nothing.
  const orgDomain = dmarc.orgDomain ?? domain;
  const localRua = r.rua.filter(
    (u) => u.host === domain || u.host === orgDomain || u.host.endsWith(`.${orgDomain}`),
  );
  if (localRua.length > 0 && mx.length === 0) {
    out.push({
      id: 'dmarc-rua-undeliverable',
      severity: 'warning',
      title: 'Your DMARC reports have nowhere to be delivered',
      detail:
        `Reports are addressed to ${localRua.map((u) => u.address).join(', ')}, but ` +
        `${domain} publishes no MX record. Mail servers will fall back to its A record, ` +
        'which serves your website and does not accept SMTP — so the reports bounce and ' +
        'you see nothing, even though the DMARC record itself is correct.',
      fix: {
        kind: 'action',
        steps: [
          'Set up mail delivery for this domain — Cloudflare Email Routing is free and ' +
            'will publish the MX records for you.',
          `Forward ${localRua[0]?.address ?? `dmarc@${domain}`} to a mailbox you actually read.`,
          'Alternatively, point rua= at a DMARC reporting service — but note that an ' +
            'external destination must authorise you first.',
        ],
      },
    });
  }

  // The silent killer: correctly-configured-looking DMARC whose reports are refused.
  for (const dest of dmarc.externalDestinations) {
    if (!dest.required || dest.authorised) continue;
    out.push({
      id: 'dmarc-external-unauthorised',
      severity: 'critical',
      title: `Reports to ${dest.uri.host} are not authorised`,
      detail:
        `You ask receivers to send reports to ${dest.uri.address}, but ${dest.uri.host} ` +
        'has not published the record that authorises it. Conforming reporters — ' +
        'including Google — will not send anything, so you are receiving far fewer ' +
        'reports than you think, or none at all.',
      fix: {
        kind: 'record',
        host: dest.expectedRecord,
        type: 'TXT',
        value: 'v=DMARC1',
        caveat:
          `This record must be published in ${dest.uri.host}'s DNS, not yours. If that ` +
          'is a third-party reporting service, they normally create it for you — ask ' +
          'them to. If you control it, publish it yourself.',
      },
    });
  }

  if (r.subdomainPolicy && r.policy) {
    const rank = { none: 0, quarantine: 1, reject: 2 };
    if (rank[r.subdomainPolicy] < rank[r.policy]) {
      out.push({
        id: 'dmarc-sp-weaker',
        severity: 'warning',
        title: `Subdomains are less protected than ${domain}`,
        detail:
          `p=${r.policy} but sp=${r.subdomainPolicy}. Attackers forge subdomains ` +
          'precisely because they are usually weaker — a lookalike like ' +
          `billing.${domain} would be treated with the weaker policy.`,
        fix: {
          kind: 'record',
          host: `_dmarc.${domain}`,
          type: 'TXT',
          value: r.raw.replace(/\bsp\s*=\s*(none|quarantine|reject)\b/i, `sp=${r.policy}`),
          caveat: 'Confirm no subdomain sends mail that would start failing under the stricter policy.',
        },
      });
    }
  }

  for (const err of r.errors) {
    out.push({
      id: 'dmarc-syntax',
      severity: r.errors.length > 0 && /required|DMARC1|more than one/.test(err) ? 'critical' : 'warning',
      title: 'DMARC record problem',
      detail: err,
    });
  }

  if (r.unknownTags.length > 0) {
    out.push({
      id: 'dmarc-unknown-tags',
      severity: 'info',
      title: 'Unrecognised DMARC tags',
      detail:
        `${r.unknownTags.join(', ')} are not defined in RFC 7489 and will be ignored. ` +
        'Usually a typo — check them against the tag you intended.',
    });
  }

  return out;
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MTA-STS, TLS-RPT, BIMI, DNSSEC
// ---------------------------------------------------------------------------

function modernFindings(input: CheckInput): Finding[] {
  const { domain, mtaSts, tlsRpt, bimi, dnssec, mx, nullMx } = input;
  const out: Finding[] = [];
  const receivesMail = mx.length > 0 && !nullMx;
  const enforcing = input.dmarc.record?.effectivePolicy === 'quarantine'
    || input.dmarc.record?.effectivePolicy === 'reject';

  // --- MTA-STS ---
  if (mtaSts.record) {
    // A DNS record with no reachable policy is the worst of both worlds: it looks
    // configured and does nothing.
    if (mtaSts.policyError) {
      out.push({
        id: 'mtasts-policy-unreachable',
        severity: 'critical',
        title: 'MTA-STS is published but its policy file cannot be fetched',
        detail:
          `You publish an MTA-STS record, but ${mtaSts.policyError}. Senders that ` +
          'cannot retrieve the policy fall back to unencrypted delivery, so this ' +
          'record is currently providing no protection at all.',
        fix: {
          kind: 'action',
          steps: [
            `Serve https://mta-sts.${domain}/.well-known/mta-sts.txt over HTTPS with a valid certificate.`,
            'It must be Content-Type text/plain and must not redirect.',
            'Publish the same MX hosts your domain actually uses.',
          ],
        },
      });
    }

    if (mtaSts.unmatchedMx.length > 0) {
      out.push({
        id: 'mtasts-mx-mismatch',
        severity: 'critical',
        title: 'Your MTA-STS policy does not list all of your mail servers',
        detail:
          `${mtaSts.unmatchedMx.join(', ')} ${mtaSts.unmatchedMx.length === 1 ? 'is' : 'are'} ` +
          'in your MX records but not covered by the policy file. In enforce mode, ' +
          'compliant senders refuse to deliver to a server the policy does not list — ' +
          'so this actively blocks incoming mail rather than merely failing to protect it.',
        fix: {
          kind: 'action',
          steps: [
            `Add ${mtaSts.unmatchedMx.map((h) => `mx: ${h}`).join(', ')} to the policy file.`,
            'Bump the id= value in the DNS record so receivers refetch it.',
          ],
        },
      });
    }

    if (mtaSts.policy?.mode === 'testing') {
      out.push({
        id: 'mtasts-testing',
        severity: 'info',
        title: 'MTA-STS is in testing mode',
        detail:
          'Failures are reported but delivery proceeds unencrypted. Correct while you ' +
          'confirm the policy is right; switch to mode: enforce once TLS-RPT reports are clean.',
      });
    }

    for (const err of [...mtaSts.errors, ...(mtaSts.policy?.errors ?? [])]) {
      out.push({ id: 'mtasts-syntax', severity: 'warning', title: 'MTA-STS problem', detail: err });
    }

    if (!mtaSts.policyError && mtaSts.unmatchedMx.length === 0 && mtaSts.policy?.mode === 'enforce') {
      out.push({
        id: 'mtasts-ok',
        severity: 'pass',
        title: 'MTA-STS is enforcing',
        detail: 'Senders are required to use TLS and to verify your mail server certificate.',
      });
    }
  } else if (receivesMail) {
    out.push({
      id: 'mtasts-missing',
      severity: 'info',
      title: 'No MTA-STS policy',
      detail:
        'Mail sent to you can be downgraded to an unencrypted connection by an attacker ' +
        'on the network. MTA-STS closes that hole. Optional, but it is what separates a ' +
        'well-run mail domain from an average one.',
      fix: {
        kind: 'record',
        host: `_mta-sts.${domain}`,
        type: 'TXT',
        value: `v=STSv1; id=${new Date().toISOString().slice(0, 10).replace(/-/g, '')}000000`,
        caveat:
          `The record alone does nothing — you must also serve a policy file at ` +
          `https://mta-sts.${domain}/.well-known/mta-sts.txt listing your MX hosts. ` +
          'Start with mode: testing, and only move to enforce once reports confirm ' +
          'nothing is failing.',
      },
    });
  }

  // --- TLS-RPT ---
  if (tlsRpt.record) {
    for (const err of tlsRpt.errors) {
      out.push({ id: 'tlsrpt-syntax', severity: 'warning', title: 'TLS-RPT problem', detail: err });
    }
  } else if (receivesMail) {
    out.push({
      id: 'tlsrpt-missing',
      severity: 'info',
      title: 'No TLS reporting',
      detail:
        'TLS-RPT asks other mail providers to tell you when encrypted delivery to your ' +
        'domain fails. It is the feedback loop that makes MTA-STS safe to enforce — ' +
        'without it you are switching on enforcement blind.',
      fix: {
        kind: 'record',
        host: `_smtp._tls.${domain}`,
        type: 'TXT',
        value: `v=TLSRPTv1; rua=mailto:tlsrpt@${domain}`,
        caveat: 'The mailbox must exist. Reports arrive daily as JSON attachments.',
      },
    });
  }

  // --- BIMI ---
  if (bimi.record) {
    if (!enforcing) {
      out.push({
        id: 'bimi-without-enforcement',
        severity: 'warning',
        title: 'BIMI is published but will be ignored',
        detail:
          'Mailbox providers only display a BIMI logo for domains at DMARC ' +
          'p=quarantine or p=reject. While your policy is p=none this record does nothing.',
        fix: {
          kind: 'action',
          steps: [
            'Move DMARC to p=quarantine, then p=reject, once your reports are clean.',
            'The BIMI record will start taking effect on its own after that.',
          ],
        },
      });
    }
    for (const err of bimi.errors) {
      out.push({ id: 'bimi-syntax', severity: 'warning', title: 'BIMI problem', detail: err });
    }
    if (!bimi.vmcUrl) {
      out.push({
        id: 'bimi-no-vmc',
        severity: 'info',
        title: 'BIMI has no Verified Mark Certificate',
        detail:
          'Gmail requires a VMC (the a= tag) before it will show your logo. Without one, ' +
          'support is limited to a few providers such as Fastmail and Zoho. VMCs are ' +
          'issued by DigiCert and Entrust and cost roughly $1,000 a year.',
      });
    }
  } else if (enforcing && !isNonSending(input)) {
    // Only worth raising once DMARC enforcement is in place, and never for a domain
    // that has declared it sends nothing — a logo on mail you never send is not a
    // missed opportunity.
    out.push({
      id: 'bimi-opportunity',
      severity: 'info',
      title: 'Your domain qualifies for BIMI',
      detail:
        `${domain} enforces DMARC, which is the hard prerequisite for BIMI — displaying ` +
        'your logo beside your messages in supporting inboxes. Adding it is now mostly ' +
        'a matter of hosting an SVG, plus a Verified Mark Certificate if you want Gmail ' +
        'to honour it.',
    });
  }

  // --- DNSSEC ---
  if (dnssec.unknown) {
    // Silent: an unavailable third-party resolver is our problem, not the user's.
  } else if (dnssec.signed) {
    out.push({
      id: 'dnssec-ok',
      severity: 'pass',
      title: 'DNSSEC is enabled',
      detail: `${dnssec.zone} is signed, so its DNS answers — including every record above — cannot be forged in transit.`,
    });
  } else {
    out.push({
      id: 'dnssec-missing',
      severity: 'info',
      title: 'DNSSEC is not enabled',
      detail:
        `${dnssec.zone} is unsigned, so an attacker able to tamper with DNS responses ` +
        'could forge your SPF, DKIM and DMARC records — undermining all three. Most ' +
        'registrars and DNS hosts enable it with one click.',
      fix: {
        kind: 'action',
        steps: [
          'Enable DNSSEC in your DNS provider (Cloudflare: DNS → Settings → Enable DNSSEC).',
          'Copy the DS record it generates into your registrar. Some registrars do this automatically.',
        ],
      },
    });
  }

  return out;
}

// ---------------------------------------------------------------------------

export interface Report {
  domain: string;
  findings: Finding[];
  counts: Record<'critical' | 'warning' | 'info' | 'pass', number>;
  /** True when nothing critical was found. Deliberately not a letter grade — a
   *  score invites arguing with the number instead of fixing the problem. */
  passing: boolean;
}

export function buildReport(input: CheckInput): Report {
  const findings = [
    ...spfFindings(input),
    ...dkimFindings(input),
    ...dmarcFindings(input),
    ...modernFindings(input),
  ].sort(bySeverity);

  const counts = { critical: 0, warning: 0, info: 0, pass: 0 };
  for (const f of findings) counts[f.severity]++;

  return { domain: input.domain, findings, counts, passing: counts.critical === 0 };
}
