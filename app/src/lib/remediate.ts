import { getDomain } from 'tldts';
import type { DkimResult } from './dkim/check.js';
import { UNGUESSABLE_PROVIDERS } from './dkim/selectors.js';
import type { DmarcResult } from './dmarc/check.js';
import type { MxRecord } from './dns/resolver.js';
import { describeLookup, type TxtLookup } from './dns/txt-lookup.js';
import type { BimiResult, DnssecResult, MtaStsResult, TlsRptResult } from './modern/check.js';
import type { Finding, FindingId, Fix } from './findings.js';
import { bySeverity } from './findings.js';
import type { SpfEvaluation } from './spf/evaluate.js';
import type { Term } from './spf/parse.js';
import { allSource, authorisesNothing, LOOKUP_LIMIT } from './spf/evaluate.js';
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
  /**
   * The CNAME chain at the checked name itself, if it is an alias. Then its TXT records,
   * SPF included, belong to the target, and an SPF fix cannot be published at it.
   */
  domainCnameChain?: string[];
  /** The checked name is itself a public suffix, such as gov.uk. */
  publicSuffix?: boolean;
}

/**
 * A TXT record fix at `host` — unless `host` is a CNAME.
 *
 * A CNAME owns its name outright: RFC 1034 §3.6.2 ("If a CNAME RR is present at a node,
 * no other data should be present") and RFC 2181 §10.1. Telling someone to publish a TXT
 * at `_dmarc.homedepot.com`, which is a CNAME into Proofpoint, hands them a record their
 * DNS host will refuse — or, worse, one that sits beside the CNAME and is never read. The
 * record lives where the chain ends, so that is where the change has to be made: in the
 * user's own zone when the target is theirs (salesforce.com aliases to a name under
 * itself), or at the provider when it is not.
 *
 * Every TXT fix in this file goes through here, so no finding can forget the check.
 */
function txtFix(
  domain: string,
  host: string,
  value: string,
  caveat: string | undefined,
  cnameChain: readonly string[],
): Fix {
  if (cnameChain.length === 0) {
    return { kind: 'record', host, type: 'TXT', value, ...(caveat ? { caveat } : {}) };
  }

  const target = cnameChain[cnameChain.length - 1]!;
  const via = cnameChain.length > 1 ? ` (via ${cnameChain.slice(0, -1).join(' → ')})` : '';
  const ours = getDomain(target) !== null && getDomain(target) === (getDomain(domain) ?? domain);

  return {
    kind: 'action',
    steps: [
      `${host} is a CNAME to ${target}${via}, so the record lives at ${target}, not at ` +
        `${host}. DNS allows nothing else at a name that is a CNAME (RFC 1034 §3.6.2), so ` +
        `a TXT record published at ${host} would be refused or never read.`,
      ours
        ? `${target} is in your own DNS: change the TXT record there so it reads as shown.`
        : `${target} is not in your DNS. It usually belongs to the provider that manages ` +
          'this record for you: make the change in their dashboard, or ask them to.',
      `To manage the record yourself instead, delete the CNAME at ${host} and publish ` +
        'the record there.',
    ],
    managedRecord: { host, target, type: 'TXT', value, ...(caveat ? { caveat } : {}) },
  };
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

/** Replace one term of an SPF record, matching whole tokens only. */
function replaceTerm(record: string, term: string, replacement: string): string {
  const tokens = record.trim().split(/\s+/);
  const i = tokens.indexOf(term);
  if (i >= 0) tokens[i] = replacement;
  return tokens.join(' ');
}

/**
 * An SPF record fix. No suggested record may carry both an `all` and a `redirect=`:
 * RFC 7208 §6.1 ignores the redirect when there is an `all` anywhere in the record, so
 * the pair is either a redirect someone believes is working or a record switched off by
 * our own advice. A redirect that `all` already makes dead is dropped here — that
 * changes nothing about what the record means — and the caveat says so.
 */
function spfFix(
  domain: string,
  host: string,
  value: string,
  caveat: string,
  chain: readonly string[],
): Fix {
  const tokens = value.trim().split(/\s+/);
  const hasAll = tokens.some((t) => /^[+\-~?]?all$/i.test(t));
  const dead = hasAll ? tokens.filter((t) => /^redirect=/i.test(t)) : [];
  if (dead.length === 0) return txtFix(domain, host, value, caveat, chain);

  return txtFix(
    domain,
    host,
    tokens.filter((t) => !dead.includes(t)).join(' '),
    `${caveat} It also leaves out ${dead.join(' ')}, which the all mechanism already ` +
      'switches off (RFC 7208 §6.1), so dropping it changes nothing.',
    chain,
  );
}

/**
 * Hosted SPF services that publish macro includes, recognised by the domain the macro
 * resolves under. Only services whose macro shape has been seen live are listed:
 * naming the wrong provider is worse than naming none.
 */
const MACRO_PROVIDERS: { suffix: string; name: string }[] = [
  { suffix: 'salesforce.com', name: 'Salesforce' },      // exists:%{i}._spf.mta.salesforce.com
  { suffix: 'pphosted.com', name: 'Proofpoint' },         // include:%{ir}.%{v}.%{d}.spf.has.pphosted.com
  { suffix: 'vali.email', name: 'Valimail' },             // include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email
];

function macroProvider(term: Term): string | null {
  // The labels after the last macro are the fixed part of the name.
  const fixed = (term.value ?? '').toLowerCase().split('.').filter((l) => !l.includes('%')).join('.');
  return MACRO_PROVIDERS.find((p) => fixed === p.suffix || fixed.endsWith(`.${p.suffix}`))?.name ?? null;
}

/**
 * Who the macros belong to. The note used to say "normal for Salesforce" for every
 * macro — including Proofpoint's on homedepot.com and Valimail's on usenix.org.
 */
function macroNote(spf: SpfEvaluation): string {
  const named = new Map<string, string[]>();
  const unknown: string[] = [];
  for (const t of spf.macroTerms) {
    const name = macroProvider(t);
    if (name) named.set(name, [...(named.get(name) ?? []), t.raw]);
    else unknown.push(t.raw);
  }

  const parts: string[] = [];
  if (named.size > 0) {
    const names = [...named.keys()];
    const list = names.length === 1 ? names[0] : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
    parts.push(`${list} ${names.length === 1 ? 'uses' : 'use'} macros like this by design, so no action is needed.`);
  }
  if (unknown.length > 0) {
    parts.push(
      `${named.size > 0 ? `${unknown.join(', ')} ${unknown.length === 1 ? 'is' : 'are'} not from a service we recognise. ` : ''}` +
      'Some hosted SPF services use macros like this; if you do not recognise ' +
      `${unknown.length === 1 ? 'it' : 'them'}, find out which service added ${unknown.length === 1 ? 'it' : 'them'}.`,
    );
  }

  // A record whose only sender is a macro: the visible count is the whole of what can
  // be seen, and it is not the whole of what a receiver evaluates.
  const senders = spf.tree?.parsed?.terms.filter(
    (t) => t.kind === 'mechanism' && t.name !== 'all',
  ) ?? [];
  if (senders.length > 0 && senders.every((t) => t.hasMacro)) {
    parts.push(
      `Here the macro is the only sender in the record, so the ${spf.lookupCount}/${LOOKUP_LIMIT} ` +
      'lookup count is all that can be seen from outside: what the hosted service evaluates ' +
      'behind it is resolved per message on its side and cannot be counted here.',
    );
  }
  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// SPF
// ---------------------------------------------------------------------------

function spfFindings({ domain, spf, flatten, domainCnameChain = [] }: CheckInput): Finding[] {
  const out: Finding[] = [];

  // No answer at the apex, even after a retry. Saying "no SPF record" here would be a
  // claim the DNS never made.
  if (spf.lookupError) {
    out.push({
      id: 'spf-lookup-failed',
      severity: 'warning',
      title: 'SPF could not be checked',
      detail:
        `The TXT lookup for ${domain} got no answer (${spf.lookupError}), after a retry. ` +
        'That is a DNS failure, not evidence the record is missing — run the check again ' +
        'in a minute.',
    });
    return out;
  }

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

  // Includes in the user's own record that cost a lookup and can never match. Found
  // before the lookup-count findings so their advice can start with the free win.
  const idle = (spf.tree?.children ?? []).filter(
    (c) => c.term.name === 'include' && c.term.value && authorisesNothing(c.node),
  );

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
      base.fix = spfFix(
        domain,
        domain,
        flatten.record,
        `This replaces ${flatten.flattened.join(', ')} with the addresses they ` +
          'resolve to right now, bringing you to ' +
          `${flatten.lookupsAfter} lookups. ` + flatten.warnings.join(' '),
        domainCnameChain,
      );
    } else {
      base.fix = {
        kind: 'action',
        steps: [
          ...idle.map((c) => `Remove ${c.term.raw}: it costs a lookup and authorises no servers.`),
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
          ...idle.map((c) => `Start with ${c.term.raw}: it costs a lookup and authorises no servers.`),
          'Audit the list for senders you no longer use.',
          'Before adding any new sending tool, re-run this check.',
        ],
      },
    });
  }

  // Where the deciding `all` lives, following redirect= — never just the apex string.
  // A record that ends in redirect= has no `all` by design: its `all` is in the target,
  // and adding one here would switch the redirect off (RFC 7208 §6.1) and leave every
  // sender, the real ones included, on whatever the new `all` says. When the target
  // could not be read, nothing is said about `all` at all; the finding that explains
  // why (lookup failed, no record, macro, limit, loop) stands on its own.
  const source = allSource(spf.tree);
  if (source && source.status !== 'unresolved') {
    const at = source.node;
    const own = at === spf.tree;
    // An apex alias cannot hold the record; a redirect target's chain was not walked.
    const chain = own ? domainCnameChain : [];
    const where = own ? '' : ` in ${at.domain}, the record your redirect= hands the policy to`;
    const targetNote = own
      ? ''
      : ` This change belongs in ${at.domain}, the record your own one redirects to, not ` +
        `in ${domain}: adding all to ${domain} would switch its redirect= off.`;
    const qualifier = source.status === 'all' ? source.term.qualifier : null;
    const swapAll = (to: string) =>
      source.status === 'all' ? replaceTerm(at.record ?? '', source.term.raw, to) : '';

    if (qualifier === '+') {
      out.push({
        id: 'spf-permissive-all',
        severity: 'critical',
        title: 'SPF ends in +all, which authorises the entire internet',
        detail:
          'Any server anywhere passes SPF for your domain. This is worse than having no ' +
          `SPF record, because it actively vouches for forgeries.${own ? '' : ` The +all is${where}.`}`,
        fix: spfFix(
          domain, at.domain, swapAll('~all'),
          'Change +all to ~all, then to -all once you have confirmed your senders are listed.' + targetNote,
          chain,
        ),
      });
    } else if (qualifier === '?') {
      out.push({
        id: 'spf-neutral-all',
        severity: 'warning',
        title: 'SPF ends in ?all (neutral)',
        detail:
          'A neutral result tells receivers nothing, so the record provides no protection ' +
          `against forgery.${own ? '' : ` The ?all is${where}.`}`,
        fix: spfFix(
          domain, at.domain, swapAll('~all'),
          'Verify all your senders are listed before tightening further to -all.' + targetNote,
          chain,
        ),
      });
    } else if (source.status === 'none') {
      out.push({
        id: 'spf-no-all',
        severity: 'warning',
        title: 'SPF has no all mechanism',
        detail:
          'Without a closing all, unlisted senders get a neutral result, which receivers ' +
          'treat almost identically to having no SPF record. The record is doing much ' +
          `less than it appears to.${own ? '' : ` The record without one is${where}.`}`,
        fix: spfFix(
          domain, at.domain, `${(at.record ?? '').trim()} ~all`,
          'Start with ~all (softfail). Move to -all only once reports confirm every ' +
            'legitimate sender is covered.' + targetNote,
          chain,
        ),
      });
    }
  }

  for (const c of idle) {
    const target = c.term.value!;
    const record = c.node!.record!;
    out.push({
      id: 'spf-include-authorises-nothing',
      // Costs a lookup that matters only when lookups are scarce.
      severity: spf.lookupCount >= LOOKUP_LIMIT - 1 ? 'warning' : 'info',
      title: `${c.term.raw} costs one DNS lookup and authorises no servers`,
      detail:
        `${target} publishes "${record}", which lists no address, no host and no further ` +
        'include, so it can never match: no message passes SPF because of it (RFC 7208 ' +
        `§5.2). It still costs one of your ${LOOKUP_LIMIT} lookups. Usually it is left ` +
        'over from a service that no longer sends through it.',
      fix: spf.record
        ? spfFix(
            domain,
            domain,
            spf.record.trim().split(/\s+/).filter((t) => t !== c.term.raw).join(' '),
            'Removing it changes no SPF result, because the include cannot match. If the ' +
              `service later starts listing servers at ${target}, it would need to go back in.`,
            domainCnameChain,
          )
        : undefined,
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
        'counted toward your lookup total but cannot be checked from here. ' +
        macroNote(spf),
    });
  }

  for (const p of spf.problems) {
    const where = p.domain === domain ? '' : ` (in the record for ${p.domain})`;

    // A syntax error is a permerror for the whole record (RFC 7208 §4.6): receivers
    // stop before evaluating anything, so every sender listed fails SPF alike.
    if (p.code === 'syntax') {
      out.push({
        id: 'spf-syntax',
        severity: 'critical',
        title: p.term ? `SPF permerror: malformed term ${p.term}` : 'SPF permerror: syntax error',
        detail:
          `${p.message}${where}. A syntax error makes the whole SPF check a permerror ` +
          '(RFC 7208 §4.6): receivers that follow the spec stop there and treat the ' +
          'record as broken, so none of the senders it lists pass SPF.' +
          (p.suggestion
            ? ' It looks like two terms with the space between them missing — often a ' +
              'record split into several TXT strings, which join with nothing between them.'
            : ''),
        fix: p.suggestion && p.term && p.domain === domain && spf.record
          ? spfFix(
              domain,
              domain,
              spf.record.replace(p.term, p.suggestion),
              `Replaces ${p.term} with ${p.suggestion}. If your DNS host shows the record ` +
                'as several quoted strings, end each string with a space, or start the next ' +
                'one with one.',
              domainCnameChain,
            )
          : undefined,
      });
      continue;
    }

    if (p.code === 'no-record' && p.domain !== domain) {
      // RFC 7208 makes both a permerror, but for different reasons and with different
      // fixes: a dead include is one sender among several, a dead redirect= is the
      // whole policy.
      const redirect = p.via === 'redirect';
      out.push({
        id: 'spf-include-no-record',
        severity: 'critical',
        title: redirect
          ? `SPF permerror: the redirect= target ${p.domain} publishes no SPF record`
          : `SPF permerror: ${p.domain} publishes no SPF record`,
        detail: redirect
          ? `Your record hands its whole policy to ${p.domain} with redirect=, and the ` +
            `lookup there found ${p.message.replace(/^no SPF record published/, 'no SPF record')}. ` +
            'RFC 7208 §6.1 makes that a permerror rather than "none", so every message ' +
            'from your domain fails SPF the same way, the real ones included.'
          : `Your record includes ${p.domain}, which has no SPF record. RFC 7208 §5.2 makes ` +
            'that a permerror when a receiver reaches it. Usually the include belongs to a ' +
            'service you no longer use, or its name was mistyped.',
        fix: {
          kind: 'action',
          steps: redirect
            ? [
                `Check the redirect= value against your provider's current documentation — ` +
                  'a single wrong character here breaks SPF for every sender.',
                'If the provider has moved your record, point redirect= at the new name.',
              ]
            : [
                `Check the include value against the provider's current documentation.`,
                'If you no longer use the service, remove the include.',
              ],
        },
      });
      continue;
    }

    if (p.code === 'dns-error') {
      // A failed lookup is a temperror (RFC 7208 §4.4), not a missing record. On a
      // redirect= target it is also the whole policy: the senders and the all that
      // decide the result live there, so the report has nothing else to say about
      // them — and must not, say, call the record "missing an all mechanism".
      const redirect = p.via === 'redirect';
      out.push({
        id: 'spf-lookup-failed',
        severity: redirect ? 'warning' : 'info',
        title: redirect
          ? `SPF could not be checked: the redirect= target ${p.domain} did not answer`
          : `${p.domain} could not be checked`,
        detail: redirect
          ? `Your record hands its whole policy to ${p.domain} with redirect=, and the ` +
            `lookup for it got no answer (${p.message}), after a retry. Its senders and ` +
            'its all mechanism live there, so nothing about them can be checked from ' +
            'here. A receiver hitting the same failure returns temperror (RFC 7208 §4.4) ' +
            'and usually retries later; this is not evidence the record is missing. Run ' +
            'the check again in a minute.'
          : `The SPF record at ${p.domain} got no answer (${p.message}), after a retry, so ` +
            'the lookup count below it is incomplete. Run the check again in a minute.',
      });
      continue;
    }

    const map: Record<string, { id: FindingId; severity: Finding['severity']; title: string }> = {
      'multiple-records': { id: 'spf-multiple-records', severity: 'critical', title: 'More than one SPF record' },
      // RFC 7208 §4.6.4: past two, the check is a permerror like the lookup limit.
      'void-limit': { id: 'spf-void-limit', severity: 'critical', title: 'SPF permerror: too many void lookups' },
      'ptr-deprecated': { id: 'spf-ptr', severity: 'warning', title: 'SPF uses the deprecated ptr mechanism' },
      'loop': { id: 'spf-loop', severity: 'critical', title: 'SPF include loop' },
      'mx-fanout': { id: 'spf-mx-fanout', severity: 'warning', title: 'An mx mechanism returns too many hosts' },
      'dead-terms': { id: 'spf-dead-terms', severity: 'warning', title: 'Part of the SPF record is never used' },
    };
    const meta = map[p.code];
    if (!meta) continue;
    out.push({
      ...meta,
      detail: `${p.message}${where}`,
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

/**
 * Narrowed to the three fields it actually reads, rather than all of CheckInput, so the
 * record-generating half can be tested without standing up an SPF evaluation and a DKIM
 * sweep to get at it. `runCheck` still passes the whole input unchanged.
 */
export function dmarcFindings({ domain, dmarc, mx }: Pick<CheckInput, 'domain' | 'dmarc' | 'mx'>): Finding[] {
  const out: Finding[] = [];
  // The alias chain at a `_dmarc` name, from the tree walk that already queried it.
  const chainAt = (host: string) =>
    dmarc.lookups.find((l) => l.name.toLowerCase() === host.toLowerCase())?.cnameChain ?? [];
  const dmarcFix = (host: string, value: string, caveat?: string) =>
    txtFix(domain, host, value, caveat, chainAt(host));

  // No answer is not "no record". Saying a domain has no DMARC when its lookup merely
  // failed tells the owner of a p=reject domain that they are unprotected.
  if (dmarc.status === 'unknown') {
    const failed = dmarc.lookups[dmarc.lookups.length - 1];
    out.push({
      id: 'dmarc-lookup-failed',
      severity: 'warning',
      title: 'DMARC could not be checked',
      detail:
        `${failed ? describeLookup(failed) : 'The DMARC lookup got no answer.'} ` +
        'This is a DNS failure, not evidence that the record is missing — run the check ' +
        'again in a minute. If it keeps failing, receivers may be failing to fetch it too.',
    });
    return out;
  }

  if (!dmarc.found || !dmarc.record) {
    out.push({
      id: 'dmarc-missing',
      severity: 'critical',
      title: 'No DMARC record',
      detail:
        'Without DMARC you have no say in what receivers do with mail that fails ' +
        'authentication, and no visibility into who is sending as you. Google and ' +
        'Yahoo have required DMARC for bulk senders since February 2024. ' +
        dmarc.lookups.map(describeLookup).join(' '),
      fix: dmarcFix(
        `_dmarc.${domain}`,
        `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`,
        'p=none changes nothing about how your mail is treated — it only turns on ' +
          'reporting, so it is safe to publish today. Make sure the mailbox exists; ' +
          'it will receive daily XML reports. Move to p=quarantine once those reports ' +
          'show your legitimate senders passing.',
      ),
    });
    return out;
  }

  const r = dmarc.record;

  // Tags RFC 9989 removed and that the deprecated-tags finding below asks to be tidied
  // away. Every record suggested here is built from the published one, so it leaves
  // them out too — one page must not call pct=100 deprecated and then hand back a
  // record containing it. pct below 100 is not in this list: it still changes what
  // the record does, so it stays until the dmarc-pct fix, which is about exactly that.
  const stale = r.deprecatedTags.filter((t) => t !== 'pct' || r.pct === 100);
  const dropped: string[] = [];
  const base = r.raw
    .split(';')
    .filter((part) => {
      const name = part.split('=')[0]?.trim().toLowerCase() ?? '';
      if (!stale.includes(name)) return true;
      dropped.push(part.trim());
      return false;
    })
    .join(';');
  const droppedNote = dropped.length === 0
    ? ''
    : ` It also leaves out ${dropped.join(', ')}: RFC 9989 removed ` +
      `${dropped.length === 1 ? 'that tag' : 'those tags'}, as the note on deprecated tags explains.`;
  const fromRecord = (host: string, value: string, caveat: string) =>
    dmarcFix(host, value, caveat + droppedNote);

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
        // Gmail and Yahoo both accept p=none for their bulk-sender DMARC rule, and the
        // guides here say so with sources (google-yahoo-sender-requirements). The old
        // "does not satisfy bulk sender requirements on its own" read as the opposite.
        'Your DMARC record collects reports but asks receivers to take no action. This ' +
        'is the correct place to start, and Gmail and Yahoo accept p=none for their ' +
        'bulk-sender DMARC rule. But it is not protection: forged mail is still delivered.',
      fix: fromRecord(
        `_dmarc.${domain}`,
        base.replace(/\bp\s*=\s*none\b/i, 'p=quarantine'),
        'Only publish this once your reports show legitimate mail passing SPF or ' +
          'DKIM with alignment. Moving to quarantine while a real sender is still ' +
          'failing will send that mail to spam.',
      ),
    });
  } else if (r.effectivePolicy === 'quarantine') {
    out.push({
      id: 'dmarc-quarantine',
      severity: 'info',
      title: 'DMARC is at p=quarantine',
      detail:
        'Failing mail goes to spam rather than being rejected. This is real protection. ' +
        'p=reject is the end state once you are confident in your reports.',
      fix: fromRecord(
        `_dmarc.${domain}`,
        base.replace(/\bp\s*=\s*quarantine\b/i, 'p=reject'),
        'Move only after a sustained period with no legitimate mail failing in your reports.',
      ),
    });
  } else if (r.effectivePolicy === 'reject') {
    out.push({
      id: 'dmarc-reject',
      severity: 'pass',
      title: 'DMARC is at p=reject',
      detail: 'The strongest policy. Mail failing authentication is rejected outright.',
    });
  }

  // Reported after the policy finding above and deliberately not folded into it: t=y
  // does not change which policy is published, it changes whether receivers act on it.
  // Calling a t=y record "the strongest policy" and stopping there would be the tool
  // telling someone they are protected when they have asked not to be.
  if (r.testMode && r.effectivePolicy !== 'none') {
    out.push({
      id: 'dmarc-test-mode',
      severity: 'warning',
      title: `t=y — ${r.effectivePolicy} is published but not being applied`,
      detail:
        `Your record asks for ${r.effectivePolicy}, but t=y tells receivers you are ` +
        'testing, so they apply handling one level below it. Forged mail that reads as ' +
        `${r.effectivePolicy === 'reject' ? 'rejected is quarantined' : 'quarantined is delivered'} ` +
        'instead. That is the right setting for a dry run and the wrong one to leave behind.',
      fix: fromRecord(
        `_dmarc.${domain}`,
        base.replace(/\bt\s*=\s*y\b/i, 't=n'),
        'Publish this once a dry run has produced no surprises. Removing t= entirely ' +
          'has the same effect — t=n is the default.',
      ),
    });
  }

  if (r.pct < 100) {
    out.push({
      id: 'dmarc-pct',
      severity: 'warning',
      title: `Policy applies to only ${r.pct}% of mail`,
      detail:
        `pct=${r.pct} asks receivers to apply your policy to ${r.pct}% of failing ` +
        'messages and treat the rest more leniently. RFC 9989 removed the tag, because ' +
        'implementations never agreed on what a value between 0 and 100 meant — so the ' +
        'real coverage was always less predictable than the number suggests, and on a ' +
        'receiver that has moved to 9989 there is now no gap because there is no tag. ' +
        'Either way it should not be what stands between a forgery and your customers.',
      fix: fromRecord(
        `_dmarc.${domain}`,
        base.replace(/;?\s*pct\s*=\s*\d+/i, ''),
        'Removing pct= applies your policy to all failing mail. Do this once the ' +
          'rollout is complete. For a staged rollout, t=y is the replacement.',
      ),
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
      fix: fromRecord(
        `_dmarc.${domain}`,
        `${base.replace(/;\s*$/, '')}; rua=mailto:dmarc@${domain}`,
        'The mailbox must exist and will receive daily XML attachments from mailbox providers.',
      ),
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
        fix: fromRecord(
          `_dmarc.${domain}`,
          base.replace(/\bsp\s*=\s*(none|quarantine|reject)\b/i, `sp=${r.policy}`),
          'Confirm no subdomain sends mail that would start failing under the stricter policy.',
        ),
      });
    }
  }

  // np= covers the subdomains an attacker invents — the ones that were never real —
  // so it is only worth raising once the parent domain is actually enforcing. Offering
  // np=reject to a domain still on p=none would be advice about the wrong problem.
  if (r.nonExistentPolicy === null && r.policy && r.policy !== 'none') {
    out.push({
      id: 'dmarc-no-np',
      severity: 'info',
      title: 'No np= tag for subdomains that do not exist',
      detail:
        `RFC 9989 added np= for subdomains with no DNS records at all. That is the ` +
        `sharper tool against forgery, because names like billing.${domain} are usually ` +
        'invented rather than real — sp= covers subdomains generally, np= lets you ' +
        'refuse the unregistered ones outright while leaving your genuine subdomains ' +
        `under ${r.subdomainPolicy ? `sp=${r.subdomainPolicy}` : 'p='}. ` +
        'Receivers that have not adopted 9989 ignore it, so publishing it costs nothing.',
      fix: fromRecord(
        // foundAt, not domain, unlike the findings above: np= governs non-existent
        // subdomains *of the domain publishing it*, so on an inherited record it
        // belongs on the parent. Publishing it at the subdomain the user happened to
        // type would apply it one level too low and do nothing they asked for.
        `_dmarc.${r.foundAt}`,
        // Appended rather than spliced in after p=. Tag order carries no meaning past
        // v=, and splicing re-emitted a sp= that was already in the record — a repeated
        // tag, which this same parser correctly calls an error.
        `${base.replace(/;\s*$/, '')}; np=reject`,
        'Safe for almost every domain, because it only applies to names that resolve ' +
          'to nothing. Check first that no sender uses a subdomain that exists only as ' +
          'a bare MX or TXT name.',
      ),
    });
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
        `${r.unknownTags.join(', ')} are not defined in RFC 9989 and will be ignored. ` +
        'Usually a typo — check them against the tag you intended.',
    });
  }

  // Separate from the finding above on purpose. A deprecated tag is valid, published
  // on purpose, and still honoured by most receivers; telling someone to go looking
  // for a spelling mistake in it would send them after a bug that is not there.
  if (stale.length > 0) {
    out.push({
      id: 'dmarc-deprecated-tags',
      severity: 'info',
      title: `${stale.join(', ')} ${stale.length === 1 ? 'is' : 'are'} deprecated`,
      detail:
        `RFC 9989 removed ${stale.join(', ')}. Nothing breaks — receivers that still ` +
        'implement RFC 7489 continue to honour these, and the rest ignore them — but ' +
        'they no longer do anything you can rely on. ' +
        (stale.includes('pct') ? 't=y is the replacement for staged rollouts. ' : '') +
        (stale.includes('ri') ? 'Aggregate reports are daily in practice regardless. ' : '') +
        'Removing them is tidying, not a fix' +
        (dropped.length > 0 && out.some((f) =>
          f.id !== 'dmarc-external-unauthorised' && (f.fix?.kind === 'record' || f.fix?.managedRecord))
          ? ', and every record suggested on this page already leaves them out.'
          : '.'),
    });
  }

  return out;
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MTA-STS, TLS-RPT, BIMI, DNSSEC
// ---------------------------------------------------------------------------

/** A record we could not read, said as such rather than as "not published". */
function lookupFailed(id: FindingId, label: string, lookup: TxtLookup): Finding {
  return {
    id,
    severity: 'info',
    title: `${label} could not be checked`,
    detail:
      `${describeLookup(lookup)} That is a DNS failure, not evidence the record is ` +
      'missing. Run the check again in a minute.',
  };
}

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
  } else if (mtaSts.lookup.status === 'unknown') {
    out.push(lookupFailed('mtasts-lookup-failed', 'MTA-STS', mtaSts.lookup));
  } else if (receivesMail) {
    out.push({
      id: 'mtasts-missing',
      severity: 'info',
      title: 'No MTA-STS policy',
      detail:
        'Mail sent to you can be downgraded to an unencrypted connection by an attacker ' +
        'on the network. MTA-STS closes that hole. Optional, but it is what separates a ' +
        'well-run mail domain from an average one.',
      fix: txtFix(
        domain,
        `_mta-sts.${domain}`,
        `v=STSv1; id=${new Date().toISOString().slice(0, 10).replace(/-/g, '')}000000`,
        `The record alone does nothing — you must also serve a policy file at ` +
          `https://mta-sts.${domain}/.well-known/mta-sts.txt listing your MX hosts. ` +
          'Start with mode: testing, and only move to enforce once reports confirm ' +
          'nothing is failing.',
        mtaSts.lookup.cnameChain,
      ),
    });
  }

  // --- TLS-RPT ---
  if (tlsRpt.record) {
    for (const err of tlsRpt.errors) {
      out.push({ id: 'tlsrpt-syntax', severity: 'warning', title: 'TLS-RPT problem', detail: err });
    }
  } else if (tlsRpt.lookup.status === 'unknown') {
    out.push(lookupFailed('tlsrpt-lookup-failed', 'TLS-RPT', tlsRpt.lookup));
  } else if (receivesMail) {
    out.push({
      id: 'tlsrpt-missing',
      severity: 'info',
      title: 'No TLS reporting',
      detail:
        'TLS-RPT asks other mail providers to tell you when encrypted delivery to your ' +
        'domain fails. It is the feedback loop that makes MTA-STS safe to enforce — ' +
        'without it you are switching on enforcement blind.',
      fix: txtFix(
        domain,
        `_smtp._tls.${domain}`,
        `v=TLSRPTv1; rua=mailto:tlsrpt@${domain}`,
        'The mailbox must exist. Reports arrive daily as JSON attachments.',
        tlsRpt.lookup.cnameChain,
      ),
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

/**
 * A public suffix (gov.uk, co.uk) is checked only when it publishes SPF or DMARC, and
 * the report says what is different about one. RFC 9989 brought Public Suffix Domains
 * into DMARC proper (it obsoletes RFC 9091): a PSD's record covers names under it that
 * publish none (§4.10.1), and a Public Suffix Operator that publishes one MUST mark it
 * psd=y (§5.2). Without the tag, the §4.10.2 tree walk picks the record with the fewest
 * labels as the organizational domain, so separately run names under the suffix share
 * one organizational domain unless they publish psd=n themselves.
 */
function publicSuffixFindings({ domain, dmarc, publicSuffix }: CheckInput): Finding[] {
  if (!publicSuffix) return [];
  const r = dmarc.record;
  const unmarked = r !== null && r.psd !== 'y';
  return [{
    id: 'public-suffix',
    severity: 'info',
    title: `${domain} is a public suffix`,
    detail:
      `${domain} is on the Public Suffix List: names are registered under it, the way ` +
      `example.${domain} is. ` +
      (r
        ? `Its DMARC record also applies to names under it that publish none of their own ` +
          '(RFC 9989 §4.10.1). '
        : '') +
      `The checks below treat it like any other domain, so the findings about its own ` +
      `mail matter only if mail is sent as ${domain} itself.` +
      (unmarked
        ? ` Its DMARC record has no psd=y. RFC 9989 §5.2 says a Public Suffix Operator ` +
          'that publishes DMARC MUST include it; without it, receivers following RFC 9989 ' +
          `take ${domain} as the organizational domain of the names under it (§4.10.2), so ` +
          'they count as one organization for relaxed alignment unless they publish psd=n.'
        : ''),
    fix: unmarked
      ? {
          kind: 'action',
          steps: [
            `If the names under ${domain} are run by separate organizations, add psd=y to ` +
              `the record at _dmarc.${domain} (RFC 9989 §5.2).`,
            `If ${domain} and the names under it are one organization, nothing needs to ` +
              'change; psd=n would say so explicitly.',
          ],
        }
      : undefined,
  }];
}

export function buildReport(input: CheckInput): Report {
  const findings = [
    ...publicSuffixFindings(input),
    ...spfFindings(input),
    ...dkimFindings(input),
    ...dmarcFindings(input),
    ...modernFindings(input),
  ].sort(bySeverity);

  const counts = { critical: 0, warning: 0, info: 0, pass: 0 };
  for (const f of findings) counts[f.severity]++;

  return { domain: input.domain, findings, counts, passing: counts.critical === 0 };
}
