import type { APIRoute } from 'astro';
import { InvalidDomainError, runCheck } from '../../lib/check.js';
import { clientIp, rateLimit, RATE_LIMIT } from '../../lib/ratelimit.js';
import { siteOrigin } from '../../lib/site.js';
import { track } from '../../lib/stats.js';

/**
 * Public JSON API.
 *
 * Deliberately a stable, hand-built shape rather than `JSON.stringify(result)` —
 * dumping internal structures would make every refactor a breaking change for anyone
 * who built against it. `version` is here so that when the shape does change, callers
 * can tell.
 *
 * Same rate limit and the same crawl exclusion as the HTML route: this is the same
 * expensive, unbounded work with a different Content-Type.
 */

const API_VERSION = 1;

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      // Open CORS: the whole point is that other people's tools can call it.
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'X-Robots-Tag': 'noindex, nofollow',
      'Cache-Control': 'public, max-age=60',
      ...extra,
    },
  });

export const OPTIONS: APIRoute = () => json({}, 204);

export const GET: APIRoute = async ({ request, url, clientAddress }) => {
  const domain = url.searchParams.get('domain')?.trim() ?? '';
  if (domain === '') {
    return json({ error: 'missing_domain', message: 'Pass ?domain=example.com' }, 400);
  }

  const selectors = (url.searchParams.get('selectors') ?? '')
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^[a-z0-9._-]{1,63}$/.test(s))
    .slice(0, 5);

  const limit = await rateLimit(clientIp(request, clientAddress));
  if (!limit.allowed) {
    return json(
      {
        error: 'rate_limited',
        message: `Limit is ${RATE_LIMIT.MAX_REQUESTS} requests per ${RATE_LIMIT.WINDOW_SECONDS}s.`,
        retryAfter: limit.resetIn,
      },
      429,
      { 'Retry-After': String(limit.resetIn) },
    );
  }

  try {
    const r = await runCheck(domain, { selectors });

    track({
      path: '/api/check',
      referrer: request.headers.get('referer'),
      userAgent: request.headers.get('user-agent'),
      clientIp: clientIp(request, clientAddress),
      selfHost: new URL(siteOrigin()).hostname,
      isCheck: true,
      viaApi: true,
    });

    return json({
      version: API_VERSION,
      domain: r.domain,
      checkedAt: new Date().toISOString(),
      passing: r.report.passing,
      counts: r.report.counts,

      findings: r.report.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        fix: f.fix?.kind === 'record'
          ? { kind: 'record', host: f.fix.host, type: f.fix.type, value: f.fix.value, caveat: f.fix.caveat ?? null }
          : f.fix?.kind === 'action'
            ? { kind: 'action', steps: f.fix.steps }
            : null,
      })),

      spf: {
        found: r.spf.found,
        record: r.spf.record,
        lookupCount: r.spf.lookupCount,
        lookupLimit: 10,
        limitExceeded: r.spf.limitExceeded,
        voidCount: r.spf.voidCount,
        allQualifier: r.spf.allQualifier,
        sendsNoMail: r.spf.sendsNoMail,
        macroTerms: r.spf.macroTerms.map((t) => t.raw),
        suggestedRecord: r.flatten?.record ?? null,
      },

      dkim: {
        // Named to make the caveat unmissable: a miss is not proof of absence.
        selectorsTried: r.dkim.triedCount,
        wildcardDns: r.dkim.wildcardDns,
        keys: r.dkim.keys.map((k) => ({
          selector: k.selector,
          provider: k.provider,
          keyType: k.keyType,
          bits: k.bits ?? null,
          revoked: k.revoked,
          testing: k.testing,
        })),
      },

      dmarc: {
        found: r.dmarc.found,
        record: r.dmarc.record?.raw ?? null,
        foundAt: r.dmarc.record?.foundAt ?? null,
        inherited: r.dmarc.record?.inherited ?? false,
        policy: r.dmarc.record?.policy ?? null,
        subdomainPolicy: r.dmarc.record?.subdomainPolicy ?? null,
        nonExistentPolicy: r.dmarc.record?.nonExistentPolicy ?? null,
        effectivePolicy: r.dmarc.record?.effectivePolicy ?? null,
        // Which of p=/sp=/np= produced effectivePolicy. Additive, so no version bump:
        // a consumer that does not read it sees exactly what it saw before.
        appliedTag: r.dmarc.record?.appliedTag ?? null,
        testMode: r.dmarc.record?.testMode ?? false,
        pct: r.dmarc.record?.pct ?? null,
        rua: r.dmarc.record?.rua.map((u) => u.address) ?? [],
        externalDestinations: r.dmarc.externalDestinations.map((d) => ({
          host: d.uri.host,
          authorisationRequired: d.required,
          authorised: d.authorised,
          expectedRecord: d.expectedRecord,
        })),
      },

      mtaSts: {
        record: r.mtaSts.record,
        mode: r.mtaSts.policy?.mode ?? null,
        policyReachable: Boolean(r.mtaSts.record) && !r.mtaSts.policyError,
        policyMx: r.mtaSts.policy?.mx ?? [],
        unmatchedMx: r.mtaSts.unmatchedMx,
      },
      tlsRpt: { record: r.tlsRpt.record, rua: r.tlsRpt.rua },
      bimi: { record: r.bimi.record, logoUrl: r.bimi.logoUrl ?? null, vmcUrl: r.bimi.vmcUrl ?? null },
      dnssec: r.dnssec.unknown ? null : r.dnssec.signed,

      mx: r.mx.map((m) => ({ priority: m.priority, exchange: m.exchange })),
      nullMx: r.nullMx,

      meta: { dnsQueries: r.queryCount, elapsedMs: r.elapsedMs, truncated: r.spf.truncated },
    });
  } catch (err) {
    if (err instanceof InvalidDomainError) {
      return json({ error: 'invalid_domain', message: err.message }, 400);
    }
    console.error('api check failed', { domain, err });
    return json(
      { error: 'check_failed', message: 'The check could not be completed, usually a DNS timeout.' },
      502,
    );
  }
};
