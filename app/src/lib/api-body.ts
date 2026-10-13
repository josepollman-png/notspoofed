import type { CheckResult } from './check.js';

/**
 * The JSON body of `/api/check`.
 *
 * Deliberately a stable, hand-built shape rather than `JSON.stringify(result)` —
 * dumping internal structures would make every refactor a breaking change for anyone
 * who built against it. `version` is here so that when the shape does change, callers
 * can tell.
 *
 * Lives outside the route so the exact body can be produced from a check run against
 * recorded DNS, without an HTTP server or a rate limiter in the way.
 */

export const API_VERSION = 1;

export function apiBody(r: CheckResult, checkedAt = new Date()) {
  return {
    version: API_VERSION,
    domain: r.domain,
    checkedAt: checkedAt.toISOString(),
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
          ? {
              kind: 'action',
              steps: f.fix.steps,
              // Additive. Set when the fix is a record change at a name that is a CNAME:
              // the change belongs at `target`, never at `host`. See ManagedRecord.
              managedRecord: f.fix.managedRecord
                ? {
                    host: f.fix.managedRecord.host,
                    target: f.fix.managedRecord.target,
                    type: f.fix.managedRecord.type,
                    value: f.fix.managedRecord.value,
                    caveat: f.fix.managedRecord.caveat ?? null,
                  }
                : null,
            }
          : null,
    })),

    spf: {
      found: r.spf.found,
      record: r.spf.record,
      lookupCount: r.spf.lookupCount,
      // Additive: why a receiver would return permerror (lookupCount is then
      // informational), and whether the apex lookup got an answer at all.
      permerror: r.spf.permerror,
      lookupError: r.spf.lookupError,
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
      // Additive. 'unknown' means the lookup got no answer — never read it as absent.
      status: r.dmarc.status,
      cnameChain: r.dmarc.record?.cnameChain ?? [],
      lookups: r.dmarc.lookups.map((l) => ({
        name: l.name, status: l.status, outcome: l.outcome, cnameChain: l.cnameChain,
      })),
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
      lookupStatus: r.mtaSts.lookup.status,
    },
    tlsRpt: { record: r.tlsRpt.record, rua: r.tlsRpt.rua, lookupStatus: r.tlsRpt.lookup.status },
    bimi: {
      record: r.bimi.record, logoUrl: r.bimi.logoUrl ?? null, vmcUrl: r.bimi.vmcUrl ?? null,
      lookupStatus: r.bimi.lookup.status,
    },
    dnssec: r.dnssec.unknown ? null : r.dnssec.signed,

    mx: r.mx.map((m) => ({ priority: m.priority, exchange: m.exchange })),
    nullMx: r.nullMx,

    meta: { dnsQueries: r.queryCount, elapsedMs: r.elapsedMs, truncated: r.spf.truncated },
  };
}
