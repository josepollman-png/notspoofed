---
title: "Dataset: DMARC Posture of 6,157 Y Combinator Companies"
titleTag: "Dataset: DMARC Records of 6,157 YC Companies, Two Runs (CSV, CC BY 4.0)"
description: "Free CSV: DMARC policy, SPF and MX status for 6,157 Y Combinator company domains, scanned in August and September 2026. CC BY 4.0, cite with attribution."
path: "/research/yc-dmarc-dataset"
published: 2026-08-14
updated: 2026-09-03
draft: false
---
This is the raw data behind [our study of email spoofing exposure across Y Combinator companies](/research/yc-email-spoofing-study). It's free to download, analyse and republish with attribution.

The scan has been run in full twice. The study page's figures come from the September run; the August run stays published unchanged so that anything already citing it keeps resolving, and the diff between the two is its own file.

**[⬇ Download yc-dmarc-2026-09.csv](/data/yc-dmarc-2026-09.csv)** — September 3, 2026 run. 6,157 rows, ~577 KB, CC BY 4.0

**[⬇ Download data-quality-report.txt](/data/yc-dmarc-data-quality-report.txt)** — the September audit trail: every row excluded, repaired, re-resolved or hand-corrected

**[⬇ Download yc-dmarc-changes-2026-08-to-2026-09.csv](/data/yc-dmarc-changes-2026-08-to-2026-09.csv)** — the 72 domains whose verdict changed between the runs, with old and new policy

**[⬇ Download yc-dmarc-2026-08.csv](/data/yc-dmarc-2026-08.csv)** — August 14, 2026 run, 6,122 rows · [its audit trail](/data/yc-dmarc-2026-08-data-quality-report.txt)

## What's in it

One row per unique company domain.

| Column | Values | Description |
|---|---|---|
| `name` | text | Company name as listed in the YC directory |
| `batch` | e.g. `Winter 2012` | YC batch |
| `industry` | e.g. `B2B`, `Consumer` | YC's own industry label |
| `domain` | e.g. `example.com` | Primary domain, lowercased and de-duplicated |
| `org_domain` | e.g. `example.com` | Organizational domain (Public Suffix List, private suffixes included). Differs from `domain` on subdomain rows |
| `spf` | `yes` / `no` | Whether a `v=spf1` TXT record is published |
| `mx` | `yes` / `no` | Whether the domain publishes MX records (live mail) |
| `dmarc_policy` | `no-dmarc`, `none`, `quarantine`, `reject`, `lookup-failed` | The effective `p=` value, or absence of a record |
| `policy_source` | `own record`, `inherited from <domain> (sp=)`, `no record`, `unresolved`, `hand-verified: …` | Where the policy came from — see the RFC 7489 note below |
| `verdict` | `SPOOFABLE`, `PROTECTED`, `UNKNOWN` | Derived classification |
| `flag` | ``, `subdomain`, `mis-attributed`, `platform-hosted`, `duplicate-domain`, `invalid-domain` | Data-quality flag |
| `included` | `yes` / `no` | Whether the row counts toward our published statistics |

The September file has 6,157 rows; **filter to `included=yes`** (6,147 rows) to reproduce our
numbers. The 10 excluded rows are kept in the file for transparency rather than
silently deleted.

The changes file has one row per domain that was conclusively classified in both runs and whose verdict differed: `name`, `batch`, `domain`, `old_policy`, `new_policy`, `old_verdict`, `new_verdict`. It is derived from the two run files and can be regenerated from them.

### Classification rules

- `SPOOFABLE` — no DMARC record, or `p=none`. A forged message showing the domain's exact `From:` address is delivered.
- `PROTECTED` — `p=quarantine` or `p=reject`.
- `UNKNOWN` — no authoritative DNS answer after three attempts. 98 rows in the September run. Excluded from every percentage we publish; we'd suggest you exclude them too rather than assuming either way.

## Summary of what's inside

September 3, 2026 run, with the August 14 figure alongside where it differs:

| Measure | September | August |
|---|---:|---:|
| Domains scanned | 6,157 | 6,122 |
| — excluded (mis-attributed / platform-hosted) | 10 | 10 |
| — unresolved (`UNKNOWN`) | 98 | 99 |
| Conclusively classified | 6,049 | 6,013 |
| Spoofable | 3,657 (60.5%) | 3,666 (61.0%) |
| — no DMARC record | 1,733 | 1,743 |
| — `p=none` | 1,924 | 1,923 |
| Protected | 2,392 (39.5%) | 2,347 (39.0%) |
| — `p=quarantine` | 1,358 | 1,343 |
| — `p=reject` | 1,034 | 1,004 |
| Publishing SPF | 82.3% | 82.2% |
| Spoofable *and* publishing SPF | 73.1% | 73.1% |
| Spoofable, live mail (MX) | 57.8% | 58.4% |
| Spoofable, no live mail | 88.3% | 87.9% |

### What changed between the runs

Among the 5,959 domains conclusively classified in both runs, 56 moved from spoofable to protected and 16 moved from protected to spoofable, taking that stable cohort from 60.9% to 60.2% spoofable. 82 domains were new to the directory in September (62 of them, 75.6%, spoofable) and 47 had been removed. The headline moved less than the cohort did because the new arrivals are worse than average.

## How it was collected

Passive public DNS resolution, August 14 and September 3, 2026. For each domain we queried the `_dmarc.<domain>` TXT record, the domain's TXT records (for SPF), and its MX records.

Failed lookups were retried up to three times, and only an authoritative response — records returned, or a definitive NXDOMAIN/NoAnswer — was accepted as conclusive. This matters more than it sounds: a DNS timeout and a genuine absence of a DMARC record are indistinguishable if you only test for an empty response, and treating them the same inflates the spoofable count. On the August run's test slice, fixing this moved the headline figure from 65.5% to 61.0%.

**Subdomains follow RFC 7489 §6.6.3.** Where the directory lists a subdomain, a direct `_dmarc` lookup is the wrong question: when no record exists at the subdomain, receivers fall back to the organizational domain's record and apply its `sp=` value, or its `p=` when `sp=` is absent. A subdomain can be fully protected by its parent while looking bare on a direct query. The `policy_source` column records which applied for every row. Organizational domains come from the Public Suffix List *with private suffixes included*, so a company hosted at `something.vercel.app` is its own organizational domain and does not inherit Vercel's policy.

Rows where the directory pointed at somebody else's DNS — an aggregator profile, an app-store listing, a hosting subdomain — are flagged and excluded, as are domain strings that arrived with tracking parameters attached (`example.com?utm_source=yc` is not a resolvable hostname; those were repaired and re-scanned). Every correction is itemised in the accompanying `data-quality-report.txt`.

**Changes between runs were verified before being counted.** Every domain whose verdict differed between August and September was re-queried against Cloudflare (1.1.1.1) and Google (8.8.8.8). Where those two disagreed, the domain's authoritative nameserver was queried directly and its answer used. One row was corrected on that basis — the scan had seen `p=reject`, the nameserver publishes `p=none` — and carries `hand-verified` in `policy_source` with the check itemised in the audit trail.

**No email was sent. No domain was spoofed.** Every check reads public DNS records — the same information any receiving mail server consults, and the same check [notspoofed.com](https://notspoofed.com) runs on a single domain.

## Known limitations

We'd rather state these than have you find them:

- **Directory domain accuracy.** Company websites come from the YC directory, which occasionally points at an acquirer's domain or a profile page for defunct companies. We filtered obvious cases; assume a small residue.
- **Point-in-time.** DNS changes. Each file is accurate as of its own scan date, and the changes file shows how much moved in twenty days: about 1.2% of domains changed verdict.
- **DKIM isn't included.** DKIM selectors can't be enumerated from DNS without knowing the selector name, so DKIM presence is out of scope. It doesn't affect the spoofable/protected verdict, which depends on DMARC policy.
- **`pct` and `sp` aren't in the verdict.** A domain at `p=reject; pct=10` is counted as protected though it only rejects 10% of forged mail. Our figures are therefore slightly *generous* to the protected side.
- **Sampling frame.** YC companies are venture-backed tech startups. They are not representative of businesses generally, and are probably more technically sophisticated than average — meaning the true rate across all small businesses is likely worse, not better.

## Licence and citation

Released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Use it commercially, republish it, build on it — just attribute.

> notspoofed.com, *DMARC posture of 6,157 Y Combinator companies* (September 2026). https://notspoofed.com/research/yc-email-spoofing-study

Writing something with this data and want a figure we haven't published, or the scanner source? Ask — we're happy to help, and we'll run a custom cut if it's useful.

---

**Check your own domain:** [notspoofed.com](https://notspoofed.com) — free SPF, DKIM and DMARC check, no signup.
