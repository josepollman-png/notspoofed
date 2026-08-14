---
title: "DMARC Adoption Statistics (2026)"
titleTag: "DMARC Adoption Statistics 2026: 40 Numbers From a 6,122-Domain Scan"
description: "Current DMARC adoption statistics from an original scan of 6,122 company domains — enforcement rates, p=none share, SPF overlap, and breakdowns by industry and company age. Free to cite."
path: "/dmarc-adoption-statistics"
published: 2026-08-14
updated: 2026-08-14
draft: true
---
Most DMARC statistics in circulation are either vendor-reported or several years old. These come from a single scan we ran on **6,122 Y Combinator company domains in August 2026**, reading each domain's public DNS records directly. Every figure below is free to cite with a link to [notspoofed.com](https://notspoofed.com).

Jump to: [Headline](#headline) · [Policy breakdown](#policy) · [SPF overlap](#spf) · [By industry](#industry) · [By company age](#age) · [Abandoned domains](#abandoned) · [How to cite](#cite)

## Headline numbers {#headline}

- **61.0%** of companies scanned can be email-spoofed — no DMARC record, or a policy of `p=none`.
- **39.0%** publish DMARC at enforcement (`p=quarantine` or `p=reject`).
- **16.7%** are at `p=reject`, the only policy that fully stops spoofing.
- **6,013** domains conclusively classified out of 6,122 scanned; 99 unresolvable and 10 excluded as mis-attributed.

## Policy breakdown {#policy}

| DMARC policy | Domains | Share | Protected? |
|---|---:|---:|---|
| No DMARC record | 1,743 | 29.0% | No |
| `p=none` | 1,923 | 32.0% | No |
| `p=quarantine` | 1,343 | 22.3% | Yes |
| `p=reject` | 1,004 | 16.7% | Yes |
| **Total classified** | **6,013** | **100%** | — |

The most-cited number here is usually the last column collapsed: **61.0% unprotected, 39.0% protected**. But the more interesting one is that `p=none` alone accounts for **32.0%** of all domains — nearly a third of companies have set up DMARC and stopped before the setting that protects them.

## The SPF overlap {#spf}

- **82.2%** of all scanned domains publish an SPF record.
- **73.1%** of *spoofable* domains publish an SPF record.

That second figure is the one worth quoting. Almost three-quarters of the companies that can be spoofed have already published SPF — the step that feels like the fix. SPF validates the envelope sender, not the `From:` header the recipient sees, so it does not stop the attack people are actually worried about. ([Why SPF isn't enough →](/spf-vs-dmarc))

## By industry {#industry}

Share of companies that can be spoofed:

| Industry | Companies | Spoofable | % |
|---|---:|---:|---:|
| Consumer | 832 | 627 | 75.4% |
| Industrials | 443 | 310 | 70.0% |
| Education | 119 | 82 | 68.9% |
| Healthcare | 687 | 462 | 67.2% |
| Real Estate & Construction | 160 | 93 | 58.1% |
| B2B | 3,075 | 1,710 | 55.6% |
| Fintech | 637 | 347 | 54.5% |
| Government | 43 | 23 | 53.5% |

Fintech and B2B lead, consistent with compliance pressure and enterprise security review putting DMARC on a checklist. Consumer lags at 75.4% despite having the largest non-technical user bases — the population least able to spot a forged `support@` message.

## By company age {#age}

Restricted to domains with live MX records (companies actually running email today):

| Batch era | Spoofable |
|---|---:|
| 2011–2015 | 59.6% |
| 2016–2020 | 57.7% |
| 2021–2023 | 57.6% |
| 2024–2026 | 58.2% |

**DMARC adoption has not improved in fifteen years.** A company founded in 2025 is as likely to be spoofable as one founded in 2013. This is the finding we didn't expect, and it's the one most worth citing: enforcement is not something organizations grow into with age or scale — it happens when somebody decides to do it.

## Abandoned domains {#abandoned}

- **87.9%** of domains with no live mail (wound-down or acquired companies) are spoofable.
- **58.4%** of domains with live mail are spoofable.

Dead company domains are the most exposed category in the dataset and the least monitored. They retain brand recognition with former customers while nobody watches the DNS — a ready-made phishing asset.

## Definitions used

- **Spoofable** — publishes no DMARC record, or `p=none`. In both cases a forged message showing the domain's exact `From:` address is delivered normally.
- **Protected** — publishes `p=quarantine` or `p=reject`.
- **Operating** — publishes at least one MX record.

## Method

Passive public DNS reads of `_dmarc.<domain>` TXT, domain TXT (SPF) and MX records across 6,122 unique Y Combinator company domains, August 2026. Failed lookups retried three times; only authoritative answers accepted. Subdomains resolved per RFC 7489 §6.6.3, falling back to the organizational domain's `sp=` (or `p=`) where no record exists at the subdomain. Rows pointing at aggregators, app-store listings or hosting subdomains excluded as measuring third-party DNS. No email was sent and no domain was spoofed. [Full methodology and the underlying study →](/research/yc-email-spoofing-study)

## How to cite {#cite}

> notspoofed.com, *DMARC adoption across 6,122 company domains* (August 2026). https://notspoofed.com/research/yc-email-spoofing-study

The [raw dataset](/research/yc-dmarc-dataset) is available as a CSV under CC BY 4.0.

---

**Check your own domain:** [notspoofed.com](https://notspoofed.com) — free SPF, DKIM and DMARC check, no signup.
