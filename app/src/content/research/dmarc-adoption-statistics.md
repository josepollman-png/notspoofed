---
title: "DMARC Adoption Statistics (2026)"
titleTag: "DMARC Adoption Statistics 2026: 40 Numbers From a 6,157-Domain Scan"
description: "DMARC adoption statistics from a 6,157-domain scan run twice in 2026: enforcement rates, p=none share, SPF overlap, by industry and company age. Free to cite."
path: "/dmarc-adoption-statistics"
published: 2026-08-14
updated: 2026-09-03
draft: false
---
Most DMARC statistics in circulation are either vendor-reported or several years old. These come from a scan we ran on **6,157 Y Combinator company domains on September 3, 2026**, reading each domain's public DNS records directly — and from the same scan run three weeks earlier, which is what lets us say how fast the numbers move. Every figure below is free to cite with a link to [notspoofed.com](https://notspoofed.com).

Jump to: [Headline](#headline) · [Policy breakdown](#policy) · [SPF overlap](#spf) · [By industry](#industry) · [By company age](#age) · [Abandoned domains](#abandoned) · [Change over time](#change) · [How to cite](#cite)

## Headline numbers {#headline}

- **60.5%** of companies scanned can be email-spoofed — no DMARC record, or a policy of `p=none`.
- **39.5%** publish DMARC at enforcement (`p=quarantine` or `p=reject`).
- **17.1%** are at `p=reject`, the only policy that fully stops spoofing.
- **6,049** domains conclusively classified out of 6,157 scanned; 98 unresolvable and 10 excluded as mis-attributed.

## Policy breakdown {#policy}

| DMARC policy | Domains | Share | Protected? |
|---|---:|---:|---|
| No DMARC record | 1,733 | 28.6% | No |
| `p=none` | 1,924 | 31.8% | No |
| `p=quarantine` | 1,358 | 22.4% | Yes |
| `p=reject` | 1,034 | 17.1% | Yes |
| **Total classified** | **6,049** | **100%** | — |

The most-cited number here is usually the last column collapsed: **60.5% unprotected, 39.5% protected**. But the more interesting one is that `p=none` alone accounts for **31.8%** of all domains — nearly a third of companies have set up DMARC and stopped before the setting that protects them.

## The SPF overlap {#spf}

- **82.3%** of all scanned domains publish an SPF record.
- **73.1%** of *spoofable* domains publish an SPF record.

That second figure is the one worth quoting. Almost three-quarters of the companies that can be spoofed have already published SPF — the step that feels like the fix. SPF validates the envelope sender, not the `From:` header the recipient sees, so it does not stop the attack people are actually worried about. ([Why SPF isn't enough →](/spf-vs-dmarc))

## By industry {#industry}

Share of companies that can be spoofed:

| Industry | Companies | Spoofable | % |
|---|---:|---:|---:|
| Consumer | 837 | 621 | 74.2% |
| Industrials | 453 | 318 | 70.2% |
| Education | 120 | 83 | 69.2% |
| Healthcare | 685 | 460 | 67.2% |
| Real Estate & Construction | 160 | 93 | 58.1% |
| B2B | 3,091 | 1,702 | 55.1% |
| Government | 44 | 24 | 54.5% |
| Fintech | 642 | 344 | 53.6% |

Fintech and B2B lead, consistent with compliance pressure and enterprise security review putting DMARC on a checklist. Consumer lags at 74.2% despite having the largest non-technical user bases — the population least able to spot a forged `support@` message.

## By company age {#age}

Restricted to domains with live MX records (companies actually running email today):

| Batch era | Spoofable |
|---|---:|
| 2011–2015 | 58.8% |
| 2016–2020 | 57.2% |
| 2021–2023 | 57.2% |
| 2024–2026 | 57.1% |

**DMARC adoption has not improved in fifteen years.** A company founded in 2025 is as likely to be spoofable as one founded in 2013. This is the finding we didn't expect, and it's the one most worth citing: enforcement is not something organizations grow into with age or scale — it happens when somebody decides to do it.

## Abandoned domains {#abandoned}

- **88.3%** of domains with no live mail (wound-down or acquired companies) are spoofable.
- **57.8%** of domains with live mail are spoofable.

Dead company domains are the most exposed category in the dataset and the least monitored. They retain brand recognition with former customers while nobody watches the DNS — a ready-made phishing asset.

## Change over time {#change}

The scan was first run on August 14, 2026 and repeated in full on September 3. Among the **5,959 domains** conclusively classified in both runs:

- **56** moved from spoofable to protected — about **0.9%** of the cohort in 20 days.
- **16** moved from protected back to spoofable. Three of them had been at `p=reject`.
- The cohort's spoofable share went from **60.9% to 60.2%**.
- **82** companies were new to the directory, almost all from the Summer and Fall 2026 batches. **75.6%** of them are spoofable, against 60.5% overall.

Two things worth citing from that. Enforcement is not permanent: a DMARC policy is a DNS record, and more than one in five of the verdict changes we saw went the wrong way. And the newest companies arrive worse than the population they join, which is consistent with the age table above — nothing about maturing fixes this by itself.

## Definitions used

- **Spoofable** — publishes no DMARC record, or `p=none`. In both cases a forged message showing the domain's exact `From:` address is delivered normally.
- **Protected** — publishes `p=quarantine` or `p=reject`.
- **Operating** — publishes at least one MX record.

## Method

Passive public DNS reads of `_dmarc.<domain>` TXT, domain TXT (SPF) and MX records across 6,157 unique Y Combinator company domains, September 3, 2026, and 6,122 on August 14. Failed lookups retried three times; only authoritative answers accepted. Subdomains resolved per RFC 7489 §6.6.3, falling back to the organizational domain's `sp=` (or `p=`) where no record exists at the subdomain. Rows pointing at aggregators, app-store listings or hosting subdomains excluded as measuring third-party DNS. Every domain whose verdict changed between the runs was re-verified against two public resolvers and, where they disagreed, the authoritative nameserver. No email was sent and no domain was spoofed. [Full methodology and the underlying study →](/research/yc-email-spoofing-study)

## How to cite {#cite}

> notspoofed.com, *DMARC adoption across 6,157 company domains* (September 2026). https://notspoofed.com/research/yc-email-spoofing-study

The [raw dataset](/research/yc-dmarc-dataset) for both runs is available as CSV under CC BY 4.0.

---

**Check your own domain:** [notspoofed.com](https://notspoofed.com) — free SPF, DKIM and DMARC check, no signup.
