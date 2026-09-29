---
title: "Setting up DMARC on Google Workspace"
titleTag: "Google Workspace DMARC setup: the record and 3 traps to skip"
description: "Set up DMARC for Google Workspace: the TXT record to publish at your DNS host, why to skip pct=, why Gmail sends no ruf reports, and the 48-hour wait."
answer: "DMARC for Google Workspace is a TXT record you publish at your DNS host, not in the Admin console. Set up SPF and DKIM first, click Start authentication, wait 48 hours, then publish v=DMARC1; p=none; rua=mailto:dmarc@yourdomain at _dmarc. Read reports for two to four weeks before moving to quarantine and reject."
question: "How do I set up DMARC for Google Workspace?"
category: "Providers"
published: 2026-08-14
updated: 2026-09-22
order: 22
faq:
  - q: "Do I need SPF and DKIM before DMARC on Google Workspace?"
    a: "Yes, and Google asks you to wait 48 hours after setting them up before publishing DMARC. DMARC has nothing to evaluate without at least one of them, so publishing an enforcing policy first can reject your own mail."
  - q: "Does Google Workspace publish a DMARC record for me automatically?"
    a: "No. SPF and DKIM are configured in the Admin console, but DMARC is a TXT record you add at your DNS host yourself, at _dmarc.yourdomain.com. Nothing in the Admin console creates it."
  - q: "Should I use pct= when rolling out DMARC?"
    a: "Google's documentation still recommends it, but RFC 9989 removed the tag because implementations never agreed on what a value between 0 and 100 meant. Roll out by moving p= from none to quarantine to reject instead, and treat any pct= you find in an existing record as something to remove."
  - q: "Why am I not getting failure reports from Gmail?"
    a: "Gmail does not support the ruf tag and sends no per-message failure reports at all. Aggregate reports via rua work normally. A ruf address that never receives anything from Google is expected behaviour, not a misconfiguration."
---

Google Workspace configures SPF and DKIM inside the Admin console, which leads a lot of
people to assume DMARC works the same way. It does not: **DMARC is a DNS record you
publish yourself**, and nothing in the Admin console creates it for you.

The mechanical steps are in
[Google's own documentation](https://knowledge.workspace.google.com/admin/security/set-up-dmarc)
and are worth following. This page covers the three places that documentation will
cost you if you follow it literally.

## Before you publish anything

DMARC evaluates the results of SPF and DKIM. Publish it first and you have an
instruction with nothing to instruct on.

1. **SPF** — one TXT record at the domain root including Google:
   `v=spf1 include:_spf.google.com ~all`. If you send through anything else as well,
   count your lookups; the limit is ten and it is easy to cross with two or three
   services. → [SPF: too many DNS lookups](/guide/spf-too-many-dns-lookups)
2. **DKIM** — Admin console → Apps → Google Workspace → Gmail → Authenticate email.
   Generate the key, publish the TXT record it gives you, then come back and click
   **Start authentication**. Generating without starting is the step people miss.
3. **Wait 48 hours.** This is Google's own instruction, not caution on my part, and the
   reason is propagation: an enforcing DMARC policy that goes live before DKIM signing
   is fully in effect rejects your own mail.

## The record

At your DNS host, not in the Admin console:

| Field | Value |
|---|---|
| Type | `TXT` |
| Host / Name | `_dmarc` (some hosts want the full `_dmarc.example.com`) |
| Value | see below |

Start here:

```
v=DMARC1; p=none; rua=mailto:dmarc@example.com
```

`v=DMARC1` must come first and `p=` must come second. Everything else is optional.

## Trap 1: Google still recommends a tag the RFC removed

Google's example record includes `pct=100`, and their rollout advice tells you to start
at `pct=10` and increase it.

**Do not build your rollout on that.** [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989)
— the current DMARC specification — removed `pct=` entirely, because implementations
never agreed on what a value between 0 and 100 actually meant. A record relying on
`pct=10` to limit blast radius may be applying your policy to 10% of failing mail at one
receiver and 100% at another, and you have no way to tell which.

Roll out by moving the policy itself instead:

```
p=none        →  collect reports, change nothing
p=quarantine  →  failures go to spam
p=reject      →  failures are refused
```

That progression is understood identically everywhere. If you have an existing record
carrying `pct=`, the checker flags it — see
[what DMARC p=none actually does](/guide/dmarc-p-none) for how long to sit at each
stage.

## Trap 2: Gmail ignores `ruf` entirely

Plenty of guides give you a record with both `rua=` and `ruf=`. **Gmail does not support
`ruf`** and sends no per-message failure reports, so a `ruf` address that stays empty is
expected, not broken. Do not spend an afternoon debugging it.

Worth knowing what you are giving up: `ruf` reports contain headers from individual
failing messages, which is the fastest way to identify an unknown sender. Without them,
on a Google-heavy domain, you are working from aggregate `rua` data alone — counts per
source IP, no message detail.

## Trap 3: where the reports go

`rua=` reports arrive as one zipped XML attachment per receiver per day. On a domain of
any size that is a lot of mail, and Google explicitly recommends a dedicated mailbox or
group rather than a personal address.

The failure mode nobody warns about: if you point `rua=` at an address on a **different**
domain — a consultant, a DMARC vendor, a mailbox at your parent company — that other
domain has to publish a record authorising it. Without it, the reports are silently
discarded by every conforming receiver, and your record looks perfect while you receive
nothing at all.

→ [Your DMARC reports may be going nowhere](/guide/dmarc-reports-not-arriving)

## Subdomains

A policy at `example.com` covers subdomains by inheritance, so
`invoices.example.com` is protected by your main record unless you override it. That is
usually what you want. The case to watch is a subdomain that sends through a *different*
service — it inherits an enforcing policy it may not be able to satisfy.

## Rollout, in order

1. SPF published and under ten lookups.
2. DKIM generated **and started** in the Admin console.
3. Wait 48 hours.
4. Publish `p=none` with a `rua=` address you can actually read.
5. Read reports for two to four weeks. Every legitimate sender should be passing SPF or
   DKIM *aligned* before you go further.
6. `p=quarantine`, then `p=reject`.

Since February 2024 Google requires DMARC from bulk senders, so for anyone sending in
volume this stops at step 6, not step 4.
→ [Google and Yahoo's sender requirements](/guide/google-yahoo-sender-requirements)

---

[Check the domain](/) after each step — it reads the published records rather than the
Admin console, which is the only way to see what receivers will actually see. The
[compliance checker](/tools/gmail-yahoo-compliance) runs the full bulk-sender list.
