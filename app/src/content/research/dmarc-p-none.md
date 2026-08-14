---
title: "What Does DMARC p=none Actually Mean?"
titleTag: "What Does DMARC p=none Mean? (And Why It Doesn't Protect You)"
description: "p=none tells receivers to deliver forged mail anyway and just report it. We found 1,923 companies stuck there. What it does, why it's the right first step, and how to move past it."
path: "/dmarc-p-none"
published: 2026-08-14
updated: 2026-08-14
draft: true
---
Short answer: **`p=none` means "monitor only."** Receiving mail servers check whether a message really came from your domain, send you a report about what they found — and then deliver the message either way, including the forged ones.

It is a useful setting. It is not protection. We scanned 6,122 company domains in August 2026 and found **1,923 of them (32.0%) sitting at `p=none`** — very nearly as many as the 1,743 with no DMARC record at all.

## What the p tag controls

A DMARC record is a DNS TXT record at `_dmarc.yourdomain.com`:

```
v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
```

The `p` tag is the policy: your instruction to receiving servers about what to do when a message claiming to be from your domain fails authentication.

| Policy | Receiver's action on a forged message | Your exposure |
|---|---|---|
| `p=none` | Deliver to the inbox, report it to you | Unchanged — full |
| `p=quarantine` | Deliver to the spam folder | Substantially reduced |
| `p=reject` | Refuse it at the SMTP layer | Closed |

At `p=none`, a message forging your exact `From:` address arrives in your customer's inbox looking legitimate. You'll find out about it in an XML report, typically the next day.

## So is p=none useless?

No — and this is the part worth being fair about. `p=none` is the correct **first** step, and skipping it is how people break their own email.

When you turn on DMARC reporting, you almost always discover legitimate senders you'd forgotten: your invoicing tool, your CRM, an ATS, a support desk, a marketing platform, a server sending password resets. If you jump straight to `p=reject`, all of those stop being delivered.

`p=none` is the observation window that lets you find them safely. It's a staging area, not a destination.

## The problem is how long people stay there

`p=none` is where DMARC rollouts go quiet. The record gets published, reports start arriving, they're XML, nobody reads them, and the project moves down the priority list. The domain looks configured. Someone ticks the box on a security questionnaire. Nothing is protected.

That's what 1,923 companies in our dataset look like. Many of them clearly *started* deliberately — they configured a `rua=` reporting address, which nobody does by accident. They just never took the last step.

An attacker doesn't care about your intentions. To them, `p=none` and no DMARC record are the same target.

## How to tell where you are

```bash
dig +short TXT _dmarc.yourdomain.com
```

- Nothing returned → no DMARC. Spoofable.
- `p=none` → monitoring only. Spoofable.
- `p=quarantine` or `p=reject` → at enforcement.

Or check all three records at once with [notspoofed.com](https://notspoofed.com).

## Two settings that quietly undo your policy

Worth checking even if your `p=` looks right:

**`sp=`** sets the policy for subdomains. A domain at `p=reject; sp=none` has a protected root and wide-open subdomains — `billing.yourcompany.com` remains spoofable. If you don't need a different subdomain policy, leave `sp` out entirely so subdomains inherit `p`.

**`pct=`** applies your policy to only a percentage of failing mail. `p=reject; pct=10` rejects 10% of forged messages and delivers the other 90%. It's a legitimate ramping tool — but a `pct` left at a low value after the rollout finished is a common way to be at "reject" and still be spoofable.

## Moving from p=none to enforcement

1. **Collect reports for 2–4 weeks.** Feed the `rua` address into any DMARC report parser; raw XML is not worth reading by hand.
2. **Inventory every legitimate sender.** Build the list from the reports, not from memory.
3. **Fix alignment for each.** Usually a custom return-path (SPF alignment) or a DKIM key published on your domain. Your vendors document this.
4. **Confirm your own mail passes** with aligned SPF or DKIM across all of them.
5. **Move to `p=quarantine`.** Watch the reports for two weeks; failures now go to spam, which is recoverable.
6. **Move to `p=reject`.** Done.

Most domains can complete this in a month. The work is in steps 2 and 3 — the policy change itself is a one-line DNS edit.

## The record you want to end up with

```
v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1
```

No `sp` (subdomains inherit), no `pct` (applies to everything), reporting still on so you keep visibility.

---

**Related:** [Why SPF alone doesn't stop spoofing](/spf-vs-dmarc) · [DMARC adoption statistics 2026](/dmarc-adoption-statistics) · [The full 6,122-domain study](/research/yc-email-spoofing-study)

**Check your domain free:** [notspoofed.com](https://notspoofed.com)
