---
title: "SPF vs DMARC: Why SPF Alone Doesn't Stop Email Spoofing"
titleTag: "SPF vs DMARC: Why SPF Alone Doesn't Stop Spoofing (With Data)"
description: "SPF checks the envelope sender, not the From address your recipients see. We scanned 6,122 domains: 73.1% of spoofable ones already had SPF. Here's the gap and how to close it."
path: "/spf-vs-dmarc"
published: 2026-08-14
updated: 2026-08-14
draft: true
---
If you've published an SPF record, you've done something real — but you probably haven't stopped anyone from spoofing your domain.

We scanned 6,122 company domains in August 2026 and found that **73.1% of the domains that can be spoofed already publish a valid SPF record**. These aren't teams that ignored email security. They're teams that did the step that feels like the fix and stopped there.

Here's why that gap exists.

## The two "from" addresses in every email

Every email has two sender addresses, and most people only ever see one.

**The envelope sender** (`Return-Path`, also called MAIL FROM) is the address the sending server declares during the SMTP handshake. It's used for bounces. Your recipient never sees it.

**The header From** (`From:`) is the address displayed in the inbox. It's what your recipient reads, trusts, and decides to act on.

These can be completely different addresses, and nothing in the base email protocol requires them to match.

## What SPF actually checks

SPF answers one question: *is this server allowed to send mail for the envelope sender's domain?*

A receiving server reads the envelope sender's domain, looks up its SPF record, and checks whether the connecting IP is on the approved list.

```
v=spf1 include:_spf.google.com include:sendgrid.net ~all
```

That's the whole scope. **SPF never looks at the `From:` header.**

So an attacker sends a message with an envelope sender on a domain they legitimately control — one that passes its own SPF check perfectly — and a `From:` header reading `billing@yourcompany.com`. SPF passes. The message lands. Your customer sees your name.

This isn't an SPF bug. SPF was designed to authenticate the transport layer, and it does that correctly. It just isn't the layer your recipients look at.

## What DKIM adds, and what it doesn't

DKIM cryptographically signs the message so a receiver can verify it wasn't altered and that it came from a domain holding the signing key.

That's stronger — but on its own it still doesn't help, because DKIM doesn't require the signing domain to match the `From:` domain either. A message can carry a perfectly valid DKIM signature from `attacker-domain.com` while displaying `From: billing@yourcompany.com`.

Valid signature. Wrong sender. Still delivered.

## What DMARC does that neither can

DMARC adds the missing piece: **alignment**. It requires that the domain in the visible `From:` header matches the domain that passed SPF or DKIM.

That single requirement is what closes the spoofing hole. Now an attacker can't borrow a passing result from a domain they control — the passing domain has to be *your* domain.

DMARC then adds the second missing piece: **a policy telling receivers what to do when alignment fails.**

```
v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com
```

| Policy | What receivers do with forged mail | Protects you? |
|---|---|---|
| `p=none` | Deliver it normally, send you a report | **No** |
| `p=quarantine` | Send it to spam | Mostly |
| `p=reject` | Refuse it outright | Yes |

## The trap: p=none is not protection

This is where most of the exposure in our scan actually sits. **1,923 of the 6,013 domains we classified — 32.0% — publish DMARC at `p=none`.**

`p=none` means "monitor only." Alignment is checked, failures are reported to you, and the forged message is **delivered to your customer anyway**. From an attacker's perspective a `p=none` domain is exactly as spoofable as one with no DMARC record at all.

`p=none` is the correct *first* step — it lets you find your legitimate senders before you start blocking. It just isn't a destination, and a lot of rollouts quietly stop there.

## Do you need all three?

Yes, and in this order:

1. **SPF** — authorizes your sending servers.
2. **DKIM** — signs your messages so they survive forwarding.
3. **DMARC** — requires one of the above to *align* with your visible `From:`, and tells receivers what to do when neither does.

SPF and DKIM are the inputs. DMARC is the part that turns them into protection. Skipping DMARC is like installing locks and never closing the door.

## How to check where you stand

Fastest: enter your domain at **[notspoofed.com](https://notspoofed.com)** — it reads all three records and tells you whether you can currently be spoofed.

Or check by hand:

```bash
dig +short TXT yourdomain.com | grep spf1        # SPF
dig +short TXT _dmarc.yourdomain.com            # DMARC — look at p=
```

If the second command returns nothing, or returns `p=none`, your domain can be spoofed right now regardless of what your SPF record says.

## Getting to enforcement

1. Publish `v=DMARC1; p=none; rua=mailto:you@yourdomain.com`.
2. Read the aggregate reports for 2–4 weeks. Find every legitimate sender — your ESP, invoicing tool, CRM, support desk, HR system. There are always more than you expect.
3. Fix alignment for each one (usually a custom return-path or a DKIM key on your domain).
4. Move to `p=quarantine`. Watch for a couple of weeks.
5. Move to `p=reject`.

Step 5 is where protection begins. Based on our data, that's the step most companies never take.

---

**Related:** [DMARC adoption statistics 2026](/dmarc-adoption-statistics) · [What p=none actually means](/guides/dmarc-p-none/) · [The full 6,122-domain study](/research/yc-email-spoofing-study)

**Check your domain free:** [notspoofed.com](https://notspoofed.com)
