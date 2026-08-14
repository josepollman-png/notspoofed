---
title: "SPF, DKIM and DMARC on Cloudflare DNS"
description: "Cloudflare hosts your DNS, it does not send your mail. The orange cloud, the inbound-only Email Routing trap, and what DMARC Management changes in your record."
question: "How do I set up SPF, DKIM and DMARC on Cloudflare?"
published: 2026-08-14
updated: 2026-08-14
order: 26
faq:
  - q: "Does the orange cloud break my email?"
    a: "Not by itself. Cloudflare does not proxy SMTP on port 25, and MX and TXT records cannot be proxied at all, so authentication records are unaffected. The real risk is proxying an A record that your SPF relies on through an a or mx mechanism, because the address receivers resolve is then Cloudflare's, not your mail server's."
  - q: "Can I send email through Cloudflare Email Routing?"
    a: "No. Email Routing forwards inbound mail to another address and does not send outbound mail. Sending requires an external provider, whose SPF include and DKIM records you publish yourself."
  - q: "Is Cloudflare DMARC Management free?"
    a: "Yes, on all plans, provided your DNS is on Cloudflare. Enabling it adds a Cloudflare rua address to your DMARC record — appended alongside any address you already have rather than replacing it — and reports start arriving within about 24 hours."
  - q: "Cloudflare created a DMARC record for me. Is that enough?"
    a: "It is a start, not a finish. A record created for reporting typically sits at p=none, which collects data and blocks nothing. Spoofing protection only begins when you raise the policy to quarantine and then reject."
---

Cloudflare is a common source of confusion here because it occupies a role the other
providers do not: **it hosts your DNS, it does not send your mail.** SPF, DKIM and DMARC
are records you publish *at* Cloudflare on behalf of whoever actually sends for you —
Google Workspace, Microsoft 365, an ESP — so the content of those records is decided by
your sender, not by Cloudflare.

What Cloudflare does change is a handful of platform-specific behaviours, and they trip
people up in predictable ways.

## The orange cloud

The short version: **the proxy does not break authentication.** MX and TXT records cannot
be proxied at all, and Cloudflare does not proxy SMTP on port 25 by default — proxying
mail traffic requires Spectrum with explicit SMTP configuration.

The failure that does happen is indirect. If your SPF record leans on an `a` or `mx`
mechanism, receivers resolve that name to decide whether the connecting server is
authorised. Proxy the record behind the orange cloud and the address they get back is
Cloudflare's, not your mail server's — so a mechanism that used to match stops matching,
and nothing in the SPF syntax looks wrong.

Two ways out, in order of preference:

1. **Name the sender explicitly** rather than by reference — `include:` for a provider,
   or `ip4:` for a fixed address. This is better practice regardless of Cloudflare.
2. Keep a **DNS-only (grey cloud)** record for the mail host, e.g. `mail.example.com`,
   and point the `a`/`mx` mechanism at that.

## Email Routing is inbound only

Cloudflare Email Routing forwards mail arriving at your domain to a mailbox somewhere
else. It is free, it is useful, and **it cannot send.** People enable it, see "email" in
the dashboard, and assume outbound is handled — then wonder why their contact form's mail
fails authentication.

Outbound still needs a real sending provider, and that provider's `include:` and DKIM
records are what go in your zone. Note too that Email Routing adds records of its own
when enabled; if you already had an SPF record, check afterwards that you still have
**exactly one** TXT record starting `v=spf1`. Two SPF records is a permanent error, not
a merge.

## DMARC Management: useful, and it edits your record

Cloudflare DMARC Management is free on every plan and needs only that your DNS is with
Cloudflare. It parses the daily aggregate XML for you and shows which sources are
sending as your domain — genuinely the tedious part of DMARC, and worth turning on.

Be clear on what enabling it does to your zone:

- **No DMARC record?** Cloudflare creates one.
- **Record already there?** Cloudflare **appends** an additional `rua=` entry pointing at
  its own address. Existing `rua` values are preserved, so a vendor you already send
  reports to keeps receiving them.

Two caveats from Cloudflare's own documentation. Allow up to 24 hours for the first
report. And DMARC Management does not support modifying SPF records when a CNAME in your
zone points to an external domain — changes made in that state can invalidate your
policy, so check the SPF record by hand afterwards.

> Worth saying plainly: report aggregation is something Cloudflare does and this checker
> does not. If you want a dashboard of who is sending as your domain over time, use
> DMARC Management, or dmarcian or EasyDMARC. This tool answers a different question —
> whether the records you have published are correct right now, and what to publish if
> they are not.

## A record that a reporting tool created is not a finished policy

The one thing to watch after enabling any reporting product: it will happily leave you
at `p=none`, because that is the safe default for collecting data. `p=none` blocks
nothing. It is the right place to start and the wrong place to stop, and a domain that
sits there indefinitely is spoofable indefinitely.

→ [What DMARC p=none actually does](/guides/dmarc-p-none/)

## Publishing the records in the dashboard

DNS → Records → Add record. The fields that catch people:

| Record | Name | Notes |
|---|---|---|
| SPF | `@` | TXT. One record only. Cloudflare shows `@` as your root domain. |
| DKIM | `selector._domainkey` | TXT or CNAME, whichever your sender specifies. Do not add your domain to the end — Cloudflare appends it. |
| DMARC | `_dmarc` | TXT. Same rule about not appending the domain. |

That last point causes a quiet, common failure: typing `_dmarc.example.com` into the Name
field produces a record at `_dmarc.example.com.example.com`, which resolves for nobody.
After saving, check the row shows the name you expect.

---

[Check the domain](/) once the records are in. It resolves them the way a receiver would,
which catches the doubled-name mistake and the two-SPF-records mistake immediately.
