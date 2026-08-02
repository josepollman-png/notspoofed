---
title: "Your DMARC reports may be going nowhere"
description: "A DMARC record can look flawless and still deliver you no reports at all. Two failure modes that leave you blind, and how to check for both."
question: "Why am I not receiving DMARC reports?"
published: 2026-07-31
updated: 2026-07-31
order: 30
faq:
  - q: "Why am I not getting DMARC aggregate reports?"
    a: "The two usual causes are an external reporting address that has not authorised your domain, and a reporting address on a domain with no MX record. Both leave the DMARC record looking perfectly valid."
  - q: "What is a DMARC external destination verification record?"
    a: "If your rua address is on a different organisational domain, RFC 7489 requires that domain to publish a TXT record at yourdomain.com._report._dmarc.theirdomain.com containing v=DMARC1. Without it, conforming reporters send nothing."
  - q: "Can I send DMARC reports to a Gmail address?"
    a: "Not directly. Google would have to publish an authorisation record in their own DNS for your domain, which they will not do. Use an address on your own domain and forward it, or use a reporting service that publishes the required records."
---

There is a specific kind of failure in DMARC that is worse than a misconfiguration:
the record is valid, every checker says it is fine, and you receive nothing. Months
pass. You assume nobody is forging your domain, when in fact you simply cannot see.

Two causes account for most of it.

## 1. The reporting address is external and has not authorised you

This is the one almost nobody knows about, and it is in the spec.

If your `rua=` address is on a **different organisational domain** from the domain
publishing the DMARC record,
[RFC 7489 §7.1](https://www.rfc-editor.org/rfc/rfc7489#section-7.1) requires the
destination to explicitly consent. Otherwise anyone could point their `rua=` at your
mailbox and use the world's mail infrastructure to flood it.

Consent is a DNS record, published by the **receiving** domain:

```
<your-domain>._report._dmarc.<their-domain>.  TXT  "v=DMARC1"
```

So if `example.com` sends reports to `dmarc@reports.vendor.com`, then
`vendor.com` must publish:

```
example.com._report._dmarc.reports.vendor.com.  TXT  "v=DMARC1"
```

Without it, conforming reporters — including Google, which is most of your report
volume — send nothing at all.

You can see this working in the wild. PayPal sends its aggregate reports to a
third-party provider, and the corresponding authorisation records exist:

```
paypal.com._report._dmarc.rua.agari.com.  TXT  "v=DMARC1;"
```

**What this means practically:** you cannot put a Gmail address in `rua=`. Google is
not going to publish `yourdomain.com._report._dmarc.gmail.com` for you, and you cannot
create records in their zone. The same applies to any address at a domain you do not
control.

If you use a commercial DMARC service, they normally publish these records for you as
part of onboarding — often via a wildcard. If reports never start arriving after you
sign up, this is the first thing to check, and it is worth raising with their support
directly.

**When it does not apply:** reporting to an address on your own organisational domain
needs no authorisation. `example.com` sending reports to `dmarc@mail.example.com` is
fine, because both share the same organisational domain.

## 2. The reporting address has no mail server behind it

Subtler, and easy to create by accident on a domain that only serves a website.

You publish:

```
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

Correct, self-referential, no authorisation needed. But if `example.com` has **no MX
record**, mail servers fall back to its A record
([RFC 5321 §5.1](https://www.rfc-editor.org/rfc/rfc5321#section-5.1) — the implicit
MX rule). For a web-only domain, that A record points at a web server, which does not
speak SMTP. Every report bounces.

The DMARC record itself is flawless. Nothing in it is wrong. You just have no mailbox.

This is easy to hit on a domain used only for a marketing site or a brand
registration — exactly the domains where you have published DMARC as a hardening
measure and are least likely to notice the silence.

**The fix** is to give the domain somewhere to receive mail. Free forwarding services
handle this well: they publish the MX records, and you forward `dmarc@` to a mailbox
you actually read. You do not need a full mail server.

## How to check both, quickly

```sh
# 1. What does your DMARC record say?
dig +short TXT _dmarc.example.com

# 2. If rua points off-domain, is it authorised?
dig +short TXT example.com._report._dmarc.THEIR-DOMAIN.com
#    Expect: "v=DMARC1"  — anything else means reports are refused.

# 3. If rua points at your own domain, can it receive mail?
dig +short MX example.com
#    Empty means every report bounces.
```

## A third, less common cause

Some mailbox providers only send aggregate reports when they see meaningful volume
from your domain. A domain that sends almost nothing may legitimately receive few or
no reports, especially from smaller providers.

Rule out the two DNS causes above first — those are deterministic and fixable. Low
volume is a plausible explanation only after both check out, and even then Google will
typically report on a domain with any real traffic within a day or two.

## Why this matters more than it sounds

The entire value of `p=none` is the reporting. If you are at `p=none` with broken
reporting, you have taken on all the work of DMARC and received none of the benefit —
no protection, because `p=none` blocks nothing, and no visibility either.

It is worth checking on the day you publish, not six months later when someone asks
how the rollout is going.
