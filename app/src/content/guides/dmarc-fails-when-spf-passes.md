---
title: "Why DMARC fails when SPF and DKIM pass"
description: "Passing SPF is not enough — the domain that passed has to match the one your recipient sees. How to read alignment from your own message headers."
question: "Why does DMARC fail when SPF passes?"
published: 2026-07-31
updated: 2026-07-31
order: 25
faq:
  - q: "Why does DMARC fail when SPF passes?"
    a: "Because DMARC requires alignment as well as a pass. SPF authenticates the envelope sender, which for mail sent through a marketing or invoicing platform is usually that platform's own domain — not the domain in your From header. A pass for the wrong domain does nothing for DMARC."
  - q: "What is DMARC alignment?"
    a: "Alignment means the domain that authenticated matches the domain in the visible From header. For SPF that is the envelope sender domain; for DKIM it is the d= value of a valid signature. DMARC passes if at least one of them both passes and aligns."
  - q: "What is the difference between relaxed and strict alignment?"
    a: "Relaxed alignment, the default, only requires the organisational domains to match, so mail.example.com aligns with example.com. Strict alignment requires an exact match. You control this with the aspf and adkim tags in your DMARC record."
---

This header block confuses almost everyone who sees it for the first time:

```
Authentication-Results: mx.google.com;
       spf=pass smtp.mailfrom=bounce@esp-vendor.net;
       dkim=pass header.d=esp-vendor.net;
       dmarc=fail (p=REJECT) header.from=yourcompany.com
```

SPF passed. DKIM passed. DMARC failed. Nothing is broken, no record is malformed, and
the mail is being rejected anyway.

The missing concept is **alignment**.

## The rule

DMARC does not ask "did SPF pass?". It asks:

> Did SPF or DKIM pass **for the same domain the recipient sees in the From: header?**

Three domains are involved in an email, and only one of them is visible to a human:

| Identifier | Where it lives | Who sees it |
|---|---|---|
| **From:** header | The message | **Your recipient** |
| Envelope sender (`MAIL FROM`) | The SMTP conversation | Nobody — used for bounces, checked by SPF |
| DKIM `d=` | The signature header | Nobody — checked by DKIM |

SPF authenticates the *envelope sender*. DKIM authenticates the *signing domain*.
Neither of them is the From: header. DMARC's entire job is to insist that at least one
of them matches it.

In the example above, SPF passed for `esp-vendor.net` and DKIM signed as
`esp-vendor.net`, but the recipient sees `yourcompany.com`. Nothing authenticated
`yourcompany.com`, so DMARC fails — correctly. Otherwise anyone with a mailbox at a
provider with valid SPF could send as you.

## How this happens to you by accident

You sign up for a marketing platform, an invoicing tool, or a helpdesk. You set the
From address to `hello@yourcompany.com`. The platform sends the mail from its own
infrastructure with its own envelope domain, because that is where bounces need to go.

SPF passes — for them. Your From: header says you. Those do not align. If nothing is
DKIM-signed with your domain, DMARC fails on every message.

This is the most common cause of "we set up SPF and it still doesn't work".

## Relaxed and strict

Alignment has two modes, set by `aspf=` (for SPF) and `adkim=` (for DKIM) in your DMARC
record:

- **Relaxed** (`r`, the default) — the *organisational* domains must match.
  `mail.example.com` aligns with `example.com`.
- **Strict** (`s`) — exact match only. `mail.example.com` does **not** align with
  `example.com`.

Relaxed is right for almost everyone. Strict is worth it only when you are confident
every sender uses the exact apex domain, and it will break the moment someone starts
sending from a subdomain.

One thing relaxed alignment does *not* do: two unrelated domains sharing a public
suffix are never aligned. `attacker.co.uk` and `victim.co.uk` have no relationship,
even though they share their last two labels. Tools that compare "the last two labels"
get this wrong.

## Reading it from your own headers

Send a message to a mailbox at a different provider, open the delivered copy, and view
the source — **⋮ → Show original** in Gmail, **View message details** in Outlook. Then
compare three things:

```
From: Your Company <hello@yourcompany.com>     ← the domain that must be matched
       spf=pass smtp.mailfrom=bounce@esp.net   ← authenticated esp.net
       dkim=pass header.d=esp.net              ← signed by esp.net
```

If neither the `smtp.mailfrom` domain nor the DKIM `d=` matches your From domain, DMARC
will fail no matter how correct your SPF record is.

Our [header analyzer](/headers) does this comparison for you and shows the result as a
table — including the relaxed-versus-strict distinction. It runs in your browser, so
the headers are not uploaded anywhere.

> Use a message you **received**. A copy from your Sent folder has no
> `Authentication-Results` header, because that verdict is added by the receiving
> server. This trips up nearly everyone the first time.

## Fixing it

### Get DKIM signing with your domain — do this one

Every serious sending platform supports signing as your domain. It is usually called
"authenticate your domain", "domain authentication" or "custom DKIM" in their setup,
and it produces a selector for you to publish in DNS.

Once the platform signs with `d=yourcompany.com`, DKIM aligns and DMARC passes —
regardless of what the envelope sender says.

DKIM is the better fix for a second reason: **it survives forwarding.** SPF breaks the
instant a message is forwarded, because the forwarding server is not in your SPF record.
Every mailing list and every user-configured forward becomes a DMARC failure if SPF is
all you have.

### Or set a custom return-path

Some platforms let you point the envelope sender at a subdomain of yours — often called
a custom return-path or custom bounce domain. You publish a CNAME, and the envelope
domain becomes `bounce.yourcompany.com`, which aligns under relaxed alignment.

This works, but it fixes only the SPF half and still dies on forwarding. Do it *as well
as* DKIM if the platform offers it, not instead.

### What does not fix it

**Adding the vendor's include to your SPF record.** It is the intuitive move and it
changes nothing. `include:esp-vendor.net` authorises their servers to send for *your*
envelope domain, but their mail still uses *their* envelope domain, so alignment is
untouched. You will have spent one of your ten DNS lookups for no benefit.

## Checking before you enforce

This is exactly why the rollout order matters. Publish `p=none` with a reporting
address first, and read the aggregate reports — they tell you which sources are passing
SPF and DKIM *with alignment*, which is a different and much smaller set than the
sources that merely pass SPF.

Move to `p=quarantine` only once that list matches the systems you expect. Otherwise
you will discover the misaligned ones by having their mail rejected.
