---
title: "Finding your DKIM selector"
description: "DKIM selectors cannot be listed from DNS. Why every checker is guessing, how to find yours for certain, and the trap that makes some tools report keys that do not exist."
question: "How do I find my DKIM selector?"
published: 2026-07-31
updated: 2026-07-31
order: 50
faq:
  - q: "How do I find my DKIM selector?"
    a: "You cannot list selectors from DNS. Get it from your mail provider's admin console, or read the DKIM-Signature header of a message you have sent — the s= tag is the selector."
  - q: "Why does a DKIM checker say no key found when I have DKIM enabled?"
    a: "Checkers guess from a list of common selector names. If your provider uses an unusual selector, or a randomly generated one as Amazon SES does, the guess fails even though your DKIM is working correctly."
  - q: "What does an empty p= value mean in a DKIM record?"
    a: "It means the key has been revoked. Anything still signing with that selector will fail DKIM. Publishing an empty key deliberately is also a way to declare that a selector is not in use."
---

Almost every other DNS record can be looked up. You ask for the SPF record and you get
it. You ask for `_dmarc` and it is there.

DKIM does not work that way, and it changes how you have to approach it.

## Why selectors cannot be listed

A DKIM public key lives at:

```
<selector>._domainkey.<domain>
```

The selector is an arbitrary name chosen by whoever set up the signing. Google
Workspace uses `google`. Microsoft 365 uses `selector1` and `selector2`. Mailchimp
uses `k1`. Amazon SES generates three random tokens per identity.

There is no DNS query that returns "all names under `_domainkey`". `ANY` queries do
not do this, and zone transfers are refused by every sane nameserver. To read a DKIM
key you must already know the selector.

This means **every DKIM checker in existence is guessing.** Reputable ones try a list
of forty or fifty common selectors. When one reports "no DKIM found", the honest
reading is *"we tried our list and nothing matched"* — which is genuinely different
from "you have no DKIM".

Amazon SES makes this concrete: its selectors are random tokens. No guess list will
ever find them. A domain signing perfectly with SES will show as "no DKIM" on every
guessing tool, forever.

> **Looking for the selector your provider uses?**
> [DKIM selectors by provider](/guides/dkim-selector-list/) lists the known selector for
> each major platform, marked according to whether it was verified against a live domain
> or only documented — plus the providers whose selectors cannot be guessed at all.

## Two ways to find yours for certain

### Read a message you sent

The most reliable method, and it needs no access to anything.

Send yourself a message, then view the raw source. In Gmail: open it, then **⋮ → Show
original**. Look for the `DKIM-Signature` header:

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=example.com; s=selector1; t=1785453729;
```

The `s=` tag is your selector. The `d=` tag is the signing domain — check that it
matches your visible `From:` domain, because if it does not, DKIM is passing but not
*aligning*, and DMARC will still fail.

If you would rather not read them by eye, paste the whole block into the
[header analyzer](/headers) — it pulls out the selector, checks alignment for you, and
explains any mismatch. It runs in your browser, so the headers are not uploaded
anywhere.

If you send from several systems, do this once per system. They will each have their
own selector, and they all need to work.

### Check the provider's console

Every sending platform exposes this somewhere under "authentication", "verified
domains", or "DKIM". It is also where you go to enable signing if it turns out it was
never switched on.

## Verifying a selector once you have it

```sh
dig +short TXT selector1._domainkey.example.com
```

A working key looks like:

```
"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA…"
```

Things worth noticing in the response:

- **`p=` with nothing after it** means the key is **revoked**. If anything still signs
  with that selector, that mail is failing DKIM right now.
- **A missing `v=` tag is fine.** RFC 6376 only recommends it. Plenty of real records
  begin straight at `k=rsa` and work perfectly.
- **Key length.** A 1024-bit RSA key is still accepted everywhere but is no longer
  considered strong; 2048 is the current norm. Rotation is done through your provider,
  not by editing DNS.
- **A `CNAME` instead of a TXT record is normal.** Most platforms have you delegate the
  selector to them so they can rotate keys without touching your DNS. Following the
  CNAME should land on a valid key.

## The trap: records that exist but are not DKIM

Some domains publish a **wildcard DNS record**, which answers *every* name under the
domain. On such a domain, `anything-at-all._domainkey.example.com` returns a record —
because the wildcard matches, not because that selector exists.

A checker that only asks "did I get an answer?" will report a dozen imaginary DKIM
selectors on these domains, confidently and wrongly. The defence is to require the
answer to actually parse as DKIM — specifically to carry a `p=` tag, which
[RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) makes mandatory.

That is necessary but, it turns out, not sufficient. Some wildcards publish a
structurally valid DKIM record with an empty key:

```
*._domainkey.example.com.  TXT  "v=DKIM1; p="
```

That is a real DKIM record by every syntactic measure, so the `p=` test passes and
every guessed selector comes back looking like a revoked key. The only reliable
defence is to query a deliberately nonsensical selector first and discard any result
identical to whatever the wildcard returns.

If a tool tells you that you have thirty revoked DKIM selectors, this is what has
happened, and you can ignore it.

## Publishing a wildcard on purpose

The pattern above is worth stealing for domains that send no mail:

```
*._domainkey.example.com.  TXT  "v=DKIM1; p="
```

This declares that every selector on the domain is revoked. Combined with
`v=spf1 -all` and a DMARC policy of `p=reject`, it is a clear statement that the
domain sends nothing and that any signature claiming otherwise is forged.

Add an explicit record for a real selector later and it takes precedence
automatically — DNS wildcards only apply where no exact match exists, so one working
key coexists happily with a revoke-everything wildcard.
