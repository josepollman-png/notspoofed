---
title: "DKIM selectors by provider"
description: "The DKIM selector each major provider uses — and which are unguessable by design."
question: "What DKIM selector does my email provider use?"
published: 2026-08-06
updated: 2026-08-06
order: 55
faq:
  - q: "What DKIM selector does Google Workspace use?"
    a: "google. It is the same for every Google Workspace customer, so if you send through Google Workspace that is almost certainly your selector."
  - q: "What DKIM selector does Microsoft 365 use?"
    a: "selector1 and selector2. Microsoft publishes two because it rotates between them, and both should resolve. If only one does, that is normal mid-rotation and not a fault."
  - q: "Why can I not find my Amazon SES DKIM selector?"
    a: "Amazon SES Easy DKIM issues three random tokens published as CNAMEs, so no guess list will ever contain them. A domain signing perfectly through SES will read as no DKIM on every guessing tool. Read the s= tag from a message you sent instead."
  - q: "Can I look up every DKIM selector on a domain?"
    a: "No. There is no DNS query that returns all names under _domainkey, and zone transfers are refused by every sane nameserver. Every DKIM checker works from a list of common names and hopes."
---

Selectors cannot be listed from DNS. There is no query that returns "every selector on
this domain" — [the reason is here](/guides/dkim-selectors/). Every checker, including
ours, works from a list of common names and hopes.

This is that list, with an honest note about how reliable each entry is.

The only certain method is still to read a message you sent and take the `s=` tag from
its `DKIM-Signature` header. Use this table to make a good guess, not to conclude that
DKIM is missing.

## What the two confidence labels mean

They are not decoration, and the difference matters when you are about to conclude
something about your own domain:

- **Verified** — confirmed on 6 August 2026 by running a real domain through
  [the checker](/) and reading the selectors it actually found. Not copied from another
  list.
- **Documented** — taken from provider documentation and community lists, but *not*
  confirmed against a live domain. Treat it as a good lead rather than a fact.

Where only some of a provider's selectors were seen live, the label says which — for
example **Verified (k1)** means `k1` was observed and the others were not.

## Fixed, predictable selectors

These providers use the same selector for every customer. If you use the provider, this
is almost certainly your selector.

| Provider | Selector(s) | Confidence |
|---|---|---|
| Google Workspace | `google` | Verified |
| Microsoft 365 / Outlook | `selector1`, `selector2` | Verified |
| Mailchimp | `k1` (sometimes `k2`, `k3`) | Verified (k1) |
| Mandrill | `mandrill`, `m1`, `m2` | Verified |
| Zendesk | `zendesk1`, `zendesk2` | Verified |
| SendGrid | `s1`, `s2` | Verified (s2) |
| Zoho Mail | `zoho` | Documented |
| Proton Mail | `protonmail`, `protonmail2`, `protonmail3` | Documented |
| Mailjet | `mailjet` | Documented |

Microsoft publishes two because it rotates between them. Both should resolve; if only
one does, that is normal mid-rotation and not a fault.

## Per-account selectors

These providers generate a selector unique to your account. Guessing cannot work, but
the shape is predictable enough to recognise once you see it.

| Provider | Shape |
|---|---|
| HubSpot | Contains your per-account hub ID |
| Klaviyo | Per-account value issued at domain setup |

Find these in the provider's own console, under "authentication", "verified domains" or
"DKIM".

## Unguessable by design

These are worth calling out separately, because they are the reason "no DKIM found" is
so often wrong.

| Provider | Why |
|---|---|
| Amazon SES | Easy DKIM issues three random tokens published as CNAMEs. No guess list will ever contain them. |
| SparkPost | Date-stamped selectors, e.g. `scph0819`. Effectively unguessable without knowing the date. |

A domain signing perfectly through SES will read as "no DKIM" on every guessing tool,
forever. If a checker reports no DKIM and you know you sign through SES or SparkPost,
the checker is wrong, not your DNS.

## Generic names worth trying

If your provider isn't listed, these are the conventional fallbacks: `default`, `dkim`,
`mail`, `email`, `smtp`, `key1`, `key2`, `s`, `sig1`, `selector`.

## Verifying a selector once you have a candidate

```sh
dig +short TXT selector1._domainkey.example.com
```

A working key looks like:

```
"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA…"
```

Two results that look like success but aren't:

- **`p=` with nothing after it** — the key is revoked. If anything still signs with that
  selector, that mail is failing DKIM right now.
- **An answer on a selector you invented** — the domain has a wildcard record answering
  every name under `_domainkey`. Query a deliberately nonsensical selector first; if it
  also returns something, discard every result matching it.
  [More on that trap](/guides/dkim-selectors/#the-trap-records-that-exist-but-are-not-dkim).

## Still not sure?

Run your domain through [the checker](/) — it tries around a hundred selectors, verifies
each hit is a real parseable signing key rather than a wildcard echo, and tells you
plainly when a miss isn't proof of absence.
