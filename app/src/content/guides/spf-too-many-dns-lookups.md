---
title: "SPF: too many DNS lookups"
description: "SPF allows ten DNS lookups. Go over and receivers ignore your record entirely. How to count them, and the three ways to get back under."
question: "Why does my SPF record say too many DNS lookups?"
published: 2026-07-31
updated: 2026-07-31
order: 10
faq:
  - q: "How many DNS lookups does SPF allow?"
    a: "Ten. RFC 7208 limits the number of terms that trigger a DNS query — include, a, mx, ptr, exists and redirect — to ten across the whole evaluation, including everything inside nested includes."
  - q: "What happens if I exceed the SPF lookup limit?"
    a: "Receivers return a PermError and treat your SPF record as unusable. In practice your SPF stops working entirely, which means mail that should pass can start failing DMARC."
  - q: "Do ip4 and ip6 entries count toward the SPF lookup limit?"
    a: "No. ip4, ip6 and all require no DNS query, so you can list as many as you like. This is why flattening an include into raw IP ranges reduces your lookup count."
---

If a checker tells you your SPF record needs eleven or twelve DNS lookups, the
important thing to understand is that this is not a warning about efficiency. Your
SPF record has **stopped working**.

## What the limit actually is

[RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4) says an
evaluator must limit the number of terms that cause a DNS query to ten. Go past it
and the result is `PermError` — a permanent failure. Receivers do not fall back to
"probably fine". They treat the record as unusable.

Six terms cost a lookup:

| Costs a lookup | Free |
|---|---|
| `include:` | `ip4:` |
| `a` | `ip6:` |
| `mx` | `all` |
| `ptr` | `exp=` |
| `exists:` | |
| `redirect=` | |

The count is cumulative across the whole tree. If you have four includes and one of
those vendors has six includes of their own, you are at eleven — even though your own
record lists four things.

That is the trap. Your record looks short. Someone else's record broke yours.

## Two things people miss when counting

**`redirect=` uses an equals sign, not a colon.** It is a modifier, not a mechanism,
and it is easy for both humans and software to skip past. Plenty of real domains are
nothing *but* a redirect:

```
hubspot.com.  TXT  "v=spf1 redirect=_hspf.hubspot.com"
```

Miss that one term and you conclude the domain uses zero lookups, when in fact
everything — every include, every cost — lives behind it. If a tool tells you a
domain like this is using no lookups, the tool is wrong.

**Void lookups have their own limit.** A lookup returning no records is a "void
lookup", and RFC 7208 caps those at two. An include pointing at a vendor you stopped
using a year ago, whose record no longer exists, counts against you twice over: once
toward the ten, and once toward the void limit.

## Fixing it, in the order you should try

### 1. Remove senders you no longer use

This is the only fix with no downside, and it is usually available. Most domains over
the limit are carrying two or three includes for tools nobody has logged into in
years. Every one you delete buys back its entire subtree.

Before touching anything else, get the list of includes in front of whoever owns
marketing and billing and ask which are still live.

### 2. Ask whether the vendor has a narrower include

Some providers publish a general-purpose include covering all their infrastructure
plus a narrower one for specific products or regions. It is worth asking support
directly — this information is rarely in the docs.

### 3. Flatten — carefully

Flattening means replacing `include:vendor.com` with the IP ranges it currently
resolves to. Those `ip4:` and `ip6:` entries cost nothing, so a subtree of five
lookups collapses to zero.

The catch is permanent: **you have taken on the vendor's maintenance burden.** When
they add a sending IP, their include updates automatically and yours does not. Your
mail from that provider starts failing SPF, silently, with no bounce and no warning
until someone notices deliverability has dropped.

Some rules if you go this route:

- **Flatten as little as possible.** You do not need to inline everything — only
  enough to get under ten. Retiring the single most expensive include is often all it
  takes, and leaves every other vendor still able to rotate their own IPs.
- **Never flatten a provider that publishes macros.** A term like
  `exists:%{i}._spf.example.com` expands using the connecting server's IP address.
  There is no fixed set of addresses to inline, and flattening it silently drops every
  sender it would have matched.
- **Re-check monthly.** Put it in a calendar, not in your memory.

> Large providers increasingly flatten their own records for exactly this reason.
> `_spf.google.com` today contains only `ip4:` and `ip6:` entries — no nested includes
> at all — so an `include:_spf.google.com` costs you exactly one lookup rather than
> four.

## A detail that breaks naive tooling

DNS transmits TXT records as one or more character-strings of at most 255 bytes each.
A long SPF record arrives in several pieces, and
[RFC 7208 §3.3](https://www.rfc-editor.org/rfc/rfc7208#section-3.3) says they are
joined with **nothing between them**.

Real records split mid-token. One production record ends a chunk with `…ip4` and
begins the next with `:161.38.192.0/20`. Joined correctly you get
`ip4:161.38.192.0/20`. Joined with a space — which is the obvious-looking mistake —
you get `ip4 :161.38.192.0/20`, which is not valid syntax.

If you are writing your own tooling, this is the first thing to get right. If you are
using someone else's and the parsed output looks subtly mangled, this is why.

## What "under the limit" should mean

Ten is legal, but ten is not a target. A record sitting at exactly ten breaks the day
your marketing team signs up for one more tool, and nobody will connect those two
events. Aim for seven or eight so there is room to add a sender without an outage.
