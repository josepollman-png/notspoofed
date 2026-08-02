---
title: "SPF: should it end in ~all or -all?"
description: "The difference matters far less than the arguments about it suggest, and the settings people choose instead of either are the ones that actually break things."
question: "Should my SPF record end in ~all or -all?"
published: 2026-08-03
updated: 2026-08-03
order: 15
faq:
  - q: "What is the difference between ~all and -all in SPF?"
    a: "~all is softfail — the receiver should accept the message but treat it as suspicious. -all is fail — the receiver is invited to reject it. If you publish DMARC, both produce the same DMARC outcome, because DMARC only asks whether SPF passed and aligned."
  - q: "Is -all safe to publish?"
    a: "Yes, once every legitimate sender is either in your SPF record or signing with DKIM. The risk is not the qualifier itself but publishing it before you have enumerated your senders."
  - q: "What happens if my SPF record has no all mechanism?"
    a: "The evaluation ends in neutral, which receivers treat as though you published no policy at all. An SPF record with no all is close to useless, and unlike a syntax error nothing reports it as broken."
---

The short answer: **publish `-all` once you know all your senders, `~all` while you are
still finding them, and never leave the record without an `all` at all.**

The longer answer is that this question absorbs far more argument than it deserves, and
the settings nobody argues about are the ones that actually cause damage.

## The four qualifiers

The `all` mechanism matches every sender that no earlier term matched. Its qualifier is
what you are telling receivers to do with them.

| Ending | Result | What a receiver does |
|---|---|---|
| `-all` | Fail | Invited to reject the message |
| `~all` | Softfail | Accept, but treat as suspicious |
| `?all` | Neutral | Nothing. You have stated no opinion. |
| `+all` | Pass | **Everyone on the internet passes SPF for your domain** |
| *(omitted)* | Neutral | Same as `?all` |

## Why the choice matters less than you think

If you publish DMARC — and you should — the distinction between `~all` and `-all` mostly
evaporates.

DMARC does not ask *how* SPF failed. It asks a single question: did SPF produce a **pass**
for a domain that aligns with the `From:` header? A softfail and a hardfail are both
"not a pass", so they lead to identical DMARC outcomes. A forged message hits your
`p=reject` policy and is refused either way.

```
v=spf1 include:_spf.google.com ~all      →  DMARC fail  →  rejected at p=reject
v=spf1 include:_spf.google.com -all      →  DMARC fail  →  rejected at p=reject
```

Where the qualifier still does real work is with receivers that evaluate SPF *without*
DMARC — smaller mail servers, appliances, and spam filters that weigh SPF independently.
There, `-all` is a stronger signal than `~all`. That is a genuine but modest difference,
and it is the entire practical stake in the argument.

## The endings that actually cause problems

**`+all` is a catastrophe.** It says every host on the internet is authorised to send as
your domain. It is worse than having no SPF record, because you have actively vouched for
your attacker. It usually appears through a copy-paste error or a misremembered
"allow everything while I debug this". If your domain publishes `+all`, fix that today and
consider the rest of this page academic.

**No `all` is nearly as bad, and much easier to miss.** A record like:

```
v=spf1 include:_spf.google.com include:sendgrid.net
```

is syntactically valid and will not be flagged by anything that only checks syntax. But
when a sender matches none of those includes, the evaluation runs out of terms and ends
in **neutral** — which receivers treat as no policy. You have done the work of listing
your senders and published a record that declines to say anything about anyone else.

**`?all` is the same thing, stated deliberately.** There is no good reason to publish it.

## When `~all` is the right choice

While you genuinely do not yet know every system that sends as you.

Most organisations send from more places than they think, and the ones that surface last
are the ones that fire monthly or quarterly — invoicing runs, renewal notices, an annual
report from a system nobody owns. `~all` with DMARC at `p=none` is the correct posture
during that discovery period: nothing is blocked, and the aggregate reports tell you who
is out there.

## When to move to `-all`

Once your DMARC reports have shown you a full billing cycle with no unexplained senders.
By that point you are not guessing, and `-all` is simply the accurate statement of a
thing you now know.

Move the SPF qualifier at the same time as, or before, you raise the DMARC policy. There
is no sense in `p=reject` sitting behind a record that ends in `?all`.

## The forwarding caveat, and why DKIM is the real answer

The standard argument for `~all` is forwarding, and it is a real effect.

When a message is forwarded — a mailing list, a `.forward` rule, a university alumni
address — the envelope sender is usually preserved but the message now arrives from the
forwarder's server. That IP is not in your SPF record, so SPF fails. This is not a
misconfiguration; it is inherent to how SPF works.

The conclusion people draw is "so use `~all`, to be safe". The better conclusion is
**get DKIM signing working**, because:

- DKIM signs the message itself, so it survives forwarding intact.
- DMARC passes if **either** SPF or DKIM passes with alignment. A DKIM-signed message
  that gets forwarded still passes DMARC after SPF has broken.

With DKIM in place, forwarding stops being an argument about SPF qualifiers. Without it,
`~all` is a partial mitigation for a problem that has a proper fix.

## What to publish

While discovering senders, with DMARC at `p=none`:

```
example.com.  TXT  "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
```

Once the reports are clean and DKIM is signing:

```
example.com.  TXT  "v=spf1 include:_spf.google.com include:sendgrid.net -all"
```

One caution while editing: every `include:` you add costs DNS lookups against a limit of
ten, and going over silently disables the whole record. If you are close to the limit,
see [SPF: too many DNS lookups](/guides/spf-too-many-dns-lookups/).

Run the domain through the [checker](/) to see which ending you currently publish, how
many lookups you are using, and whether anything is failing.
