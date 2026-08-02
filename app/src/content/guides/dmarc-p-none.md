---
title: "What DMARC p=none actually does"
description: "p=none collects reports and blocks nothing. It is the right place to start and the wrong place to stop. How to get to enforcement without losing mail."
question: "Does DMARC p=none protect my domain?"
published: 2026-07-31
updated: 2026-07-31
order: 20
faq:
  - q: "Does p=none stop email spoofing?"
    a: "No. p=none asks receiving servers to take no action on mail that fails authentication, so forged messages are still delivered. It only switches on reporting."
  - q: "How long should I stay at p=none?"
    a: "Long enough to see a full billing cycle of aggregate reports — usually four to six weeks — so that monthly and quarterly senders like invoicing systems appear before you start enforcing."
  - q: "Is p=quarantine or p=reject better?"
    a: "p=reject is stronger and is the end goal. p=quarantine is a safer intermediate step because failing mail goes to spam rather than disappearing, so a mistake is recoverable."
---

`p=none` is the most misunderstood setting in email authentication, because it looks
like protection and is not.

## What each policy does

The `p=` tag tells receiving mail servers what to do with a message that claims to be
from your domain and fails authentication.

| Policy | What the receiver does |
|---|---|
| `p=none` | Nothing. Deliver as normal. Send you a report. |
| `p=quarantine` | Treat as suspicious — usually the spam folder. |
| `p=reject` | Refuse the message outright. |

At `p=none`, someone forging your domain has their mail delivered to the inbox exactly
as before you published DMARC. You will *learn* it happened, from the reports. You
will not have stopped it.

This is not a flaw. Monitoring first is the correct sequence — you cannot safely
enforce a policy until you know what your own legitimate mail looks like. The failure
mode is stopping here. Plenty of domains published `p=none` during the 2024 sender
requirement scramble and have not touched it since, and they are no more protected
than a domain with no DMARC record at all.

## Why you cannot just skip to p=reject

Because you will lose mail, and you will not know which mail.

Almost every organisation sends from more places than it thinks: the CRM, the
invoicing system, the ticketing tool, the recruitment platform, a booking form on a
website nobody has looked at since 2019. Each of those has to pass SPF **or** DKIM
*with alignment* before DMARC considers it legitimate.

Alignment is where this usually bites. It is not enough for a message to pass SPF —
the domain that passed SPF must match the domain in the visible `From:` header. A
vendor sending on your behalf with their own envelope domain can pass SPF perfectly
and still fail DMARC. If that sounds like your situation, it has its own guide:
[why DMARC fails when SPF and DKIM pass](/guides/dmarc-fails-when-spf-passes/).

Go straight to `p=reject` and those systems stop being delivered immediately, with no
bounce that anyone reads.

## The path to enforcement

**1. Publish `p=none` with a reporting address.**

```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

A DMARC record without `rua=` is close to useless. You are enforcing nothing and
learning nothing.

**2. Wait, and read the reports.**

Aggregate reports arrive daily as XML attachments from mailbox providers. They are
unpleasant to read raw — each one lists sending IPs, message counts, and whether SPF
and DKIM passed and aligned.

Give it four to six weeks. Some senders only fire monthly or quarterly — an invoicing
run or an annual renewal notice will not appear in a week of data, and those are
exactly the messages you cannot afford to break.

**3. Fix what is failing.**

For each legitimate source in the reports, either add it to SPF or, better, get DKIM
signing set up with your domain. DKIM survives forwarding; SPF does not. A mailing
list that rewrites nothing will break SPF alignment every time, and DKIM is what saves
those messages.

**4. Move to `p=quarantine`.**

```
_dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

Failing mail now goes to spam. If you have missed a sender, someone will find the
message in their junk folder and tell you — recoverable, and far better feedback than
silence.

**5. Move to `p=reject`.**

Once a few weeks of quarantine produce no surprises.

## Two tags worth knowing about

**`sp=`** sets the policy for subdomains. If you omit it, subdomains inherit `p=`.
Setting `sp=none` while `p=reject` is a common and bad combination — attackers forge
subdomains precisely because they are usually the weaker target, and
`billing.example.com` is just as convincing to a recipient as the real thing.

**`pct=`** applies your policy to a percentage of failing mail. It exists for gradual
rollouts, and it is genuinely useful at `pct=25` for a week or two on the way to
enforcement. It is also frequently left behind by accident. `pct=50` at `p=reject`
means half of the forgeries targeting your customers are delivered.

## The honest summary

`p=none` is a diagnostic tool, not a control. If your domain has been at `p=none` for
more than a couple of months, nothing is protecting it, and the reports you are
collecting are only worth anything if you act on them.
