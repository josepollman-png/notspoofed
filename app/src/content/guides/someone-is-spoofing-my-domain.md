---
title: "Someone is sending email as my domain"
description: "Four different problems get called spoofing, and DMARC only fixes one of them. How to tell which one is happening to you before you change any DNS."
question: "How do I stop someone sending email from my domain?"
published: 2026-08-03
updated: 2026-08-03
order: 5
faq:
  - q: "How do I stop someone sending email from my domain?"
    a: "Publish SPF, DKIM and DMARC, then raise the DMARC policy to p=reject. That stops forgeries that use your exact domain in the From header. It does not stop lookalike domains or display-name impersonation, which are different attacks."
  - q: "I am getting bounce messages for email I never sent. Has my account been hacked?"
    a: "Usually not. Those are backscatter — a spammer forged your address as the sender, and the bounces came back to you. It is evidence your domain is being forged, not that anything of yours was accessed."
  - q: "Does DMARC stop someone impersonating me from a Gmail address?"
    a: "No. If the attacker sends from their own address and only sets the display name to your name, the message is authenticated correctly for their domain. DMARC has nothing to act on, because your domain is not in the From header."
---

Before changing any DNS, work out which problem you actually have. Four quite different
attacks get reported as "someone is spoofing my domain", and **DMARC only fixes one of
them.** Publishing `p=reject` against the wrong one costs you weeks and fixes nothing.

## Which one is happening to you

Look at the `From:` address on a copy of the offending message — the actual address, not
the name your mail client displays.

| What you see | What it is | What fixes it |
|---|---|---|
| `billing@example.com` — your exact domain | **Domain spoofing.** Anyone can write any address into a `From:` header. | SPF + DKIM + DMARC at `p=reject` |
| `Your Name <randomuser@gmail.com>` | **Display-name impersonation.** The address is theirs; only the label is yours. | Nothing in your DNS. Receiver-side rules and staff awareness. |
| `billing@examp1e.com`, `example-inc.com` | **Lookalike (cousin) domain.** A different domain that reads like yours. | Monitoring and takedowns. Your DMARC record has no authority over it. |
| Genuinely from your account, in your Sent folder | **Compromised account.** | Change the password, revoke sessions, check for forwarding rules the attacker added. |

Only the first row is domain spoofing. It is also the only one where a stranger can put
*your* domain in front of *your* customers — which is why it is the one worth fixing
first, and the one DMARC was designed for.

If you are unsure which you are looking at, paste the message's raw headers into the
[header analyzer](/headers). It runs entirely in your browser and will tell you which
domain actually authenticated.

## "I'm getting bounces for mail I never sent"

This is the most common way people discover the problem, and it is alarming in a
misleading way.

A spammer sent mail to a few thousand addresses with your address forged as the sender.
Some of those addresses did not exist, so the receiving servers bounced the messages —
back to the forged sender. You.

**It does not mean anything of yours was accessed.** No password was needed to write
your address into a header. It is evidence your domain is being forged, and a reason to
get DMARC to enforcement, but it is not a breach.

The exception worth ruling out: if the bounces are for messages that appear in your own
Sent folder, that is a compromised account, not spoofing. Different problem, much more
urgent.

## Fixing real domain spoofing

The mechanism is worth understanding, because it explains why this takes weeks rather
than minutes.

Nothing in the original design of email verifies the `From:` header. SMTP will accept
whatever a sender writes there. SPF, DKIM and DMARC are a layer bolted on afterwards
that lets *you* publish a statement about who is allowed to send as you, and lets
receivers act on it.

**1. Publish SPF and DKIM for every legitimate sender.**

Not just your mailbox provider — the CRM, the invoicing system, the ticketing tool, the
booking form. Each one needs to pass SPF **or** DKIM, and to pass it *aligned* with your
domain. A vendor sending with their own envelope domain can pass SPF perfectly and still
fail DMARC; that trap has [its own guide](/guides/dmarc-fails-when-spf-passes/).

**2. Publish DMARC at `p=none` with a reporting address.**

```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

This blocks nothing. It tells you who is sending as you — including the forger, and
including the three internal systems you had forgotten about.

**3. Read the reports for four to six weeks, then enforce.**

Long enough for monthly and quarterly senders to appear. Then `p=quarantine`, then
`p=reject`. The full sequence, including what to do with what the reports show you, is
in [what DMARC p=none actually does](/guides/dmarc-p-none/).

At `p=reject`, a forged message using your domain is refused by every major mailbox
provider. That is the outcome you are after, and there is no shortcut to it that does
not risk blocking your own mail.

## Set `sp=` while you are there

Attackers move to subdomains when the parent domain becomes unusable, because
`billing.example.com` is just as convincing to a recipient and is often left unprotected.

Subdomains inherit `p=` unless you override it, so a bare `p=reject` already covers them.
The mistake is publishing `sp=none` alongside it — usually copied from an example
somewhere — which reopens exactly the door you just closed.

## What DMARC will not do for you

Worth being clear about, because a great deal of security marketing implies otherwise:

- **It does not stop lookalike domains.** `examp1e.com` is somebody else's domain. Your
  DNS says nothing about it, and `p=reject` on your domain has no effect on theirs.
- **It does not stop display-name impersonation.** The message is properly authenticated
  for the sender's own domain. There is no authentication failure for DMARC to act on.
  This is now the more common attack against small organisations, precisely because
  DMARC adoption has made the easy version harder.
- **It does not stop your name being used in the message body.**
- **It does not apply retroactively.** Mail already delivered stays delivered.

What it does do is remove your domain from the attacker's toolkit, which is worth the
few weeks it takes. The rest is a filtering and training problem, not a DNS one.

## Check what you currently publish

Run your domain through the [checker](/) — it reports whether SPF, DKIM and DMARC exist,
whether the DMARC policy is actually enforcing, and whether a subdomain policy is
weakening it. If something is missing, the result hands you the record to publish.
