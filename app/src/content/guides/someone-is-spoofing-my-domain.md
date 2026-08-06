---
title: "Someone is sending email as my domain"
description: "Four different problems get called spoofing, and DMARC only fixes one of them. How to tell which one is happening to you before you change any DNS."
question: "How do I stop someone sending email from my domain?"
published: 2026-08-03
updated: 2026-08-06
order: 5
faq:
  - q: "How do I stop someone sending email from my domain?"
    a: "Publish SPF, DKIM and DMARC, then raise the DMARC policy to p=reject. That stops forgeries that use your exact domain in the From header. It does not stop lookalike domains or display-name impersonation, which are different attacks."
  - q: "I am getting bounce messages for email I never sent. Has my account been hacked?"
    a: "Usually not. Those are backscatter — a spammer forged your address as the sender, and the bounces came back to you. It is evidence your domain is being forged, not that anything of yours was accessed."
  - q: "Does DMARC stop someone impersonating me from a Gmail address?"
    a: "No. If the attacker sends from their own address and only sets the display name to your name, the message is authenticated correctly for their domain. DMARC has nothing to act on, because your domain is not in the From header."
  - q: "Why does my own forwarded email fail DMARC?"
    a: "Forwarding breaks SPF, because the message reaches the recipient from the forwarder's server rather than yours. DKIM normally survives a plain forward, so DMARC still passes on DKIM alone. But a mailing list that rewrites the subject or appends a footer breaks the DKIM body hash too, and then DMARC fails on a message that is genuinely yours. In an aggregate report that is indistinguishable from a forgery."
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

## A fifth thing, and it isn't an attack

The four rows above all answer "what is the attacker doing". There is a fifth case that
looks exactly like the first one in a DMARC report and is not an attack at all: your own
mail, forwarded.

It matters because this is the case where enforcing hurts you rather than the forger.

Whether it breaks depends on one thing — whether anything modified the message on the
way.

| What happened | SPF | DKIM | DMARC result |
|---|---|---|---|
| Plain forward, message untouched | Breaks — the return path is the forwarder now | Survives | Passes on DKIM alone |
| A list rewrites the `Subject` or appends a footer | Breaks | Breaks — the `bh=` body hash no longer matches | Fails |

The first case is survivable and you would never notice it without reading reports. The
second is the problem: a genuinely-yours message with both mechanisms failing,
quarantined at the final hop, arriving in your `rua` as a failing source.

In the aggregate report those two are indistinguishable from a forgery. Same shape —
your domain in the `From:`, both mechanisms failing, an IP you do not recognise. Nothing
in the report tells you which is which. The only thing that separates them is whether you
recognise the source, and that is the real reason to read reports for four to six weeks
rather than one: a monthly newsletter that goes out through a mailing list will not
appear in a fortnight of data, and it is exactly the traffic you will break.

### ARC, and what it does not promise

ARC exists for precisely this. A forwarder that implements it records the authentication
results it saw before it touched the message, so a receiver further down the chain can
honour the original verdict despite the break.

The caveat is that it only helps when the final receiver evaluates the chain. Google and
Microsoft do. Many receivers do not, and even those that do are under no obligation to
trust a given chain. ARC improves your odds; it does not remove the need to recognise
your own forwarders before you enforce.

### The list-side fix

If the traffic is a mailing list you control, the pragmatic mitigation is From-rewriting
— Mailman and equivalents replace the `From:` with the list's own address, so DMARC
evaluates the list's domain instead of yours and the break stops mattering.

It is why list mail so often shows up as "via" in Gmail. Inelegant, and it works.

### What to do about it

Before moving off `p=none`, go through the failing sources in your reports and sort them
into three piles rather than two:

1. **Recognised sender, failing** — fix the authentication (usually DKIM signing with
   your domain).
2. **Recognised forwarder** — expected. Do not try to fix it in DNS; you cannot. Note it
   and move on.
3. **Unrecognised** — this is the forgery, and it is what enforcement is for.

Pile two is the one people skip, and skipping it is how a `p=reject` rollout quietly
starts deleting a department's mailing list.

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

Long enough for monthly and quarterly senders to appear, and to tell a forgery apart from
[your own forwarded mail](#a-fifth-thing-and-it-isnt-an-attack). Then `p=quarantine`,
then `p=reject`. The full sequence, including what to do with what the reports show you,
is in [what DMARC p=none actually does](/guides/dmarc-p-none/).

At `p=reject`, a forged message using your domain is refused by every major mailbox
provider. That is the outcome you are after, and there is no shortcut to it that does
not risk blocking your own mail.

## Set `sp=` while you are there

Attackers move to subdomains when the parent domain becomes unusable, because
`billing.example.com` is just as convincing to a recipient and is often left unprotected.

Subdomains inherit `p=` unless you override it, so a bare `p=reject` already covers them.
The mistake is publishing `sp=none` alongside it — usually copied from an example
somewhere — which reopens exactly the door you just closed.

[RFC 9989](https://www.rfc-editor.org/rfc/rfc9989) adds `np=` for subdomains that do not
exist at all. This is the sharper tool for this attack, because the subdomains attackers
invent are almost never real ones. `np=reject` refuses mail from anything unregistered
while leaving your genuine subdomains under `sp=`.

```
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:dmarc@example.com"
```

Receivers that have not adopted RFC 9989 yet ignore `np=` and fall back to `sp=`, so
there is no downside to publishing it now.

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
