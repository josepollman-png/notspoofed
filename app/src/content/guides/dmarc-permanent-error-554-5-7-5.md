---
title: "554 5.7.5 permanent error evaluating DMARC policy"
titleTag: "554 5.7.5 permanent error evaluating DMARC policy: the fix"
description: "Gmail bounced your mail with 554 5.7.5? It's your DMARC DNS, not the message: two records at _dmarc, a malformed record or failed alignment. The fix."
answer: "554 5.7.5 means the receiver could not get a usable DMARC result for your domain and refused the message rather than guess. It is a DNS fault, not spam. The usual cause is two v=DMARC1 records at _dmarc, then a malformed record, and last a valid policy with failing alignment. Keep exactly one valid record."
question: "What does 554 5.7.5 permanent error evaluating DMARC policy mean?"
category: "Error messages"
published: 2026-08-14
updated: 2026-09-22
order: 18
faq:
  - q: "Does 554 5.7.5 mean my email was hacked?"
    a: "No. It means the receiver could not evaluate your domain's DMARC policy and refused the message rather than guessing. It is a configuration fault in your DNS records, not evidence of compromise."
  - q: "Is 554 5.7.5 a permanent failure? Will it retry?"
    a: "It is permanent. The 5.x.x class tells the sending server not to retry, so the message is gone and the sender gets a bounce. Fixing DNS does not resend it — the message has to be sent again."
  - q: "I only have one DMARC record. Why do I still get this?"
    a: "Check for a second TXT record at _dmarc that you did not add — a previous provider or a migration often leaves one. Two DMARC records at the same name is the same as none, because the receiver cannot choose between them."
  - q: "How long after fixing the record before mail flows again?"
    a: "As soon as the old record's TTL expires at the receiver, typically minutes to a few hours. Re-run a check rather than test by sending, so you are not judging propagation from a single delivery."
---

Gmail returned something like:

```
554 5.7.5 permanent error evaluating DMARC policy
```

This is not a spam judgement and it is not about the content of your message. The
receiver tried to work out what your domain's DMARC policy says, could not reach a
usable answer, and **refused the message rather than guess**.

The `5` in `554` and in `5.7.5` means permanent: nothing retries, the message is gone,
and the sender gets a bounce. That is the good news, in a sense — this is a DNS fault
you can fix once, not an intermittent reputation problem you have to nurse.

## What the receiver was actually doing

DMARC evaluation is a lookup of the TXT record at `_dmarc.<your-domain>`, followed by a
decision. The error means that lookup produced something the receiver could not act on.
There are only three realistic ways that happens, and they are worth checking in this
order because that is roughly how often each is the real cause.

## Cause 1: two DMARC records at the same name

The most common cause, and the least obvious, because your record looks perfect when you
view it in isolation.

[RFC 7489 §6.6.3](https://www.rfc-editor.org/rfc/rfc7489#section-6.6.3) is explicit: if
more than one record starting `v=DMARC1` is found at `_dmarc`, the receiver **discards
them all and treats the domain as having no DMARC record at all.** Some receivers go
further and report the ambiguity as a permanent error, which is what you are seeing.

This almost always comes from history — a previous provider, a migration, a DMARC
vendor's onboarding wizard, or two people fixing the same problem a year apart. Nobody
deletes the old one because nobody knows it is there.

Check for it directly:

```sh
dig +short TXT _dmarc.example.com
```

More than one line coming back that starts with `v=DMARC1` is the bug. Delete every one
but the record you actually want. This is also why a check that reports "DMARC found" is
not sufficient on its own — it has to report *how many*.

## Cause 2: the record is malformed

DMARC's grammar is stricter than it looks, and the failures are unglamorous:

| Mistake | What it looks like |
|---|---|
| `v=` not first | `p=reject; v=DMARC1` — the version tag must lead |
| Missing `p=` | `v=DMARC1; rua=mailto:…` with no policy at all |
| Wrong version string | `v=DMARC` or `v=dmarc1` |
| Semicolons | missing between tags, or a stray one at the start |
| Smart quotes | a record pasted through a word processor |
| Wrapped record | the TXT value split so a tag breaks mid-token |

A valid minimal record is exactly this:

```
v=DMARC1; p=none; rua=mailto:dmarc@example.com
```

`v=DMARC1` first, `p=` second, tags separated by semicolons, and the whole thing as one
TXT value at `_dmarc`. If you are starting from a broken record, publish that and add
tags back one at a time.

> A detail that catches people out: TXT records longer than 255 bytes arrive in several
> chunks, and they are joined with **nothing** between them. A DMARC record long enough
> to split — several `rua=` addresses will do it — can be published correctly and still
> parse as nonsense if the tooling in between joins the pieces with a space.

## Cause 3: the policy is fine, and alignment is failing

Less common for this specific error string, but worth ruling out once the record is
clean: if your record is valid and readable, the rejection is DMARC doing its job. Your
mail failed both SPF and DKIM *alignment*, and your own policy told the receiver to
reject it.

The word doing the work is **alignment**. SPF can pass for the envelope domain while the
`From:` header shows a different one, and DMARC only counts a pass that matches the
domain your recipient sees. Most "we have SPF and it still fails" reports are this.
Security gateways enforce the same policy in their own words — Mimecast returns
`550 DMARC Sender Invalid - envelope rejected`, and its whole family of rejection
messages is [decoded here](/guide/bounce/mimecast-rejected).

→ [Why DMARC fails when SPF and DKIM pass](/guide/dmarc-fails-when-spf-passes)

If this is the cause, dropping to `p=none` will make the rejections stop immediately —
but understand that this fixes the symptom by turning enforcement off, and leaves your
domain spoofable while you sort out the real alignment problem.
→ [What DMARC p=none actually does](/guide/dmarc-p-none)

## Fix it in order

1. **Count your records.** `dig +short TXT _dmarc.example.com`. Exactly one line should
   start with `v=DMARC1`. Delete the others.
2. **Validate what remains.** `v=` first, `p=` present, semicolons between tags, no
   curly quotes.
3. **Re-check** — [run the checker](/) on the domain. It reports the record count and
   the parse result separately, which is what distinguishes cause 1 from cause 2.
4. **Only then** look at alignment, using a copy of a message that failed.
   The [header analyzer](/headers) shows which of SPF and DKIM aligned and which did not.

## What not to do

**Do not delete your DMARC record to make the error go away.** It works — receivers
stop evaluating a policy that is not there, and the bounces stop — and it leaves your
domain with no spoofing protection at all, which is how this becomes a much worse
problem six months later. The fix is one valid record, not zero.

Equally, do not jump straight to `p=reject` after fixing the syntax. If cause 3 is also
present you will turn a bounce for some of your mail into a bounce for all of it.

---

[Check your domain](/) — it reports how many DMARC records exist, whether the one it
found parses, and the exact record to publish if it does not.
