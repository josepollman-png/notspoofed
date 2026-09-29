---
title: "DKIM passed but SPF failed"
titleTag: "DKIM pass, SPF fail: why it happens and when to ignore it"
description: "SPF breaks on forwarded mail by design, and DMARC still passes on DKIM. How to tell a harmless SPF fail from a permerror that needs a DNS fix."
answer: "If DKIM passed and aligns with your From domain, DMARC passes and the message is fine: DMARC needs only one aligned pass. SPF usually fails because the mail was forwarded and the forwarder's IP is not in your record. Fix SPF only if the failing IP is a sender you control, or the result is permerror."
question: "Why did SPF fail when DKIM passed?"
category: "SPF"
published: 2026-09-08
updated: 2026-09-22
order: 34
faq:
  - q: "Can DMARC pass if SPF fails?"
    a: "Yes. DMARC needs one aligned pass, not two. A message with a valid DKIM signature from a domain that aligns with your From header passes DMARC even when SPF failed outright. This is the normal outcome for forwarded mail."
  - q: "Why does SPF fail on forwarded email?"
    a: "Because the forwarding server is not in your SPF record. It keeps your envelope sender but connects from its own IP, so the receiver checks your record against an address you never authorised. Nothing is misconfigured — SPF simply does not survive forwarding."
  - q: "What is the difference between spf=fail and spf=permerror?"
    a: "spf=fail means your record was read and this sender is not authorised by it. spf=permerror means the record could not be evaluated at all — over ten DNS lookups, two SPF records on one name, a syntax error, or an include that no longer resolves. A permerror disables your SPF entirely."
  - q: "Should I add the forwarder to my SPF record?"
    a: "No. You cannot enumerate every mailbox your recipients forward to, and each entry costs one of your ten DNS lookups. DKIM is what carries a forwarded message through DMARC, and yours is already working if DKIM passed."
---

This is the mirror image of the usual complaint, and it worries people more than it
should:

> **Find your selector.** The [DKIM selector finder](/tools/dkim-selector-finder) tests the selectors every major provider publishes for a domain, follows CNAME delegation to whoever holds the key, and reports key size, testing mode and revoked keys.

```
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=s1 header.b=Ht9kQ2mR;
       spf=fail (google.com: domain of ceo@example.com does not designate
         203.0.113.44 as permitted sender) smtp.mailfrom=ceo@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
```

SPF failed. DMARC passed anyway. The message was delivered. Before you go editing DNS,
work out whether anything is actually wrong — for a large share of the people who search
this, nothing is.

## What each result actually proves

**DKIM proved the message.** A verifier fetched your public key from DNS, recomputed the
hash of the body and of the signed headers, and got a match. That is a cryptographic
statement about content: this message left `example.com` intact and has not been altered
in any way the signature covers.

**SPF proved nothing here, and that is a narrower failure than it sounds.** SPF asks a
single question — was the connecting IP listed in the SPF record of the envelope sender
domain? A `fail` means *this particular IP, at this particular hop*, was not authorised.
It is a statement about a path, not about a message. A message that changed hands twice
gets checked against the second hop, and your record has no idea that hop exists.

The consequence people miss: **SPF results are not portable.** Your DKIM signature is
still valid three forwards later. Your SPF result was decided at the first receiver and
is worthless to anyone downstream.

## Why DMARC passed

Because it only needs one. [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989) — the 2026
revision that replaced RFC 7489 — says that if one or more of the authenticated
identifiers aligns with the Author Domain, the message passes the DMARC check.

The Author Domain is the domain in the `From:` header. That is the identity a human
reads, and it is the only one DMARC cares about matching. Alignment comes in two modes:

- **Relaxed** (`adkim=r` / `aspf=r`, the default) — the organisational domains must
  match, so a signature from `mail.example.com` aligns with a From of `example.com`.
- **Strict** (`adkim=s` / `aspf=s`) — the domains must be identical, label for label.

So `dkim=pass header.d=example.com` with `header.from=example.com` is an aligned pass,
and DMARC is satisfied. The SPF result is not consulted further. This is exactly the
design intent: DKIM is the mechanism that survives relaying, and SPF is the one that
does not.

One detail that catches people out on bounces and out-of-office replies: RFC 9989 relies
**solely** on the `MAIL FROM` identity for SPF. A null reverse-path — which
[RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) turns into `postmaster@` the HELO name
— can produce a perfectly good SPF pass that DMARC cannot use, because it aligns with
nothing. On those messages DKIM is not the better option, it is the only one.

## Reading which identifier failed, and how

Every SPF result is a different diagnosis. The values come from
[RFC 8601](https://www.rfc-editor.org/rfc/rfc8601), and treating them as
interchangeable is what sends people down the wrong path:

| Result | What it means | Your record is |
|---|---|---|
| `spf=fail` | Record read, IP not authorised, record ends `-all` | Working |
| `spf=softfail` | Same, but the record ends `~all` | Working |
| `spf=neutral` | The record ends `?all`, or has no `all` at all | Saying nothing |
| `spf=none` | No SPF record exists for the envelope domain | Missing |
| `spf=permerror` | The record could not be evaluated | **Broken** |
| `spf=temperror` | DNS did not answer in time | Fine; transient |

`fail` and `softfail` mean SPF worked and gave a verdict. Only `permerror` and `none`
mean you have something to fix in DNS. See
[~all versus -all](/guide/spf-softfail-vs-hardfail) for why the first two matter less
than the arguments about them suggest.

Read the `smtp.mailfrom` value next, because it is frequently not the domain you assumed:

```
spf=fail smtp.mailfrom=bounces@sendingplatform.net
```

That is a different domain's record failing, not yours. And read the `Received:` chain
from the bottom up — if there is a hop between your server and the final receiver, you
are looking at forwarded mail and the SPF failure is structural. Some receivers also
stamp a `Received-SPF:` header at the hop where they made the decision, which tells you
exactly which IP and which identity were checked.

Use a message you **received** at a mailbox on another provider. A copy from your Sent
folder carries no `Authentication-Results`, because the receiving server writes it. Paste
the block into the [header analyzer](/headers) to have the comparison done for you — it
runs in your browser and uploads nothing.

## The causes, in the order they are worth checking

### Forwarding, which is not a fault

A `.forward` rule, a university alumni address, a role account that redirects, a mailing
list. The forwarder keeps your envelope sender and connects from its own IP. Your record
does not list it, so SPF fails. RFC 7208 describes this directly in its discussion of
mediators, and offers no fix that lives in your record — because there isn't one.

Some forwarders implement **SRS**, rewriting the envelope sender into their own domain so
SPF passes for them. That fixes the forwarder's deliverability, not your DMARC: the
rewritten domain is theirs, so it does not align with your From header, and DMARC is
still riding entirely on DKIM. SRS is a convention rather than a standard, and plenty of
forwarders do not implement it.

If DKIM passed, this case needs nothing from you. Note it and move on.

### A sender genuinely missing from the record

The failure you do want to act on. Look at the IP in the parenthetical and work out what
it is:

- A vendor added since the record was last touched — a new helpdesk, invoicing tool or
  monitoring system.
- An application server sending directly instead of relaying through your gateway.
- A provider that changed outbound IPs and expects you to use their `include:` rather
  than the `ip4:` you hardcoded.
- **IPv6.** A host with an AAAA record will send over IPv6 given the chance, and an
  `ip4:` list does not cover it. Records that work for years fail the day a receiver
  turns on IPv6.
- An `mx` mechanism used as a shortcut, where outbound mail does not leave from the same
  hosts that receive it.

### An include that stopped resolving

This one produces `permerror`, and the mechanism is worth knowing. RFC 7208 defines
`include:` as a recursive evaluation, and its result table is explicit: if the referenced
domain has **no** SPF record, the `include` returns `permerror` — and that permerror
propagates up and takes down your entire record. One decommissioned vendor whose SPF
record was deleted can therefore break authentication for every message you send, with
no other symptom.

Check every `include:` in your record still returns something.

### Over the ten-lookup limit

Also `permerror`, also total. Every `include`, `a`, `mx`, `ptr`, `exists` and `redirect`
counts, and the count is cumulative across the whole nested tree — RFC 7208 requires it
to be tracked as one global limit, not per evaluation. Go over and receivers treat the
record as unusable. Related and easier to miss: **void lookups**, terms whose DNS query
returns nothing, are limited to two by the same section.

[SPF: too many DNS lookups](/guide/spf-too-many-dns-lookups) has the counting method
and the three ways back under.

### Two SPF records, or one bad character

If more than one TXT record at your domain begins `v=spf1`, RFC 7208 requires a
`permerror` — the receiver is not allowed to pick one. This happens routinely during
provider migrations, when a second record is added rather than the existing one edited.
Syntax faults do the same: a stray semicolon, `include=` instead of `include:`, or a
record split across two quoted strings that reassembles with a space in the middle.

### The envelope sender is not the domain you think

SPF is looked up at exactly the envelope domain, with no inheritance — a subdomain does
not fall back to its parent's record. If your platform sends with an envelope of
`bounce.example.com` and only `example.com` has a record, the result is `none`, not a
pass borrowed from the apex.

## What to do next

Take the `smtp.mailfrom` value and the IP out of the failing header and answer one
question: **is this a hop you control?**

If it is not — a forwarder, a list, a redirect one of your recipients set up — do
nothing to your SPF record. DKIM is already carrying the message through DMARC, which is
the outcome the design intends.

If it is, and the result was `fail` or `softfail`, add that sender to your record using
the provider's `include:` rather than a hardcoded IP, then re-check your lookup count
before you publish.

If the result was `permerror`, stop treating this as an SPF failure — your record is
switched off entirely and every message you send is relying on DKIM alone. Query each
`include:` for a live record, delete the ones that return nothing, and confirm there is
exactly one `v=spf1` TXT record on the name.

Run the domain through the [checker](/) to see the record as receivers evaluate it,
lookup count included, before you edit anything. If your header shows a different mix of
results, [what every SPF, DKIM and DMARC pass/fail combination means](/guide/spf-dkim-dmarc-results)
covers each one.
