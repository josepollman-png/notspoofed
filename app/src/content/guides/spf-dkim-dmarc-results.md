---
title: "SPF, DKIM and DMARC results: what every pass/fail combination means"
titleTag: "SPF, DKIM, DMARC pass/fail combinations explained"
description: "SPF pass, DKIM fail, DMARC pass? Every result combination in an Authentication-Results header: what it means for delivery, and the one fix for each."
answer: "DMARC passes when SPF or DKIM passes and the domain it passed for matches the domain in your From: header. A pass on its own is not enough: SPF can pass for your email vendor's domain and DMARC still fails. One aligned pass is sufficient, which is why DMARC often passes when SPF fails."
question: "What does SPF pass, DKIM fail, DMARC pass mean?"
category: "DMARC"
published: 2026-09-23
updated: 2026-09-23
order: 31
faq:
  - q: "What does spf pass dkim fail dmarc pass mean?"
    a: "SPF passed for a domain that aligns with your From: header, so DMARC passed on SPF alone. DKIM failed, which usually means the signature broke in transit or the selector's key is missing. The message is fine today, but it has no second route through DMARC: the first time it is forwarded, SPF fails too and so does DMARC."
  - q: "Why does DMARC fail when SPF and DKIM both pass?"
    a: "Because both passed for a domain other than the one in your From: header — usually your email platform's own domain. DMARC requires a pass that aligns with the From: domain. Have the platform DKIM-sign as your domain, so that header.d matches header.from."
  - q: "What does dmarc=fail with compauth=pass mean?"
    a: "It is Microsoft-specific. DMARC failed, but Microsoft's own composite authentication decided to trust the message anyway — for example because a trusted forwarder sealed it with ARC. The message is delivered at Microsoft. Gmail, Yahoo and other receivers do not use compauth, so the DMARC failure still counts there."
  - q: "What does dmarc=bestguesspass mean?"
    a: "It is Microsoft's result when the From: domain publishes no DMARC record. The message would have passed if a record existed. Nothing is failing, but nothing is protecting the domain either: publish a DMARC record."
  - q: "Can DMARC pass if SPF fails?"
    a: "Yes. DMARC needs one aligned pass, not two. If DKIM passes and header.d matches your From: domain, DMARC passes even when SPF failed outright. This is the normal result for forwarded mail."
---

Every receiving server writes its verdict into an `Authentication-Results` header, and
that header reports three results that look independent but are not. SPF and DKIM each
report on a domain. DMARC reports on whether either of those domains was *yours*.

> **Which row are you in?** Paste your headers into the [header analyzer](/headers) and we'll tell you which row you're in. It runs in your browser; nothing is uploaded.

## The rule behind every row

[RFC 7489 §4.2](https://www.rfc-editor.org/rfc/rfc7489#section-4.2) states it in two
lines: a message satisfies DMARC if at least one mechanism produces a pass, *and*
produces it for an identifier that is in alignment with the From: domain.
[RFC 9989](https://www.rfc-editor.org/rfc/rfc9989), which replaced RFC 7489 in 2026, keeps
the rule unchanged.

Each result reports on a different domain, and the header names each one:

| Result | Domain it checked | Where to read it in the header |
|---|---|---|
| `spf=` | The envelope sender ([RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)) | `smtp.mailfrom=` |
| `dkim=` | The signing domain ([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)) | `header.d=` (Microsoft) or `header.i=@…` (Gmail) |
| `dmarc=` | The visible From: domain | `header.from=` |

DMARC passes when `header.from` matches the `smtp.mailfrom` domain of a passing SPF
check, or the `header.d` domain of a passing DKIM signature. Under the default relaxed
alignment ([RFC 7489 §3.1](https://www.rfc-editor.org/rfc/rfc7489#section-3.1)),
`bounce.example.com` counts as a match for `example.com`.

## Every combination

| SPF | DKIM | DMARC | What it means | Delivered? | Fix |
|---|---|---|---|---|---|
| pass | pass | pass | Both aligned, or at least one. | Yes | Nothing. |
| pass | fail | pass | SPF aligned; the DKIM signature broke or its key is missing. | Yes | [Fix DKIM](/guide/spf-pass-dkim-fail) before a forward breaks SPF too. |
| fail | pass | pass | Typical of forwarding: DKIM survived, SPF did not. | Yes | Usually nothing. See [DKIM pass, SPF fail](/guide/dkim-pass-spf-fail). |
| pass | pass | fail | Neither aligned: a vendor sent with its own domain. | Per your policy | Have the vendor DKIM-sign as your domain. |
| pass | none | fail | SPF passed for the Return-Path domain, not yours. | Per your policy | Turn on the vendor's custom DKIM. |
| fail | fail | fail, `p=none` | Nothing authenticated your domain. | Usually, often to spam | Find the source in DMARC reports. |
| fail | fail | fail, `p=reject` | Nothing authenticated, and you asked for rejection. | No, bounced | Authenticate the sender, or it is a spoof. |
| softfail | pass | pass | Unlisted IP under `~all`; DKIM carried it. | Yes | Add the IP only if it is your sender. |
| permerror | pass | pass | Your SPF record is broken; DKIM carried it. | Yes, for now | [Get under 10 lookups](/guide/spf-too-many-dns-lookups). |
| any | any | fail, `compauth=pass` | Microsoft only: DMARC failed, Microsoft trusted it anyway. | At Microsoft | Fix alignment; other receivers will not do this. |
| any | any | `bestguesspass` | Microsoft only: no DMARC record; it would have passed. | Yes | Publish a DMARC record. |

"Per your policy" means what your DMARC record's `p=` asks for: `none` delivers,
`quarantine` sends to spam, `reject` bounces. Receivers may deviate either way, which
[RFC 7489 §6.7](https://www.rfc-editor.org/rfc/rfc7489#section-6.7) allows explicitly:
"Final disposition of a message is always a matter of local policy."

## SPF pass, DKIM pass, DMARC fail

This is the combination people search for most in disbelief. Nothing is broken, and
the mail is failing anyway:

```
Authentication-Results: mx.google.com;
       dkim=pass header.i=@mail.example.net header.s=s1 header.b=Qm3Tz1pA;
       spf=pass (google.com: domain of bounces+8841@mail.example.net
         designates 198.51.100.23 as permitted sender)
         smtp.mailfrom=bounces+8841@mail.example.net;
       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=example.com
```

Read three values:

- `smtp.mailfrom=…@mail.example.net` — SPF passed for **example.net**.
- `header.i=@mail.example.net` — DKIM passed for **example.net**.
- `header.from=example.com` — the reader sees **example.com**.

Neither pass was for `example.com`, so neither counts. This is a sending platform, such
as a newsletter tool, CRM or helpdesk, using its own envelope and signing domain while
you set the From: address. The fix is the platform's "authenticate your domain" or
"custom DKIM" setting, which makes it sign with `d=example.com`. Adding
`include:mail.example.net` to your SPF record changes nothing, because their mail
still uses their envelope domain.
[Why DMARC fails when SPF passes](/guide/dmarc-fails-when-spf-passes) covers the fix
for each type of platform.

The **pass/none/fail** row is the same problem with one piece missing: the platform
does not DKIM-sign at all, so the only pass is SPF on its own Return-Path domain.

## Forwarding: SPF fail, DKIM pass, DMARC pass

```
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=google header.b=Vx7kP0aL;
       spf=fail (google.com: domain of alice@example.com does not designate
         192.0.2.77 as permitted sender) smtp.mailfrom=alice@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
```

`192.0.2.77` is a forwarding server, such as a university alias or a mailing list.
It kept your envelope sender but connected from its own address, which your SPF record
has never heard of. SPF is working as designed.

`header.i=@example.com` matches `header.from=example.com`, so DKIM carries DMARC on its
own. Do not add the forwarder to your SPF record: you cannot list every server your
recipients forward through, and each entry costs one of your ten DNS lookups.
[DKIM pass, SPF fail](/guide/dkim-pass-spf-fail) explains how to tell a harmless
fail from one that needs a DNS change.

This row is also why DKIM matters more than SPF. A message that passes DMARC only on
SPF, the **pass/fail/pass** row, has nothing left once it is forwarded. If you do not
know which selector your provider signs with, find it from the `s=` tag
([finding your DKIM selector](/guide/dkim-selectors)), or test the common ones with the
[DKIM selector finder](/tools/dkim-selector-finder).

## Microsoft's compauth: DMARC fail, delivered anyway

Microsoft 365 and Outlook.com add a result no other receiver uses:

```
Authentication-Results: spf=pass (sender IP is 198.51.100.23)
 smtp.mailfrom=lists.example.org; dkim=fail (body hash did not verify)
 header.d=example.com;dmarc=fail action=none
 header.from=example.com;compauth=pass reason=130
```

`compauth` is Microsoft's composite authentication. It takes SPF, DKIM, DMARC and its
own signals into account and can overrule the DMARC result.
[Microsoft's header reference](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo#authentication-results-message-header-fields)
lists the reason codes. `130` means an ARC result from a trusted sealer overrode the
DMARC failure, which is typical of a mailing list that rewrote the body. Other `1xx`
codes cover cases such as reverse-DNS alignment.

Read it as "Microsoft decided to trust this", not "this is authenticated". Gmail and
Yahoo do not compute compauth, so the same message fails DMARC there. The fix is the
same as for any DMARC failure: an aligned DKIM signature that survives the path.

**`dmarc=bestguesspass`** is Microsoft-specific too. Their documentation defines it as
no DMARC record for the domain, where the message would have passed if one existed.
Nothing is wrong with the message, but the domain has no DMARC protection at all.

## Permerror: a broken SPF record hidden by DKIM

```
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=s1 header.b=L2nW8sQe;
       spf=permerror (google.com: permanent error in processing during lookup
         of bounce@example.com) smtp.mailfrom=bounce@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
```

A `permerror` is not a verdict on the sender. It means the record could not be
interpreted ([RFC 7208 §2.6.7](https://www.rfc-editor.org/rfc/rfc7208#section-2.6.7)).
The usual causes are more than ten DNS lookups, two SPF records on one name, or an
include that no longer resolves. DMARC still passed here because DKIM aligned, so the
error goes unnoticed. It stays hidden until the day DKIM fails, at which point nothing
passes. Count your lookups with the
[SPF lookup counter](/tools/spf-lookup-counter), and see
[SPF: too many DNS lookups](/guide/spf-too-many-dns-lookups) for ways to get under the
limit.

`softfail` is different and much milder. The record works and says this IP is probably
not authorised (the `~all` ending). For DMARC it is simply not a pass.

## Will my email still be delivered?

DMARC failing does not decide delivery by itself. Your policy tells the receiver what you
want done with failing mail:

- **`p=none`** — deliver as normal and send reports. Failing mail usually arrives,
  though a receiver's own filters may still send it to spam.
- **`p=quarantine`** — treat as suspicious, which in practice means the spam folder.
- **`p=reject`** — refuse it during the SMTP conversation. At Gmail the sender gets
  [550 5.7.26](/guide/bounce/gmail-550-5-7-26-unauthenticated).

Bulk senders have extra rules. [Google requires](https://support.google.com/a/answer/81126)
anyone sending 5,000 or more messages a day to Gmail accounts to set up SPF, DKIM and
DMARC, and the From: domain must align with the SPF or DKIM domain. The DMARC policy
itself may be `p=none`. [Yahoo requires](https://senders.yahooinc.com/best-practices/)
bulk senders to publish a DMARC policy of at least `p=none` that passes, and accepts
relaxed alignment. So for a bulk sender, a DMARC failure is a delivery problem even
under `p=none`. [Google and Yahoo sender requirements](/guide/google-yahoo-sender-requirements)
has the full checklist.

If you have no DMARC record yet, this is the starting point. It changes nothing about
delivery and starts the reports that tell you which row each of your senders is in:

```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
```

Read the reports, make every legitimate source pass with alignment, then move to
`p=quarantine` and `p=reject`.

## Reading your own header

Use a message you **received**, from a mailbox at another provider. A copy in your Sent
folder has no `Authentication-Results` header, because the receiving server is what adds
it. In Gmail, open the message and choose **Show original**. Find the
`Authentication-Results` line added by the receiver, not one added by an earlier hop.
Then find the three domains: `smtp.mailfrom`, `header.d` or `header.i`, and
`header.from`, and compare them with the table above. The
[header analyzer](/headers) does the comparison and applies relaxed or strict
alignment for you.
