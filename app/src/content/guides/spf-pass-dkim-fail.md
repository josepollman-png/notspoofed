---
title: "SPF passed but DKIM failed"
titleTag: "DKIM fail, SPF pass: what it means and how to fix DKIM"
description: "SPF passing says nothing about DKIM. Read the failure: body changed in transit, a missing or revoked selector, or a mailing list. Then fix the right one."
answer: "SPF and DKIM check different things, so one passing says nothing about the other. DKIM usually fails because something changed the message after signing, such as a footer, link rewriter or mailing list, or because the selector in s= is missing or revoked in DNS. DMARC still passes if the SPF pass aligns with your From domain."
question: "Why did SPF pass but DKIM fail?"
category: "DKIM"
published: 2026-09-08
updated: 2026-09-22
order: 32
faq:
  - q: "Can DMARC pass if DKIM fails?"
    a: "Yes. DMARC needs one aligned pass, not two. If SPF passed for a domain that aligns with your From header, DMARC passes even though DKIM failed. If the SPF pass was for a vendor's envelope domain, nothing aligned and DMARC fails."
  - q: "Why does DKIM fail only on mailing lists?"
    a: "Because lists modify the message. Subject tags, footers and added List- headers change bytes the signature covers, and the body hash no longer matches. The signature was valid when it left you and broke in transit."
  - q: "What does dkim=fail body hash did not verify mean?"
    a: "The body of the message changed after it was signed. Something between you and the recipient appended, rewrote or re-encoded it — a footer appliance, a link rewriter, or a list server. The headers are usually fine."
  - q: "Is dkim=permerror the same as dkim=fail?"
    a: "No, and the difference is the whole diagnosis. permerror means the verifier could not use your key at all — the selector is not in DNS, the record is malformed, or the key is revoked. fail means the key was found and the signature did not match."
---

You opened a delivered message, looked at the source, and found this:

> **Find your selector.** The [DKIM selector finder](/tools/dkim-selector-finder) tests the selectors every major provider publishes for a domain, follows CNAME delegation to whoever holds the key, and reports key size, testing mode and revoked keys.

```
Authentication-Results: mx.google.com;
       dkim=fail header.i=@example.com header.s=s1 header.b=Ht9kQ2mR;
       spf=pass (google.com: domain of bounce@example.com designates
         198.51.100.20 as permitted sender) smtp.mailfrom=bounce@example.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com
```

One passed, one failed, and the natural reading — "the two of them disagree, so one of
them is lying" — is wrong. SPF and DKIM are not two opinions about the same question.
They check different things, and a pass from one carries no information at all about the
other.

## What each result actually proves

**SPF checked the connection.** It took the envelope sender — the `MAIL FROM` address
in the SMTP conversation, which your recipient never sees — and asked whether the IP
that connected was listed in that domain's SPF record. A pass means one thing: *this
machine was allowed to send for that envelope domain.* It says nothing about who wrote
the message, nothing about whether the content arrived intact, and nothing about the
address in the `From:` header.

**DKIM checked the message.** The signer hashed the body, hashed a named list of header
fields, and signed the result with a private key. A verifier fetches the public key from
DNS and recomputes both hashes. A failure means the bytes it hashed are not the bytes
that were signed, or that it could not get a usable key.

So `spf=pass` with `dkim=fail` is not a contradiction. It is the completely ordinary
situation where the message travelled by an authorised path and then something changed
it — or where your key is not where the verifier looked.

## Why DMARC can still pass

DMARC does not require both. [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989), the
2026 revision that replaced RFC 7489, puts it plainly: if **one or more** of the
authenticated identifiers aligns with the Author Domain, the message passes DMARC.

The Author Domain is the domain in the `From:` header — the one your recipient actually
reads. That is the whole point of the mechanism. SPF authenticates the envelope sender,
DKIM authenticates the `d=` value of the signature, and DMARC's job is to insist that at
least one of those matches the visible one.

Alignment has two modes, set in your DMARC record:

- **Relaxed** (`aspf=r` / `adkim=r`, the default) — the organisational domains must
  match, so `bounce.example.com` aligns with `example.com`.
- **Strict** (`aspf=s` / `adkim=s`) — the domains must be identical.

That gives you two very different situations wearing the same `dkim=fail`:

| What you see | What it means |
|---|---|
| `spf=pass` aligned, `dkim=fail`, `dmarc=pass` | Delivery is fine today. You are running on one leg, and it is the leg that breaks when anyone forwards your mail. |
| `spf=pass` for a vendor domain, `dkim=fail`, `dmarc=fail` | Nothing authenticated your From domain. This is being rejected at `p=reject`. |

If yours is the second row, the SPF half of the problem is alignment rather than DKIM —
[why DMARC fails when SPF passes](/guide/dmarc-fails-when-spf-passes) covers that half
in full. The rest of this page is about the DKIM half, which you need fixed either way.

## Reading which identifier failed

`Authentication-Results` is defined by
[RFC 8601](https://www.rfc-editor.org/rfc/rfc8601), and the useful part is that each
method reports its own identifier. For DKIM those are `header.d` (the signing domain),
`header.s` (the selector), `header.i` (the signing identity) and `header.b` (the first
bytes of the signature, which lets you tell two signatures apart). For SPF it is
`smtp.mailfrom`.

Microsoft writes the same information differently:

```
authentication-results: spf=pass (sender IP is 198.51.100.20)
 smtp.mailfrom=example.com; dkim=fail (body hash did not verify)
 header.d=example.com; dmarc=pass action=none header.from=example.com;
 compauth=pass reason=100
```

The parenthetical is where the diagnosis lives, and the exact wording varies by
receiver. The distinctions that matter:

| Result | What the verifier is telling you |
|---|---|
| `dkim=fail` *(body hash did not verify)* | The key was fine. The **body** changed after signing. |
| `dkim=fail` *(signature did not verify)* | The key was fine. A **signed header** changed. |
| `dkim=permerror` | It could not use your key: no such selector, malformed record, or revoked. |
| `dkim=temperror` | DNS did not answer. Retryable, not your configuration. |
| `dkim=none` | There was no signature to check at all. |
| `dkim=neutral` | The verifier declined to reach a verdict — Gmail uses this for a bad body hash. |

Two more things worth noticing before you go hunting. A message can carry **more than
one** `DKIM-Signature`, and a receiver reports a result for each — your ESP's signature
plus your own is normal, and one `pass` alongside one `fail` is fine as long as the
aligned one passed. And you must read this from a message you **received**, at a mailbox
on another provider. A copy from your Sent folder has no `Authentication-Results` header
at all, because that verdict is written by the receiving server.

Paste the block into the [header analyzer](/headers) if you would rather not do the
comparison by eye — it pulls out `d=`, `s=` and the alignment verdict. It runs in your
browser, so nothing is uploaded.

## The causes, in the order they are worth checking

### Something rewrote the message in transit

This is the common one, and the tell is `body hash did not verify`. DKIM signs the body
byte for byte; the relaxed canonicalisation defined in
[RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) forgives trailing whitespace and
collapses runs of spaces, and that is the entire allowance. Anything else breaks it:

- A security appliance appending a legal disclaimer or an external-sender banner.
- A link rewriter — URL defence, click tracking, safe-links — swapping every href.
- A gateway re-encoding the body from 8-bit to quoted-printable.
- An antivirus scanner stripping or replacing an attachment.

If the appliance is yours and sits *after* signing, either move signing to the last hop
outbound or stop it modifying the body.

### A mailing list or a forwarder

The same effect, deliberately. Lists add a `[listname]` subject tag, append an
unsubscribe footer, and insert `List-Id` and friends. Any of those breaks the signature
if it touches something the signature covers.

Header additions break it for a reason people find surprising: RFC 6376 lets a signer
name a header field in `h=` **even when that field does not exist**, treating it as an
empty string. Signers do this deliberately — it is called over-signing — precisely so
that adding one later invalidates the signature. If your ESP over-signs `Sender:` or
`List-Unsubscribe:` and a list adds one, DKIM fails and nothing is misconfigured.

There is no fix for this on your end, because it is not your bug. Modern lists mitigate
it with [ARC](https://www.rfc-editor.org/rfc/rfc8617), which records the authentication
verdict at each hop so a downstream receiver can see the message passed before the list
touched it. ARC is Experimental, and the large receivers honour it from senders they
already trust. What you can do is make sure the message was signed correctly when it
left you — check a direct delivery, not the list copy.

### The selector is not in DNS, or was rotated out

`dkim=permerror` with wording about a missing key. RFC 6376 is specific here: if the key
record does not exist, the verifier **must** immediately return PERMFAIL. Look at the
`s=` value in the failing signature and query it:

```sh
dig +short TXT s1._domainkey.example.com
```

Nothing back means the signer is signing with a selector you never published, or one
you published and later deleted, or a CNAME to the provider that no longer resolves.
Providers rotate keys and expect the CNAME to follow. See
[finding your DKIM selector](/guide/dkim-selectors) if you do not know which selectors
you should have.

### The key is revoked

A record that exists but reads `v=DKIM1; p=` is a **revoked** key — RFC 6376 requires a
PERMFAIL, and it makes no distinction between a revoked key and a deleted one. This
happens when a rotation was half-finished, or when a wildcard `*._domainkey` record with
an empty `p=` is answering for a selector you forgot to publish explicitly.

### The record is there but unusable

Worth ruling out while you have `dig` open:

- **A split TXT record reassembled wrongly.** Keys longer than 255 octets are published
  as multiple quoted strings that concatenate. Some DNS interfaces insert a space at the
  join, which corrupts the key.
- **An algorithm mismatch.** Signing Ed25519 against an `k=rsa` record fails as a
  permerror, not as a bad signature.
- **An expired signature.** The `x=` tag sets an expiry; a badly delayed message can
  arrive after it.

### A body length limit

If your signatures carry an `l=` tag, only that many octets of the body are signed and
everything past it is unverified. RFC 6376 explicitly warns that verifiers may treat a
message with content beyond the signed length with suspicion and fail it as
`unsigned content`. If you are setting `l=` to survive footer appliances, stop — you are
trading a working signature for one receivers are entitled to reject.

## What to do next

Send one message from the affected system to a mailbox at a different provider —
directly, not via a list — and read the `Authentication-Results` in the delivered copy.

If it says **permerror**, the fix is DNS: publish the selector the `s=` tag names, or
repair the CNAME, and re-test in a few minutes.

If it says **body hash did not verify** on a direct send, an appliance in your own
outbound path is modifying signed mail; move the signing step after it.

If a direct send passes and only list traffic fails, your DKIM is correct and you should
leave it alone — publish `p=quarantine` rather than `p=reject` while you watch the
aggregate reports, so list mail is not destroyed while ARC does its work.

Run the domain through the [checker](/) to confirm which selectors resolve before you
change anything else. If your header shows a different mix of results,
[what every SPF, DKIM and DMARC pass/fail combination means](/guide/spf-dkim-dmarc-results)
covers each one.
