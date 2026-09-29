---
title: "Google and Yahoo sender requirements: a pass/fail checklist"
titleTag: "Gmail and Yahoo sender requirements: pass/fail checklist"
description: "The 12 Gmail and Yahoo sender requirements (SPF, DKIM, DMARC, one-click unsubscribe, spam rate), each with a pass test, and which no DNS lookup can check."
question: "What are the Google and Yahoo bulk sender requirements?"
category: "Bulk senders"
published: 2026-07-31
updated: 2026-09-11
order: 12
faq:
  - q: "What do Google and Yahoo require from bulk senders?"
    a: "SPF and DKIM on the sending domain, a DMARC record of at least p=none, the From domain aligned with the SPF or DKIM domain, one-click unsubscribe on marketing and subscribed mail honoured within two days, a spam complaint rate below 0.30 percent, forward-confirmed reverse DNS on the sending IP, and TLS on the connection."
  - q: "Does the 5,000 a day threshold apply to me?"
    a: "Google counts messages sent to personal Gmail accounts in a 24-hour period, adding up every subdomain of the same primary domain. Cross it once and Google treats you as a bulk sender permanently — bulk status has no expiry. Below the threshold you still need SPF or DKIM, valid reverse DNS, TLS and a spam rate under 0.30 percent."
  - q: "Can a domain checker tell me whether I comply?"
    a: "Only partly. SPF, DKIM key publication, DMARC and reverse DNS are visible in DNS. Alignment and the unsubscribe headers exist only in a delivered message, and your spam complaint rate exists only inside Google Postmaster Tools and Yahoo Sender Hub. Any checker showing all twelve green after a DNS lookup is reporting things it never measured."
  - q: "What happens if I fail one of these?"
    a: "Usually nothing you can see. Mail is throttled, filed as spam, or rejected in a way that never reaches the person who sent it. Aggregate DMARC reports and Postmaster Tools are the only feedback channels that tell you what receivers actually did."
---

Every domain sending to Gmail or Yahoo must pass SPF or DKIM, have forward-confirmed
reverse DNS on its sending IP, connect over TLS, and keep Gmail-reported spam
complaints under 0.30%. Send about 5,000 messages a day or more to personal Gmail
addresses and you also need DMARC, alignment, and one-click unsubscribe on marketing
mail.

Below is each requirement with the condition that counts as passing — not a
description of the topic, a test you can run. Where Google and Yahoo word a
requirement differently, both wordings are given.

## The checklist

### 1. SPF published, valid, and covering every sender

**Passes when** your domain publishes exactly one `v=spf1` TXT record, it evaluates in
ten DNS lookups or fewer, and every system that sends as you is inside it. Two SPF
records is a permanent error; so is the eleventh lookup.

Run the [domain check](/) for the record and the lookup count. If it comes back over
ten, [SPF: too many DNS lookups](/guide/spf-too-many-dns-lookups) is the fix, and
[`~all` vs `-all`](/guide/spf-softfail-vs-hardfail) covers the ending — either
qualifier satisfies the requirement, so do not break working mail to change it.

### 2. DKIM signing with a key that resolves

**Passes when** delivered messages carry a `DKIM-Signature` with `d=` your domain, the
`s=` selector resolves to a TXT record at `selector._domainkey.yourdomain` with a
non-empty `p=`, and the signature verifies.

Selectors cannot be enumerated from DNS, so this one is only half-checkable without a
message — [DKIM selectors explained](/guide/dkim-selectors) covers why, and the
[selector finder](/tools/dkim-selector-finder) tries the names your provider is likely
to use. Confirm it properly by pasting a real message into the
[header analyzer](/headers).

### 3. A DMARC record on the sending domain

**Passes when** `_dmarc.yourdomain` returns a single TXT record starting `v=DMARC1;`
with a `p=` tag. Both providers accept `p=none` — Yahoo's wording is "publish a valid
DMARC policy with at least p=none". Required above the volume threshold, and worth
publishing below it.

Add `rua=` at the same time. A DMARC record without a reporting address enforces
nothing and teaches you nothing: see [what p=none actually does](/guide/dmarc-p-none).

### 4. Alignment between the From domain and the authenticated domain

**Passes when** the domain in the visible `From:` header matches either the domain that
passed SPF or the `d=` domain that passed DKIM. Google: "The domain in the sender's
From: header must be aligned with either the SPF domain or the DKIM domain."

This is the requirement that catches organisations that believed they were fine,
because SPF can pass for your vendor's envelope domain while your `From:` says
something else. Open a delivered message in Gmail, choose **Show original**, and read
the `DMARC:` line — `PASS` is the only passing result. If it says `FAIL`,
[why DMARC fails when SPF and DKIM pass](/guide/dmarc-fails-when-spf-passes) is the
walkthrough, with [SPF pass, DKIM fail](/guide/spf-pass-dkim-fail) and
[DKIM pass, SPF fail](/guide/dkim-pass-spf-fail) for the two halves.

### 5. The one-click unsubscribe header pair

**Passes when** marketing and subscribed messages carry *both* headers, exactly:

```
List-Unsubscribe-Post: List-Unsubscribe=One-Click
List-Unsubscribe: <https://example.com/unsubscribe/token>
```

and both header names appear in the `h=` list of your DKIM signature. Transactional
mail — password resets, receipts, booking confirmations — is excluded by Google from
this requirement.

Two failure modes dominate, and both are silent:
[`List-Unsubscribe` present but `List-Unsubscribe-Post` missing](/guide/missing-list-unsubscribe-post),
and [the headers not covered by the DKIM signature](/guide/list-unsubscribe-not-dkim-signed).
Send yourself a campaign and run it through the
[unsubscribe checker](/tools/unsubscribe-checker).

### 6. An unsubscribe endpoint that works and is honoured in two days

**Passes when** the `List-Unsubscribe` URL is HTTPS, accepts an unauthenticated HTTP
POST, returns success without asking the recipient to log in or confirm anything, and
the address is actually removed within two days. Yahoo states it plainly: "Honor
unsubscribes within 2 days." Google's guidance is the same 48 hours.

A `mailto:` value alone does not satisfy one-click —
[the URL has to be HTTPS](/guide/one-click-unsubscribe-https) — and an endpoint that
answers the POST with a redirect to a preference centre
[often fails in practice](/guide/unsubscribe-endpoint-redirects). Test it with a real
POST, not by clicking the link in your browser.

### 7. Forward and reverse DNS on the sending IP

**Passes when** the IP your mail leaves from has a PTR record, and the hostname in that
PTR resolves forward to the same IP. Both directions, or it does not count. Google:
"Ensure that sending domains or IPs have valid forward and reverse DNS records, also
referred to as PTR records."

Put the IP into the [sending IP checker](/ip), which confirms the round trip and checks
the major blocklists while it is there. If you send through a provider, their addresses
are their responsibility and are normally correct.

### 8. TLS on the connection

**Passes when** your outbound server negotiates STARTTLS with the receiver. Google lists
it as a requirement for every sender — "Use a TLS connection for transmitting email."
Yahoo's published requirements do not name TLS, so Google's is the binding one.

Check the `Received:` header of a delivered message: `with ESMTPS` means the hop was
encrypted, `with ESMTP` means it was not. For the inbound direction,
[MTA-STS](/guide/mta-sts-setup) is the separate, stronger commitment — not required
here, but the next thing worth doing.

### 9. Spam complaint rate below 0.30%

**Passes when** the user-reported spam rate in Google Postmaster Tools stays below
0.10% and never reaches 0.30%. Google's wording: "Keep spam rates reported in
Postmaster Tools below 0.10% and avoid ever reaching a spam rate of 0.30% or higher."
Yahoo: "Keep your spam rate below 0.3%", reported in Yahoo Sender Hub.

There is no DNS record, header or public source for this number. You must have
[Postmaster Tools set up](/guide/google-postmaster-tools) — and it needs DKIM or SPF
verification and enough volume before it shows you anything, so set it up before you
need it, not during an incident.

### 10. Know which side of 5,000 a day you are on

**Passes when** you have actually counted, rather than assumed. Google: "A bulk sender
is any email sender that sends close to 5,000 messages or more to personal Gmail
accounts within a 24-hour period." Every subdomain of the same primary domain is added
together — 2,500 from the root and 2,500 from a marketing subdomain makes you a bulk
sender. And it does not lapse: "Email senders that have been classified as bulk senders
are permanently classified as such."

The count is of personal Gmail addresses, across marketing, transactional and whatever
your support desk emits. Add those up, then run the
[Gmail and Yahoo compliance checker](/tools/gmail-yahoo-compliance) against the domain.

### 11. ARC, if you forward mail

**Passes when** messages leaving your forwarder carry `ARC-Seal`,
`ARC-Message-Signature` and `ARC-Authentication-Results`, and the chain validates. Yahoo
requires it of forwarders: "If you forward emails, implement ARC (Authenticated Received
Chain)." Google's sender guidelines do not list ARC as a numbered requirement; they point
forwarders at the forwarding best practices instead.

This applies to you only if you run a mailing list, an inbound gateway, or a service that
relays other people's mail. If you do, check that your MTA is configured to seal — most
can, few do by default.

### 12. A From domain you control, and not a free-mail address

**Passes when** the `From:` header uses a domain whose DNS you administer, and the
message is formatted to RFC 5322. Sending as `you@gmail.com` from your own
infrastructure fails outright: Google's requirement is "Don't impersonate Gmail From:
headers", backed by a DMARC policy on its consumer domains. Checked on 11 September
2026, `gmail.com` publishes `p=none; sp=quarantine` and `yahoo.com` publishes
`p=reject` — so a forged `@yahoo.com` From is refused today.

Move the address to your own domain and authenticate that, then confirm it with
[the spoofability check](/guide/check-if-your-domain-can-be-spoofed).

## Which of these a domain check can settle

This matters, because a checklist that implies a DNS lookup measures a complaint rate
is lying to you.

| Verifiable from DNS alone | Needs a real delivered message | Needs Postmaster Tools or Sender Hub |
|---|---|---|
| SPF published and valid (1) | DKIM signature verifying (2) | Spam complaint rate (9) |
| DKIM key, *if you know the selector* (2) | Alignment (4) | |
| DMARC record present (3) | Unsubscribe header pair and DKIM coverage (5) | |
| Reverse DNS, *if you know the IP* (7) | TLS on the hop, via `Received:` (8) | |
| Free-mail From policies (12) | | |

Items 6, 10 and 11 belong to none of the three: the unsubscribe endpoint needs an HTTP
POST, the volume threshold needs your own sending figures, and ARC applies only if you
forward.

So the honest sequence is three passes, in this order:

1. **DNS.** Run the [domain check](/) and the
   [compliance checker](/tools/gmail-yahoo-compliance). Settles items 1, 3, 7 and 12,
   and half of 2.
2. **A real message.** Send yourself one, open **Show original**, paste it into the
   [header analyzer](/headers), and run a campaign through the
   [unsubscribe checker](/tools/unsubscribe-checker). Settles 2, 4, 5 and 8.
3. **Reporting.** Postmaster Tools and Sender Hub for item 9, and `rua=` in your DMARC
   record for everything that fails when you are not looking.

The first pass takes ten minutes. The third is the one nobody does, and it is the one
that tells you when something broke.
