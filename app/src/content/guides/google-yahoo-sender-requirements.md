---
title: "Google and Yahoo's sender requirements"
description: "What Google and Yahoo have required from senders since February 2024, who it applies to, and how to tell whether you comply."
question: "What are the Google and Yahoo bulk sender requirements?"
published: 2026-07-31
updated: 2026-07-31
order: 12
faq:
  - q: "What do Google and Yahoo require from bulk senders?"
    a: "SPF and DKIM on the sending domain, a DMARC record with at least p=none, alignment between the visible From domain and the authenticated domain, one-click unsubscribe on marketing mail, and a spam complaint rate below 0.3 percent."
  - q: "Does the 5000 message threshold apply to me?"
    a: "The bulk sender rules formally apply above roughly 5000 messages a day to Gmail addresses, but the authentication requirements are applied to all senders in practice. Below the threshold you still need SPF, DKIM and DMARC."
  - q: "What happens if I do not comply?"
    a: "Mail is throttled or rejected, and the failure is largely invisible from the sending side. There is often no bounce you would notice, just a quiet decline in delivery."
---

In February 2024, Google and Yahoo began enforcing a shared set of requirements on
people who send them mail. A large number of organisations discovered at that point
that they had no idea what SPF, DKIM or DMARC were. The requirements have not
loosened since, and Microsoft has since moved in the same direction.

## What is required

**Everyone sending to Gmail or Yahoo:**

- **SPF and DKIM** on the sending domain. Not one or the other — both.
- **Valid forward and reverse DNS** on the sending IP — and it has to confirm in *both*
  directions. You can [check a sending IP here](/ip), which also covers blocklists.
- **A spam complaint rate below 0.3%**, measured by the receiver, not by you.
- **Messages formatted to RFC 5322.** Standard mail software handles this.
- **No impersonating Gmail `From:` headers.** Sending as `something@gmail.com` from
  your own infrastructure fails outright.

**Additionally, for bulk senders** — roughly 5,000+ messages a day to Gmail addresses:

- **A DMARC record**, at minimum `p=none`.
- **Alignment**: the domain in the visible `From:` header must match the domain
  authenticated by SPF or DKIM.
- **One-click unsubscribe** on marketing mail (`List-Unsubscribe` and
  `List-Unsubscribe-Post` headers), honoured within two days.

## The threshold is not the useful part

The 5,000-a-day figure gets quoted constantly, and it distracts from the practical
reality: the authentication requirements are applied broadly, and a domain without
SPF, DKIM and DMARC is treated with suspicion regardless of volume.

More to the point, the threshold counts messages to *Gmail addresses specifically*,
across everything sent from your domain — marketing, transactional, and whatever your
support desk emits. Organisations routinely cross it without anyone deciding to.

If you are wondering whether the rules apply to you, the question is not worth
answering. Do the authentication work.

## Alignment is where people fail

This is the requirement that catches organisations that thought they were fine.

Passing SPF is not sufficient. The domain that passed SPF must **match** the domain in
the `From:` header your recipient sees.

A typical failure: your marketing platform sends on your behalf using its own envelope
domain. SPF passes — for *their* domain. Your `From:` header says
`hello@yourcompany.com`. Those do not align, so DMARC fails, even though a naive check
shows SPF passing.

The fix is almost always DKIM. Configure the platform to sign with `d=yourcompany.com`
using a selector they give you, and alignment works regardless of the envelope domain.
Every serious sending platform supports this; it is usually called something like
"authenticate your domain" or "custom domain setup" in their onboarding.

Alignment is subtle enough to deserve its own explanation —
[why DMARC fails when SPF and DKIM pass](/guides/dmarc-fails-when-spf-passes/) walks
through it with real headers.

DKIM has a second advantage: it survives forwarding. SPF breaks the moment a message
is forwarded, because the forwarding server is not in your SPF record. If you rely on
SPF alone, every mailing list and every user-configured forward becomes a DMARC
failure.

## How to tell whether you comply

```sh
dig +short TXT yourdomain.com | grep spf1      # SPF present?
dig +short TXT _dmarc.yourdomain.com           # DMARC present?
```

DKIM is harder to verify from DNS alone, because selectors cannot be enumerated — you
have to know the name your provider uses, or guess it. The reliable check is to send
yourself a message and look at the headers: in Gmail, open the message, choose "Show
original", and look for `SPF: PASS`, `DKIM: PASS` and `DMARC: PASS`.

That header view is the single most useful diagnostic available, and it is free.

## What failure looks like

Not a bounce. That is the difficulty.

Mail gets throttled, or filed as spam, or quietly rejected in a way that never reaches
whoever sent it. Your open rates drift down. Someone eventually mentions that they
stopped getting your invoices. By then it has usually been happening for months.

This is why DMARC reporting matters even at `p=none`: the aggregate reports are the
only feedback channel that tells you what receivers actually did with your mail.

## A reasonable order of work

1. Publish SPF listing every system that sends as you.
2. Turn on DKIM at each of those systems, signing with your domain.
3. Publish `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`.
4. Read the reports for a month. Fix whatever is failing alignment.
5. Move to `p=quarantine`, then `p=reject`.
6. Add one-click unsubscribe to anything resembling marketing.

Steps 1 to 3 can be done in an afternoon. Step 4 is the one that takes real time, and
it is the one that cannot be skipped.
