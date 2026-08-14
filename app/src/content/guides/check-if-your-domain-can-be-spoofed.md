---
title: "How to check if your domain can be spoofed"
description: "Find out whether anyone can send email as your domain — in about two minutes, without sending a message. How to run the check and read all three results."
question: "How do I check if my domain can be spoofed?"
category: "Getting started"
published: 2026-08-14
updated: 2026-08-14
order: 8
faq:
  - q: "Can I check whether my domain is spoofable without sending an email?"
    a: "Yes. Everything that decides it lives in public DNS records — SPF, DKIM and DMARC — so a check is a read-only lookup. No mail is sent and nothing touches your servers."
  - q: "I already have SPF and DKIM. Does that stop spoofing?"
    a: "Not on its own. SPF and DKIM let a receiver detect a forgery; DMARC is what tells it to act. If your DMARC policy is missing or set to p=none, receivers check the signatures, see the failure, and deliver the mail anyway."
  - q: "A checker says DKIM is not found. Does that mean DKIM is broken?"
    a: "Not necessarily. DKIM keys live at named selectors and there is no DNS query that lists them, so every checker guesses. A miss can simply mean your provider uses a selector the tool did not try. Find the selector name in your provider's DNS setup instructions and check it directly."
  - q: "How long should I wait after changing DNS before re-checking?"
    a: "Minutes to hours, depending on the TTL on the old record. Re-run the check rather than assuming it worked — a typo in a published record is far more common than a propagation delay."
---

Every week someone discovers that scammers have been sending invoices, password resets
or phishing mail "from" their domain. Not from a hacked mailbox — from thin air. Email's
original design lets any server put any address in the `From:` field, and the only thing
stopping it is three DNS records most domains get at least partly wrong.

You can check your own domain in about two minutes, for free, without sending a single
message. Here is how, and how to read the results.

## What "spoofable" actually means

A domain is spoofable when receiving mail servers have no instruction to reject mail
that fails authentication. That instruction comes from three records working together:

| Record | What it does |
|---|---|
| **SPF** | Lists the servers allowed to send mail for your domain. |
| **DKIM** | Cryptographically signs each message, so receivers can verify it was not forged or altered. |
| **DMARC** | Ties the two together and tells receivers what to do when both fail. |

Here is the part most people miss: **you can have SPF and DKIM configured perfectly and
still be spoofable.** If your DMARC policy is missing or set to `p=none`, receivers check
the signatures, see the failure, and deliver the mail anyway.

The policy is the lock. SPF and DKIM are just the keys.

## Step 1: Run the check

Enter your domain on the [checker](/) and press Check. It reads your public DNS records
and reports on all three mechanisms. No mail is sent, nothing touches your servers, and
the domain you check is not recorded.

Everything below applies whatever checker you use.

## Step 2: Read the SPF result properly

Two failure modes matter, and one of them is invisible.

**The lookup limit.** SPF allows exactly ten DNS lookups. Every `include:` in your
record — and every include *inside* those includes — counts against it. Go over, and
receivers silently stop evaluating your record. No bounce, no warning; your SPF simply
stops existing. This is common on domains using several sending services at once
(Google Workspace, Mailchimp and a CRM will get you close on their own). A good checker
walks the whole chain and shows the count; this one generates a corrected record if you
are over. → [SPF: too many DNS lookups](/guides/spf-too-many-dns-lookups/)

**The ending.** `~all` (softfail) suggests receivers treat unlisted senders with
suspicion; `-all` (hardfail) tells them to reject outright. With DMARC in place, `~all`
is generally the right choice — but the record must end with one of them.
→ [Should it end in ~all or -all?](/guides/spf-softfail-vs-hardfail/)

## Step 3: Check DKIM, and distrust green ticks

DKIM keys live at named *selectors* in DNS, and there is no query that lists a domain's
selectors. Every checker guesses common ones. Two consequences follow:

- **"DKIM not found" does not prove DKIM is absent.** Your provider may use a selector
  the tool never tried. Find the name in your provider's DNS setup instructions and
  check it directly. → [Finding your DKIM selector](/guides/dkim-selectors/)
- **Worse, some domains answer *every* DNS query.** On those, a careless checker reports
  DKIM keys that do not exist. If a tool shows a green tick for a selector, it should
  have verified an actual signing key rather than the mere presence of an answer.

## Step 4: The DMARC record, where spoofing is actually decided

Look for three things.

**The policy.** `p=none` means monitoring only — mail that fails authentication is still
delivered. It is the right place to start and the wrong place to stop; a domain that
stays on `p=none` forever is spoofable forever. The goal is `p=quarantine`, then
`p=reject`. → [What DMARC p=none actually does](/guides/dmarc-p-none/)

**Subdomain coverage.** Attackers who cannot spoof `yourdomain.com` will try
`invoices.yourdomain.com`. Check how your policy applies to subdomains.

**Where the reports go.** DMARC reports (`rua=`) tell you who is sending as your domain.
If they go to a third-party address, that party has to publish a record authorising it —
otherwise your reports silently go nowhere, and the record looks flawless while you stay
blind. Almost no checker tests this.
→ [Your DMARC reports may be going nowhere](/guides/dmarc-reports-not-arriving/)

## Step 5: Fix, wait, re-check

DNS changes propagate in minutes to hours. The safe rollout order:

1. Publish or fix **SPF** — under ten lookups, ending in `~all`.
2. Enable **DKIM** signing at your provider and publish the selector record.
3. Publish **DMARC** at `p=none` with a `rua=` address, and watch the reports for a
   couple of weeks.
4. Move to `p=quarantine`, then `p=reject`, once legitimate mail passes cleanly.

Then re-run the check.

If a suspicious message arrives meanwhile, the [header analyzer](/headers) shows why it
passed or failed DMARC — including the classic case where SPF passes but for the *wrong*
domain, which is why most "we have SPF" domains still fail.
→ [Why DMARC fails when SPF and DKIM pass](/guides/dmarc-fails-when-spf-passes/)

## Why this stopped being optional

Since February 2024, Google and Yahoo have required SPF, DKIM and DMARC from anyone
sending them bulk mail. Non-compliant domains get throttled or rejected, and the failure
is invisible from the sending side — your mail simply stops arriving. Spoofability and
deliverability are now the same problem.

Authentication is only three of the nine things they ask for. The
[Gmail and Yahoo compliance checker](/tools/gmail-yahoo-compliance) runs the whole list.
→ [Google and Yahoo's sender requirements](/guides/google-yahoo-sender-requirements/)

---

Two minutes to check: [run it on your domain](/). If something is broken, it tells you
the exact record to publish.

> Results from any DNS checker are informational. Verify records against your provider's
> documentation before publishing — DNS changes affect live mail delivery.
