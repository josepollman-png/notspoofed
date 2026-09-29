---
title: "Email authentication for Shopify"
titleTag: "Shopify email from shopifyemail.com? Set up DMARC and DKIM"
description: "Store mail sent as store+123@shopifyemail.com means your domain isn't authenticated. Publish Shopify's CNAMEs and a DMARC record, and avoid adkim=s."
answer: "Shopify rewrites your sender to shopifyemail.com when your domain is not authenticated. To fix it, add the CNAME records Shopify gives you under Settings → Notifications → Sender email, which cover DKIM and SPF, then publish a DMARC TXT record at _dmarc of at least v=DMARC1; p=none. Do not use adkim=s or aspf=s."
question: "Why does my Shopify email come from shopifyemail.com?"
category: "Providers"
published: 2026-08-14
updated: 2026-09-22
order: 28
faq:
  - q: "Why does my Shopify store email show as store+123@shopifyemail.com?"
    a: "Shopify rewrote your sender address because your domain is not authenticated. Since February 2024 Gmail and Yahoo require authentication and a DMARC record, so rather than have your mail rejected, Shopify substitutes an address on a domain it does control. Authenticate the domain and your own address comes back."
  - q: "Do I need an SPF TXT record for Shopify?"
    a: "Not for the sender address Shopify authenticates. The CNAME records added during domain authentication cover both SPF and DKIM for it. You still need your own SPF record for any other service that sends as your domain, such as your mailbox provider."
  - q: "Can I use aspf=s or adkim=s with Shopify?"
    a: "No. Shopify states that strict alignment on either tag prevents its mail from authenticating properly. Use relaxed alignment, which is the default when the tags are absent — so the fix is usually to delete them rather than change them."
  - q: "I bought my domain through Shopify. Do I need to do anything?"
    a: "No. Shopify configures DKIM, SPF and DMARC automatically for domains purchased through them. The work described here applies to third-party domains."
---

The symptom that brings most people here: your store's email arrives from something like

```
store+58291@shopifyemail.com
```

instead of your own address. Nothing is broken and nobody has been compromised —
**Shopify rewrote the sender on purpose.**

Since 1 February 2024 Gmail and Yahoo require senders to authenticate their domain and
publish a DMARC record. An unauthenticated branded address would be throttled or
rejected outright, so rather than let your order confirmations fail, Shopify substitutes
an address on a domain it controls and can authenticate. The rewrite is a fallback, not
a fault.

Authenticate your domain and your own address comes back.

## What to publish

Shopify handles this with **CNAME records** rather than the usual SPF and DKIM TXT
records. Add the CNAMEs it gives you in Settings → Notifications → Sender email, and they
configure DKIM signing *and* SPF for that sender in one step.

This is the part that surprises people: **you do not add a separate SPF TXT record for
the Shopify sender.** The CNAMEs cover it. You still need your own SPF record for
anything else that sends as your domain — your mailbox provider, a CRM, an invoicing
tool — and that record is unaffected by any of this.

If your domain is hosted at Cloudflare, GoDaddy or IONOS, Shopify can add the records
for you. If you bought the domain through Shopify, everything above is already done.

## Then the DMARC record

Shopify requires one, and the minimum it accepts is:

```
v=DMARC1; p=none
```

Add a reporting address while you are there, so the record does something useful rather
than merely existing:

```
v=DMARC1; p=none; rua=mailto:dmarc@example.com
```

Host `_dmarc`, type TXT.

## The tag that breaks it

**Do not use `adkim=s` or `aspf=s`.** Shopify states directly that strict alignment on
either tag prevents mail sent through Shopify from authenticating properly.

This is worth flagging because plenty of general DMARC advice recommends strict
alignment as the more secure setting, and it is — for a domain where every sender signs
with the exact domain in the `From:` header. A platform sending on your behalf through
its own infrastructure is precisely the case where strict alignment stops being free.

Relaxed alignment is the **default when the tags are absent**, so if you have inherited a
record containing them the fix is usually to delete the tags rather than set them to `r`.

If your store mail started failing right after you "hardened" your DMARC record, this is
almost certainly why.

## Where this leaves your policy

Shopify's minimum is `p=none`, which collects reports and blocks nothing. That satisfies
Shopify and satisfies the letter of the Gmail and Yahoo requirement, and it leaves your
domain spoofable.

Once your Shopify sender authenticates cleanly and your reports show every other
legitimate sender passing, move up: `p=quarantine`, then `p=reject`. Do it in that order
and read the reports at each stage — a store domain usually has more senders than the
owner expects, between the platform, a marketing tool and a support desk.

→ [What DMARC p=none actually does](/guide/dmarc-p-none)
→ [Google and Yahoo's sender requirements](/guide/google-yahoo-sender-requirements)

## Checklist

1. Settings → Notifications → Sender email, enter your branded address.
2. Publish the CNAME records Shopify gives you.
3. Publish `_dmarc` with at least `v=DMARC1; p=none` and a `rua=` address.
4. Confirm no `adkim=s` or `aspf=s` anywhere in that record.
5. Wait for Shopify to verify, then send yourself a test order confirmation and check the
   `From:` address is yours.

---

[Check the domain](/) to confirm the records resolve and the DMARC record parses, and
[paste the headers](/headers) from a test order confirmation to see whether the Shopify
signature actually aligns with your domain.
