---
title: "Setting up DMARC on Microsoft 365"
description: "M365 signs your mail with onmicrosoft.com by default, which does not align with your own domain. Why DMARC still fails with DKIM switched on, and the fix."
question: "How do I set up DMARC for Microsoft 365?"
category: "Providers"
published: 2026-08-14
updated: 2026-08-14
order: 24
faq:
  - q: "DKIM is enabled in Microsoft 365 but DMARC still fails. Why?"
    a: "Almost certainly because the signature uses the tenant domain. By default Microsoft signs with d=yourtenant.onmicrosoft.com, and Microsoft's own alignment table shows that does not align with a From address at your custom domain under either relaxed or strict alignment. Enable DKIM signing for the custom domain itself in the Defender portal."
  - q: "Do I need a DMARC record for my onmicrosoft.com domain?"
    a: "Yes. SPF and DKIM are pre-configured for it but DMARC is not, and you add that record in the Microsoft 365 admin center rather than at a registrar. If you never send from it, publish v=DMARC1; p=reject to park it."
  - q: "Why do I get no DMARC aggregate reports from Microsoft?"
    a: "Microsoft only sends aggregate reports when your MX record points directly at Microsoft 365. If a third-party gateway or an on-premises hybrid server sits in front, Microsoft sends nothing. Microsoft never sends failure (ruf) reports at all."
  - q: "Can I set the DMARC record for my custom domain in the Microsoft 365 admin center?"
    a: "No. There is no portal or PowerShell cmdlet for DMARC on custom domains — the record goes at your DNS host. Only the *.onmicrosoft.com record is managed inside the admin center."
---

Microsoft 365 will tell you DKIM is enabled, your SPF record will look correct, and your
mail will still fail DMARC. This is the most common M365 outcome and it has one specific
cause that the setup checklists do not mention.

## The trap: the default signature does not align

When you enable DKIM in Microsoft 365 without configuring it for your custom domain,
outbound mail is signed with the **tenant** domain — `d=yourtenant.onmicrosoft.com` —
rather than the domain in your `From:` header.

DMARC does not care that DKIM passed. It cares whether the signing domain **aligns**
with the domain your recipient sees. Microsoft's own alignment table is unambiguous:

| `From:` address | Signing / MAIL FROM domain | Relaxed | Strict |
|---|---|---|---|
| `user@contoso.com` | `contoso.com` | pass | pass |
| `user@contoso.com` | `bounces.contoso.com` | pass | fail |
| `user@contoso.com` | `contoso.onmicrosoft.com` | **fail** | **fail** |

`contoso.onmicrosoft.com` is a different organisational domain from `contoso.com`, so it
fails even relaxed alignment. Your DMARC result then rests on SPF alone — and the moment
anything forwards the message, SPF breaks too and DMARC fails outright.

**The fix:** Defender portal → Email & collaboration → Policies & rules → Threat policies
→ Email authentication settings → DKIM, and enable signing **for your custom domain**.
That publishes two CNAMEs (`selector1._domainkey` and `selector2._domainkey`) which
point back at Microsoft, and rotates keys for you. Until those exist and signing is
switched on, you do not have aligned DKIM.

→ [Why DMARC fails when SPF and DKIM pass](/guides/dmarc-fails-when-spf-passes/)

## Order of operations

1. **SPF** at the domain root: `v=spf1 include:spf.protection.outlook.com -all`. Add any
   other senders, and watch the ten-lookup limit.
   → [SPF: too many DNS lookups](/guides/spf-too-many-dns-lookups/)
2. **DKIM for the custom domain** — the step above. Not the default.
3. **DMARC**, at your DNS host. There is no admin-centre control for this on custom
   domains, and no PowerShell cmdlet; Microsoft is explicit about that.

```
Host:  _dmarc
Type:  TXT
Value: v=DMARC1; p=none; rua=mailto:dmarc@example.com
```

## Your onmicrosoft.com domain needs its own record

Every tenant has one, SPF and DKIM are configured on it already, and **DMARC is not**.
If you never send from it — most tenants do not — park it explicitly:

```
v=DMARC1; p=reject
```

That one is added inside the Microsoft 365 admin center: Settings → Domains → select the
`*.onmicrosoft.com` domain → DNS records → Add record.

## Reports: expect less than you think

Two Microsoft-specific limits, both worth knowing before you interpret a quiet inbox as
good news.

**Microsoft never sends failure (`ruf`) reports.** Not for any domain, regardless of what
your record asks for. An empty `ruf` mailbox is expected.

**Microsoft only sends aggregate (`rua`) reports if your MX points directly at Microsoft
365.** If you route inbound mail through a third-party security gateway first, or run a
hybrid setup where mail lands on-premises before a connector passes it to Microsoft,
Microsoft sends **no aggregate reports at all**. Your reports then cover a smaller slice
of your mail than you assume — which matters most at the moment you are deciding whether
it is safe to move to `p=reject`.

And if your `rua=` address is on a different domain from the one being monitored, that
other domain has to authorise it with a `_report._dmarc` record, or every conforming
receiver discards the reports silently.
→ [Your DMARC reports may be going nowhere](/guides/dmarc-reports-not-arriving/)

## Two more Microsoft-specific behaviours

**Enforcement affects your own outbound mail.** If your policy is `p=quarantine` or
`p=reject`, outbound M365 mail that fails DMARC at the destination is routed through
Microsoft's high-risk delivery pool — a separate, lower-reputation IP range. There is no
override for this. It is another reason to fix alignment before raising the policy
rather than after.

**`dmarc=bestguesspass` in a header is not a pass.** Microsoft infers a result when the
sending domain has no DMARC record at all. Seeing it on your own mail means your record
is not being found — treat it as missing, not as passing.

## Rollout

Microsoft recommends starting with a low-volume subdomain and saving the parent domain
for last, which is good advice. Their documentation also recommends stepping `pct=` from
10 to 100 — **skip that part.** [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989)
removed `pct=`, because implementations never agreed on what a partial value meant. Move
the policy itself instead: `p=none` → `p=quarantine` → `p=reject`.

Note that a DMARC record covers subdomains by inheritance, including ones that do not
exist — but **each sending subdomain still needs its own SPF and DKIM**, or it inherits
an enforcing policy it cannot satisfy.

---

[Check the domain](/) — it reads what receivers actually see, which is the only way to
confirm the DKIM CNAMEs resolve and the signing domain aligns.
