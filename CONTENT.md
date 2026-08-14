# Content engine

The checker cannot win on "spf checker" — MXToolbox has two decades of domain authority
on those terms. What nobody covers well is the **fix**, so every page here targets a
problem-shaped query and ends by handing the reader a record, not a definition. That is
already the rule in `src/content.config.ts`; this file turns it into a repeatable cycle
with a queue in front of it.

## The constraint that shapes everything

**Ten strong pages beat a thousand thin ones**, and on this site the asymmetry is worse
than usual. The product's entire claim is that it never overclaims — unguessable DKIM
selectors, unevaluable SPF macros and refused blocklist queries are all reported as
*unknown*, never as clean. A content pipeline that publishes plausible-sounding pages
faster than they can be verified destroys the only asset the site has.

So this is a **draft-and-verify queue, not an auto-publisher.** Nothing reaches
`src/content/guides/` without the verification pass below. A weekly cadence that ships
one checked page beats a daily one that ships five guesses.

## Definition of done

A page is publishable when every line is true:

1. **Every factual claim traces to a primary source** — an RFC, or the provider's own
   documentation. Not a competitor's blog, not a summary, not memory. Link it.
2. **The page ends in something pasteable** — a record, a DNS row, an exact setting. A
   page that only explains is a page that ranks and helps nobody.
3. **It contradicts something, specifically.** Every page below exists because the
   common advice is wrong or incomplete somewhere. If a draft agrees with the top ten
   results start to finish, it has no reason to outrank them — find the divergence or
   drop the page.
4. **It does not restate a page we already have.** Link to the guide that owns the
   detail instead. Cannibalisation is the main risk in a queue this dense.
5. **`updated` is real**, and the claims were re-checked on that date.
6. `npm run check`, `npm test`, and every internal link resolving locally — with
   `/tools/*` expected to 404 locally, since Caddy serves those from the other app.

## Already covered — do not duplicate

Checked before queueing anything. Two of the obvious error-page targets are done:

| Tempting target | Already owned by |
|---|---|
| "DMARC fail but SPF pass" | `dmarc-fails-when-spf-passes` |
| "SPF permerror too many DNS lookups" | `spf-too-many-dns-lookups` |
| "how to check if domain can be spoofed" | `check-if-your-domain-can-be-spoofed` |
| "DKIM selector not found" | `dkim-selectors`, `dkim-selector-list` |
| "what does p=none do" | `dmarc-p-none` |
| "~all vs -all" | `spf-softfail-vs-hardfail` |
| "DMARC reports not arriving" | `dmarc-reports-not-arriving` |

For `permerror` specifically the fix is a **section and an FAQ entry inside the existing
page**, not a new page — the query is a synonym, and two pages competing for it is worse
than one.

## Type 1 — Error-message pages

The highest-intent traffic on the site. Someone pasting an SMTP error into a search box
has a broken system and no patience, and the query is close to zero-competition when the
error string is exact.

**Raw material already exists.** `src/lib/findings.ts` defines ~55 finding ids and
`src/lib/guide-links.ts` maps only 21 of them to a guide. Every unmapped finding that a
receiver reports as a *string* is a candidate — the finding text is the outline, and
`remediate.ts` already contains the fix.

Template: the verbatim error first (it is what they searched, and seeing it is how they
know they are on the right page) → what the receiver actually did → the two or three
causes ranked by how often they are the real one → the fix per cause → how to confirm.

| Query | Finding id | Status |
|---|---|---|
| `554 5.7.5 permanent error evaluating DMARC` | `dmarc-syntax`, `dmarc-multiple` | **published** |
| `SPF PermError` (synonym section) | `spf-syntax` | queued — extend existing page |
| `dmarc=fail (p=REJECT)` in headers | `header-dmarc-fail` | queued |
| `550 5.7.26 unauthenticated email` | — | owned by the tools app KB |
| `too many void lookups` | `spf-void-limit` | queued |
| `no valid DKIM key for signature` | `dkim-revoked`, `dkim-none-found` | queued |
| `SPF record has multiple records` | `spf-multiple-records` | queued |
| `MTA-STS policy fetch failed` | `mtasts-policy-unreachable` | queued |

## Type 2 — Provider setup pages

Steady, durable volume, and the pages age slowly. The trap is that the provider's own
documentation already ranks first and is more authoritative — so **a page that only
restates the provider's steps has no reason to exist.**

The angle that does: the provider's docs tell you what to click; they do not tell you
where their advice is out of date, what breaks at the boundary with other senders, or
what their control panel silently does differently. Google's own DMARC page still
recommends `pct=`, which RFC 9989 removed — the checker already flags that as
`dmarc-pct`. That gap *is* the page.

| Query | Angle | Status |
|---|---|---|
| DMARC for Google Workspace | Their doc recommends deprecated `pct=`; 48-hour wait; no `ruf` support | **published** |
| DMARC for Microsoft 365 | Tenant vs custom domain; `onmicrosoft.com` cannot be DMARC'd usefully | queued |
| SPF/DMARC on Cloudflare | Proxying and DNS-only; flattening features; their Email Routing rewrites | queued |
| DMARC for Shopify | Sends via their own infrastructure; the customer-notification domain trap | queued |
| Mailchimp / Klaviyo authenticated domains | Alignment when the ESP owns the return-path | queued |
| Zoho / Fastmail | Smaller volume, high intent | backlog |

## Type 3 — Comparison pages

**Queued behind the other two deliberately.** Three reasons, and they should be weighed
before writing any of them:

1. **Every factual claim about a competitor is a liability.** Pricing and feature claims
   go stale within months, and a wrong one on a site whose pitch is accuracy costs more
   credibility than the page earns.
2. **Self-authored "X vs Y" pages convert badly and rank badly** unless they are
   genuinely even-handed, which means conceding where the competitor is better — and
   they are: dmarcian and EasyDMARC do ongoing report aggregation, which this tool does
   not do at all.
3. The honest version is a **capability table, not a versus page**: what each tool does,
   updated with a visible date, conceding the gaps.

If written, the non-negotiables are: state the check date on the page; link the
competitor's own pricing/docs page for every claim; never characterise a competitor as
bad, only as *different*; re-verify on a schedule or unpublish. The differentiator to
lead with is the one that is verifiably true and unusual — the `rua=` external
destination check, which almost nothing else tests.

| Page | Status |
|---|---|
| Capability table: notspoofed / MXToolbox / dmarcian / EasyDMARC | backlog — read the caveats above first |

## The cycle

Weekly, one page:

1. **Pick** the top queued item. Error pages before provider pages before comparisons.
2. **Verify first, write second.** Fetch the RFC or the provider doc *before* drafting.
   Where they disagree, that disagreement is the page's angle.
3. **Draft** into `src/content/guides/<slug>.md` with real frontmatter, `order` slotted
   against the existing ranking, and 3–4 FAQ entries that are not duplicates of another
   page's.
4. **Link both ways** — out to the guides that own each detail, and add the entry to
   `src/lib/guide-links.ts` if a finding should point at it. `test/guide-links.test.ts`
   fails if the slug or title drifts.
5. **Check** — `npm run check`, `npm test`, build, and resolve every internal link.
6. **Ship** and note it here. The sitemap, `llms.txt` and the homepage list all update
   themselves from the collection; no manual step.

Nothing in this cycle publishes without a human deciding it is true. That is the point.
