# notspoofed

An SPF / DKIM / DMARC checker that hands you the fixed record instead of describing the
problem.

<sub>The code calls itself `mailcheck` internally — that's the original working name, and
it survives in the container, package and `MAILCHECK_*` environment variable names.</sub>

**Live at [notspoofed.com](https://notspoofed.com)** — no signup, no ads, nothing stored.

Plenty of free checkers will tell you your SPF record exceeds the ten-lookup limit.
Almost none will give you a corrected one. That gap is the entire point of this tool:

```
✗ SPF needs 14 DNS lookups — the limit is 10                          critical

  Receivers stop evaluating at ten lookups and return a permerror, which
  DMARC treats as an SPF failure.

  Fix — replace the TXT record at example.com:

      v=spf1 include:_spf.google.com ip4:198.51.100.0/24
             ip4:203.0.113.7 -all

  ⚠ Flattened records are a snapshot of your provider's IPs and go stale
    when they change them. Only mailgun.org was flattened — the fewest
    includes needed to get under the limit.
```

Every finding terminates in a record you can paste or an unambiguous action. A finding
without a fix is a complaint, and the live test suite asserts that every `critical`
finding has one.

## What it checks

- **SPF** — full recursive evaluation, RFC 7208 lookup accounting, void-lookup and
  loop limits, macro detection, and a flattener that touches the fewest includes it can
- **DKIM** — ~50 known selectors, with the wildcard defences that stop bogus "valid key"
  results, plus key-strength parsing
- **DMARC** — policy grading, organizational-domain inheritance via `sp=`, and
  **external destination verification** (most free checkers skip this, and without it a
  domain looks perfect while its reports go nowhere)
- **MTA-STS** — including fetching the policy file and cross-checking it against live MX
  records, because a policy listing the wrong hosts is worse than no policy
- **TLS-RPT, BIMI, DNSSEC**
- **Sending IP** — 8 blocklists, forward-confirmed reverse DNS, ASN
- **Message headers** — `Authentication-Results` parsing and DMARC alignment analysis,
  entirely in the browser

There is also a **[JSON API](https://notspoofed.com/api)** with no key required.

## Quick start

```sh
git clone https://github.com/josepollman-png/notspoofed.git
cd notspoofed
docker compose up -d --build
```

That's it — <http://localhost:3000>. It brings up the app, a Redis for rate limiting, and
its own recursive resolver (which is not optional; see
[Blocklists need our own resolver](#blocklists-need-our-own-resolver)).

Every setting has a working default, so no `.env` is required. Copy `.env.example` to
`.env` to change the port, set a public URL, or enable the stats endpoint.

If you are slotting this into an existing stack that already has a reverse proxy and a
Redis, use `docker-compose.stack.yml` instead — it joins external networks and shares
them rather than duplicating them.

## Development

Requires **Node 22.12+** (Astro 7). An `.nvmrc` pins it.

```sh
cd app
nvm use
npm install
npm run dev            # http://localhost:4321
```

```sh
npm test               # 178 offline tests, no network
npm run test:live      # 12 live-DNS tests against real domains
npm run check          # astro check / typecheck — must stay at 0 errors
npm run build && npm run preview

npx vitest run test/spf.parse.test.ts   # a single file
npx vitest run -t "redirect"            # tests matching a name
```

`test/fake-dns.ts` implements the resolver's backend interface from a fixture map, so the
whole pipeline is testable offline and deterministically. Prefer it.
`test/golden.live.test.ts` exists to prove we still agree with reality and pins specific
real-world behaviours — treat a failure there as a real signal, not flake.

## Running it publicly

Put a TLS-terminating reverse proxy in front of the container.

**The rate limiter trusts `X-Forwarded-For`.** That is only safe because a correctly
configured proxy *overwrites* the header rather than appending to a client-supplied one.
Caddy and nginx both do the right thing by default; check yours before exposing this.

The trap worth naming: if you also put a CDN in front (Cloudflare's orange cloud, for
instance), your proxy now sees the *CDN's* IP as the peer and the header becomes
attacker-controllable again. Either keep the record DNS-only, or configure your proxy's
trusted-proxy ranges first. A Caddy site block is all it takes:

```
mailcheck.example.com {
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    reverse_proxy mailcheck:3000
}
```

The tool performs outbound DNS on user-supplied input, so it is rate limited per IP,
capped on total queries, and bounded by a wall-clock deadline per request. Removing any
of those turns it into a free DNS scanning proxy.

## Layout

| Path | What it does |
|---|---|
| `src/lib/dns/resolver.ts` | Shared resolver: TXT chunk joining, caching, query budget |
| `src/lib/spf/parse.ts` | Tokenizer — mechanisms, modifiers, qualifiers, dual-CIDR |
| `src/lib/spf/evaluate.ts` | Recursive walk, RFC 7208 term counting, void/loop limits |
| `src/lib/spf/flatten.ts` | Minimum-touch flattening, IPv4 CIDR collapsing, 255-byte chunking |
| `src/lib/dkim/` | Selector guessing with the wildcard defences |
| `src/lib/dmarc/check.ts` | Parsing, org-domain inheritance, external destination verification |
| `src/lib/modern/check.ts` | MTA-STS (incl. policy fetch + MX cross-check), TLS-RPT, BIMI, DNSSEC |
| `src/lib/dns/doh.ts` | DoH, used *only* for DS records — Node's resolver has no DS type |
| `src/lib/remediate.ts` | Findings → copy-paste fixes. The actual product |
| `src/lib/check.ts` | Orchestration and input validation |
| `src/pages/robots.txt.ts` | Disallows `/check` and `/api/check` — see the crawl-trap note below |
| `src/pages/api/check.ts` | Public JSON API. Hand-built response shape, versioned |
| `src/content/guides/` | Explainer content — the pages actually meant to rank |
| `src/lib/headers/` | Header analyzer — parsing and alignment analysis, **browser-side** |
| `src/lib/ip/` | Sending-IP diagnostic — blocklists, FCrDNS, ASN |
| `unbound/` | Our own recursive resolver — required for Spamhaus, see below |

## Things that are load-bearing

These were each found by testing against live DNS, and each one silently breaks the
tool if reverted. They have regression tests; do not "simplify" them away.

- **TXT chunks join with `''`, never a space.** `_hspf.hubspot.com` splits a token across
  the boundary — one string ends `…ip4`, the next begins `:161.38.192.0/20`. Joining on a
  space produces the invalid token `ip4 :161…`.

- **`redirect=` uses `=`, not `:`.** A colon-only tokenizer misses it entirely, and since
  `hubspot.com` is *nothing but* a redirect, it scores as `0 lookups` — a clean bill of
  health for a domain with plenty. Silent undercounting is the worst failure this tool
  has.

- **`all` inherits through `redirect=`.** A record with only a redirect has no `all` of
  its own; the target's applies (RFC 7208 §6.1). Reading the apex alone reports "no
  policy" for domains publishing `-all`.

- **A TXT record existing at `<selector>._domainkey` proves nothing.** Wildcard domains
  answer every name. Two separate defences are needed, because they catch different
  cases:
  - `hubspot.com` returns `v=spf1 ~all` for any selector → caught by requiring a `p=` tag.
  - `example.com` returns `v=DKIM1; p=` for any selector → *structurally valid DKIM*, so
    the `p=` check passes. Caught only by comparing against the wildcard's own answer.

- **Flattening an include saves `1 + subtree`, not `subtree`.** The include term itself
  goes away too. Off by one here leaves the "fixed" record still over the limit.

- **DMARC subdomains inherit.** No `_dmarc` record is not the same as no policy — check
  the organizational domain and apply `sp=`.

- **External destinations need authorisation.** If `rua=` points off-domain, the
  destination must publish `<your-domain>._report._dmarc.<host>`. Without it, conforming
  reporters send nothing, and the domain looks perfectly configured while receiving no
  reports at all.

- **`/check` must never be crawlable.** The query string makes the URL space unbounded,
  and every result page costs ~50 outbound DNS queries. Crawled freely, the rate limiter
  starts 429ing Googlebot, which search engines read as an unhealthy site and answer by
  crawling *less* — actively suppressing the pages meant to rank. `robots.txt` disallows
  it, and the route also sends `X-Robots-Tag: noindex` for crawlers that ignore
  robots.txt. Do not add `@astrojs/sitemap`; it enumerates routes and would list `/check`.

- **An MTA-STS DNS record without a reachable policy file does nothing**, and a policy
  listing the wrong MX hosts is worse than none — in `enforce` mode compliant senders
  *refuse delivery* to a host the policy omits. Hence the live MX cross-check.

- **`v=spf1 -all` with no senders is a valid posture, not a misconfiguration.** Parked and
  web-only domains should look exactly like that. Warning them about absent DKIM is a
  false alarm, and false alarms train people to ignore the tool.

- **`findings[].id` is a public API contract.** The JSON API documents these as the field
  callers should branch on, because titles are prose and get reworded. They are a union
  type (`FindingId` in `findings.ts`) so a rename is a compile error rather than a silent
  break. Adding an id is fine; removing or renaming one means bumping `API_VERSION`.

- **Guides are SSR, not prerendered, on purpose.** Prerendering bakes `canonical` and
  `og:url` at build time, and the image is built without `PUBLIC_SITE_URL` — so every
  guide would advertise itself as living on `localhost:3000`. Markdown rendering per
  request is cheap; wrong canonical tags are not.

- **Guide frontmatter dates use `z.coerce.date()`.** YAML parses an unquoted `2026-07-31`
  into a `Date`, so a `z.string().date()` schema fails unless every author remembers to
  quote it.

## The header analyzer runs in the browser

`src/lib/headers/` must never import a Node API. Headers contain recipient addresses,
subject lines and internal hostnames, so `/headers` parses entirely client-side and
uploads nothing — that is a real privacy property and the page says so.

Consequences worth knowing:

- The results DOM is built with `textContent`, never `innerHTML`. Every value in a
  header is attacker-controlled if someone is analysing a hostile message.
- It pulls in `tldts` (~113 KB gzipped) for the public suffix list, because relaxed
  DMARC alignment needs real org-domain comparison — a "last two labels" shortcut says
  `attacker.co.uk` and `victim.co.uk` align, which is exactly the judgement this tool
  exists to get right. Astro code-splits per page, so **only `/headers` pays that cost**;
  the landing page and guides load no JavaScript at all. Verify that isolation holds if
  the script is ever moved into the shared layout.
- `Received` headers arrive newest-first because each relay prepends its own. They are
  reversed before use; getting that backwards makes every hop delay negative and prints
  the delivery path inside out.

## Blocklists need our own resolver

Spamhaus refuses DNSBL queries arriving via a public resolver. Through `1.1.1.1` it
answers `127.255.255.254` — `"Error: open resolver"` — for every lookup, which silently
removes `zen.spamhaus.org` and `cbl.abuseat.org`, the two most authoritative lists.
Hence the `unbound` container, which recurses from the root servers. **Do not add a
`forward-zone` to it**; forwarding to a public resolver reinstates exactly the problem it
exists to solve.

Two things in `unbound/unbound.conf` are load-bearing:

- **Rebinding protection is deliberately off.** Unbound's `private-address` option
  strips loopback answers, and DNSBLs reply with `127.0.0.x` to mean *listed*. Enabling
  it would filter away every hit and turn every listed IP into a silent clean result.
- **`access-control` refuses everything except the container network.** Running an open
  resolver would be worse than the problem being solved.

The app resolves the container name to an IP at startup (`setServers` takes addresses,
not hostnames) and keeps `1.1.1.1`/`8.8.8.8` configured as fallbacks, so a dead Unbound
degrades blocklist accuracy rather than taking the site down.

Cold cache costs ~2.9 s for a full IP check; warm it is ~3 ms.

**Never report a refused lookup as "not listed".** `127.255.255.x` is the list declining
to answer, and rendering that as clean would be a false all-clear on the one tool people
reach for mid-incident. `dnsbl.sorbs.net` is absent because it was retired in 2024 and
answers nothing — it is still shipped by half the blocklist checkers on the internet.

## Measurement

No Google Analytics, no third-party scripts, no cookies. The page is ~10 KB and makes
zero external requests; adding GA4 would have meant a consent banner (EU operator,
ePrivacy applies to its cookies), 50–100 KB of JavaScript, and asking a security tool's
audience to accept Google tracking.

Instead `src/lib/stats.ts` keeps aggregate counters in Redis:

| Field | Meaning |
|---|---|
| `checks` / `api` | Checks by an apparent human or via the JSON API, and how many were the API |
| `checks:bot` | Checks by a crawler on the web route — counted, never folded into `checks` |
| `conv:guide` | **A check whose referrer was one of our own guides** — the funnel metric the content strategy rests on |
| `view:<path>` | Page views, on an allow-list of known paths |
| `ref:<host>` | External referrer, **host only** |
| `bot:<name>` | Automated hits, by name. `datacenter` and `impossible-agent` are the two filters below |

> **The bot split on `checks` is load-bearing and was wrong for the first three days.**
> The landing-page form is a `GET`, so any crawler that submits forms produces a valid
> `/check?domain=…`, and every one of them was counted as a check — inflating the single
> number the whole funnel is judged on. A user-agent that identifies a crawler now scores
> `checks:bot` instead. The JSON API is deliberately exempt: a script calling it *is* a
> real user, and filtering by user-agent there would zero out its usage figure.

Crawlers are counted separately as `bot:<name>` rather than discarded — Googlebot
arriving is the first sign indexing has started, and a Slack or Twitter fetch means
someone shared a link. Mixed into `view:` they would drown out the handful of real
readers a new site gets.

> **User-agent matching has a ceiling, and it is low.** It only catches automation that
> admits to being automation. In the first week, 167 of 195 sessions were a single page
> with zero elapsed time, one crawler produced 14 "visitors" in two seconds by rotating
> IP and user-agent across the sitemap, and around forty hits a day claimed *our own
> host* as the referrer on their first and only pageview. All of it presented ordinary
> Chrome and Safari strings and none of it was catchable by a string match.
>
> Two further filters run, and both are named separately in the readout so they can be
> audited rather than believed:
>
> - **Origin AS** (`src/lib/origin-asn.ts`, `hosting-asns.ts`). A Team Cymru DNS lookup,
>   cached per /24 for a week, resolved inside the fire-and-forget metrics write so no
>   page waits on it. A visitor from AWS or Hetzner is a rented machine. **Consumer VPNs
>   and transit carriers are deliberately excluded** — a reader using Mullvad is a reader.
>   An unresolvable AS counts as human: unknown is unknown, the same rule the checker
>   itself follows for a refused blocklist query.
> - **Impossible user-agents.** Internet Explorer, Chrome on Vista, current Chrome on
>   Windows 7. Version-independent patterns only, so nobody's genuinely old machine gets
>   libelled by a version cutoff that needs maintaining forever.
>
> The JSON API is exempt from both. A script calling it from a datacenter *is* a real
> user, and this is the second time that exemption has had to be stated explicitly.
>
> These are heuristics about networks, not evidence about people, and the ASN list will
> always be incomplete. They exist so a headline number is not wrong by an order of
> magnitude, which is the only thing these counters are for.

A self-hosted [Umami](https://umami.is) instance receives the same page views for a richer
breakdown, posted **server-side** from the middleware — the page loads no analytics script,
so there is nothing for Umami's own bot filtering to run on and the gate above is the only
one there is.

> **What reaches it is an allow-list, not a filter.** `campaignQuery()` in
> `src/lib/umami.ts` forwards exactly `utm_source`, `utm_medium`, `utm_campaign`,
> `utm_term` and `utm_content`, and nothing else, ever. `/check` carries the looked-up
> domain in its query string; a "strip the sensitive parameters" approach is one
> forgotten parameter away from publishing the one thing the site promises it never
> records. A deny-list can forget. An allow-list cannot.

> **The container healthcheck must not hit a tracked page.** It originally probed `/`
> every 30 seconds, which put **1,116 fake views on the landing page in nine hours** and
> made the metric worthless. It now probes `/healthz`, which returns `text/plain` so the
> middleware skips it even if the path filter changes. Any future probe — uptime monitor,
> load balancer, k8s liveness — needs the same treatment.

**Nothing recorded identifies a person or a domain.** No IPs, no sessions, and never the
domain someone checked — the site promises that, and a metrics feature isn't worth making
it a lie. Paths are allow-listed so a crawler hitting random URLs can't grow the hash
without bound. Writes are fire-and-forget and never awaited, so a Redis stall cannot add
latency to a page.

Read it at `/stats?token=…`, guarded by `STATS_TOKEN` from the environment. Unset or
under 16 characters and the route 404s — it fails closed, so a misconfigured deploy can't
publish traffic figures. A wrong token returns 404 rather than 401, since there's no
reason to confirm the endpoint exists to someone who can't use it.

## Deliberate limitations

Stated here and on the page, because overclaiming is how these tools lose trust.

- **DKIM selectors cannot be enumerated.** We guess around fifty (the list in
  `dkim/selectors.ts` is the source of truth; the UI derives the count from it rather
  than hardcoding a number that goes stale). "None found" is not proof of absence —
  Amazon SES uses random selectors that are unguessable by construction.
- **SPF macros cannot be statically evaluated.** `exists:%{i}…` depends on the connecting
  IP. They are counted toward the limit and reported as unevaluable rather than guessed.
- **Lookup counts are worst-case.** Real evaluation short-circuits on the first match, so
  a sender listed early may never reach term 11. We count the full walk, because the
  sender that breaks is the one in the *last* include.
- **Flattened records go stale.** They are a snapshot of a provider's IPs. This carries a
  caveat everywhere it is offered, and the flattener touches the fewest includes it can.
- **IPv6 ranges are de-duplicated but not collapsed.** Only IPv4 containment is computed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contributions are DKIM selectors
for providers we miss, blocklists that have changed status, and **any domain where the
tool is wrong** — a bug report naming a real domain and the expected answer is worth more
than a patch.

## License

[MIT](LICENSE).
