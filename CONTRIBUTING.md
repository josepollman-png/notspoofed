# Contributing

This is maintained by one person, so the honest expectations first: bug reports get
answered, small focused PRs get reviewed, and large unsolicited rewrites probably don't.
Open an issue before building anything substantial.

## The most valuable contribution is a wrong answer

If the tool reports something incorrect about a real domain, that is worth more than a
patch. Open an issue with:

- the domain
- what the tool said
- what the correct answer is, and how you know (an RFC section, a `dig` output, or a
  second checker that disagrees)

Every load-bearing behaviour in this codebase was found exactly that way. There is a
list of them in [README.md](README.md#things-that-are-load-bearing) — each one was a
plausible-looking simplification that silently produced confident nonsense.

Also genuinely useful, and easy:

- **DKIM selectors** for providers we miss — add to `app/src/lib/dkim/selectors.ts`. Say
  which provider uses it. Selectors are not enumerable, so this list only grows by people
  reporting what they actually see.
- **Blocklist status changes** — `app/src/lib/ip/blocklists.ts`. Lists get retired and
  keep answering nothing (`dnsbl.sorbs.net` went in 2024 and is still shipped by half the
  checkers on the internet). If a list is dead, that's a bug.

## Before you open a PR

```sh
cd app
nvm use                # Node 22.12+, Astro 7 requires it
npm install
npm test               # must pass
npm run check          # astro check — must stay at 0 errors
```

`npm run test:live` hits real DNS and is not required for a PR, but if you changed
anything in `src/lib/`, run it. `test/golden.live.test.ts` pins real-world behaviours;
a failure there is a real signal, not flake.

New checks need a test using `test/fake-dns.ts` rather than live DNS, so the suite stays
offline and deterministic.

## Rules that will get a PR sent back

**Every finding must end in a fix.** A `critical` finding without an actionable `fix` is
a complaint, and the live suite asserts against it. This is the whole reason the project
exists.

**Never report an unknown as a pass.** Unguessable DKIM selectors, unevaluable SPF
macros and refused blocklist queries are reported as *unknown*, never as clean. A false
all-clear on a tool people reach for mid-incident is the worst thing this can do.

**`src/lib/headers/` must never import a Node API.** It runs in the browser so that
message headers — which contain recipient addresses and internal hostnames — are never
uploaded. Its results DOM is built with `textContent`, never `innerHTML`.

**`src/lib/dns/resolver.ts` is the only route to DNS.** It handles TXT-chunk joining and
the query accounting that the lookup counts depend on. Don't call `node:dns` directly
from a checker.

**Don't record what users check.** No domains, no IPs, no sessions. `src/lib/stats.ts`
keeps aggregate counters only, on an allow-list of paths. The site promises this.

**`findings[].id` is a public API contract.** Adding one is fine. Renaming or removing
one means bumping `API_VERSION` in `src/pages/api/check.ts`.

## Out of scope

Not because they're bad ideas — because they change what this is:

- Accounts, databases, stored results
- Client-side analytics or any third-party script
- Bulk / batch checking (it would make the DNS abuse surface much harder to bound)
- SMTP probing of any kind

## Commit messages

Explain *why*, not *what* — the diff already says what. The comments in this codebase are
unusually dense for the same reason: nearly every non-obvious line is guarding against a
specific failure that already happened once.
