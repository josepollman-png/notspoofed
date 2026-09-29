#!/usr/bin/env node
/**
 * Submit URLs to IndexNow (Bing, Yandex, Naver, Seznam and Yep share one endpoint;
 * Google does not read it).
 *
 *   node scripts/indexnow.mjs                     # every URL in the production sitemap
 *   node scripts/indexnow.mjs /guides/some-page   # only the pages that changed
 *   node scripts/indexnow.mjs --dry-run           # print the payload, send nothing
 *
 * (Projects with a package.json expose this as `npm run indexnow -- …`.)
 *
 * The key is the file whose name is its own content, `<key>.txt`, in the first of
 * public/, static/ or the project root that has exactly one. That file is the single
 * source of truth: nothing in .env has to match it. The site origin comes from
 * INDEXNOW_SITE_URL, read from the environment, then ./.env, then ../.env.
 *
 * Run it AFTER the deploy is live — the script refuses to submit until the key file
 * answers on production, since IndexNow silently drops submissions whose key it
 * cannot fetch. Sitemap indexes are followed one level down.
 *
 * IndexNow's own guidance: submit URLs whose content changed, not the whole site on
 * every deploy. The no-argument form is for the first submission and for changes to a
 * shared template.
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// fileURLToPath, not .pathname: some of these projects live in directories with spaces.
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const ENDPOINT = "https://api.indexnow.org/IndexNow";
const UA = { "User-Agent": "indexnow-submit" };

function loadEnv() {
  for (const p of [resolve(root, ".env"), resolve(root, "..", ".env")]) {
    if (!existsSync(p)) continue;
    for (const raw of readFileSync(p, "utf8").split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq < 0) continue;
      const k = line.slice(0, eq).trim();
      let v = line.slice(eq + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (!(k in process.env)) process.env[k] = v;
    }
  }
}

function findKey() {
  for (const dir of ["public", "static", "."].map((d) => resolve(root, d))) {
    if (!existsSync(dir)) continue;
    const hits = readdirSync(dir)
      .filter((f) => /^[a-f0-9]{8,128}\.txt$/i.test(f))
      .filter((f) => readFileSync(resolve(dir, f), "utf8").trim() === f.slice(0, -4));
    if (hits.length === 1) return hits[0].slice(0, -4);
    if (hits.length > 1) throw new Error(`more than one <key>.txt in ${dir}`);
  }
  throw new Error("no <key>.txt found in public/, static/ or the project root");
}

async function sitemapUrls(url, depth = 0) {
  const xml = await (await fetch(url, { headers: UA })).text();
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1].trim());
  if (!/<sitemapindex/i.test(xml)) return locs;
  if (depth > 0) throw new Error(`nested sitemap index at ${url}`);
  const out = [];
  for (const child of locs) out.push(...(await sitemapUrls(child, depth + 1)));
  return out;
}

async function main() {
  loadEnv();
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const site = (process.env.INDEXNOW_SITE_URL ?? "").replace(/\/$/, "");
  if (!/^https:\/\//.test(site)) throw new Error("INDEXNOW_SITE_URL must be set (https://…) in the environment or .env");
  const host = new URL(site).host;
  const key = findKey();
  const keyLocation = `${site}/${key}.txt`;

  const paths = args.filter((a) => !a.startsWith("--"));
  const urlList = paths.length
    ? paths.map((p) => (/^https?:\/\//.test(p) ? p : `${site}${p.startsWith("/") ? p : `/${p}`}`))
    : await sitemapUrls(`${site}/sitemap.xml`);
  if (!urlList.length) throw new Error("nothing to submit");
  const foreign = urlList.filter((u) => new URL(u).host !== host);
  if (foreign.length) throw new Error(`URLs not on ${host}: ${foreign.join(", ")}`);
  if (urlList.length > 10000) throw new Error("IndexNow accepts at most 10,000 URLs per request");

  const body = { host, key, keyLocation, urlList };
  console.log(`${urlList.length} URL(s) for ${host}, key at ${keyLocation}`);
  if (dryRun) {
    console.log(JSON.stringify(body, null, 2));
    return;
  }

  const live = await fetch(keyLocation, { headers: UA });
  if (!live.ok || (await live.text()).trim() !== key) {
    throw new Error(`${keyLocation} does not serve the key yet — deploy first`);
  }

  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
  // 200 = accepted; 202 = accepted, key validation pending. Anything else is a real failure.
  const ok = res.status === 200 || res.status === 202;
  console.log(`${ok ? "OK" : "FAILED"} ${res.status} ${res.statusText}`);
  if (!ok) {
    console.log(await res.text());
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
