#!/usr/bin/env node
/**
 * Prove every old guide URL still lands where it should.
 *
 *   node scripts/check-redirects.mjs                      # against production
 *   node scripts/check-redirects.mjs http://127.0.0.1:3000
 *
 * Guides moved from `/guides/<slug>/` to `/guide/<slug>` on 2026-09-08. Google still has
 * the old URLs in its index and re-crawls them to learn where they went, so each one has
 * to answer exactly one 301 straight to its new home — not a 302, not a chain, not a
 * redirect into a 404.
 *
 * The slug list is read from git, not from the current content folder. The content
 * folder only knows the guides that exist today; git knows every guide that was ever
 * published, which is the set Google has seen. A guide deleted from the folder would
 * silently drop out of a check built on the folder — exactly the URL that most needs
 * checking. Guides added since the last commit come from the folder, so both are covered.
 *
 * Exit code is non-zero on any failure, so this can gate a deploy.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE = (process.argv[2] ?? 'https://notspoofed.com').replace(/\/$/, '');
const APP = join(dirname(fileURLToPath(import.meta.url)), '..');

function slugsFromGit() {
  try {
    const out = execFileSync(
      'git',
      ['log', '--all', '--name-only', '--format=', '--', 'src/content/guides/'],
      { cwd: APP, encoding: 'utf8' },
    );
    return out
      .split('\n')
      .map((line) => /content\/guides\/([^/]+)\.md$/.exec(line)?.[1])
      .filter(Boolean);
  } catch {
    // No git (a deploy copy, say). The folder still covers every current guide.
    return [];
  }
}

const slugsFromFolder = () =>
  readdirSync(join(APP, 'src/content/guides'))
    .filter((f) => f.endsWith('.md'))
    .map((f) => f.slice(0, -3));

const slugs = [...new Set([...slugsFromGit(), ...slugsFromFolder()])].sort();

const failures = [];
const fail = (msg) => failures.push(msg);

async function hop(path) {
  const res = await fetch(`${BASE}${path}`, {
    redirect: 'manual',
    headers: { 'User-Agent': 'notspoofed-redirect-check' },
  });
  const location = res.headers.get('location');
  return {
    status: res.status,
    // Normalise to a path so the check does not care whether Location is absolute.
    location: location ? new URL(location, `${BASE}/`).pathname + new URL(location, `${BASE}/`).search : null,
  };
}

/** Exactly one 301 to `target`, and `target` itself answers 200. */
async function expectSingle301(from, target) {
  const first = await hop(from);
  if (first.status !== 301) {
    fail(`${from}: expected 301, got ${first.status}${first.location ? ` -> ${first.location}` : ''}`);
    return;
  }
  if (first.location !== target) {
    fail(`${from}: 301 goes to ${first.location}, expected ${target}`);
    return;
  }
  const second = await hop(target);
  if (second.status !== 200) {
    fail(`${from}: target ${target} answered ${second.status} — a chain or a dead end, not one hop`);
    return;
  }
  console.log(`  ok  ${from.padEnd(52)} 301 -> ${target}`);
}

console.log(`Checking ${slugs.length} guide slugs (from git history and the content folder) on ${BASE}\n`);

for (const slug of slugs) {
  await expectSingle301(`/guides/${slug}`, `/guide/${slug}`);
  await expectSingle301(`/guides/${slug}/`, `/guide/${slug}`);
  await expectSingle301(`/guides/${slug}.md`, `/guide/${slug}.md`);
}

// The hub keeps its URL, and its trailing-slash twin folds into it.
const hub = await hop('/guides');
if (hub.status !== 200) fail(`/guides: expected 200, got ${hub.status}`);
else console.log(`  ok  ${'/guides'.padEnd(52)} 200`);
await expectSingle301('/guides/', '/guides');

// An invented slug must 404 where it stands, not 301 into a 404 somewhere else.
const bogus = await hop('/guides/this-guide-never-existed');
if (bogus.status !== 404) fail(`/guides/this-guide-never-existed: expected 404, got ${bogus.status}`);
else console.log(`  ok  ${'/guides/this-guide-never-existed'.padEnd(52)} 404`);

if (failures.length) {
  console.error(`\n${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`\nAll ${slugs.length * 3 + 3} checks passed.`);
