import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { FINDING_IDS, type FindingId } from '../src/lib/findings.js';
import { FINDING_GUIDES, guideFor } from '../src/lib/guide-links.js';

/**
 * `guide-links.ts` duplicates guide slugs and titles as plain data so the browser side
 * of `/headers` can use the same mapping the server-rendered cards use. That duplication
 * is only safe if something notices when it drifts.
 */

const GUIDES_DIR = join(import.meta.dirname, '../src/content/guides');

const published = new Map<string, string>(
  readdirSync(GUIDES_DIR)
    .filter((f) => f.endsWith('.md'))
    .map((file) => {
      const source = readFileSync(join(GUIDES_DIR, file), 'utf8');
      const title = /^title:\s*"(.+)"\s*$/m.exec(source)?.[1];
      if (!title) throw new Error(`${file} has no quoted title in its frontmatter`);
      return [file.replace(/\.md$/, ''), title];
    }),
);

describe('finding → guide mapping', () => {
  it('reads at least the guides we know are published', () => {
    // Guards the fixture itself: a broken regex would make every assertion below vacuous.
    expect(published.size).toBeGreaterThanOrEqual(8);
  });

  it('points every mapped finding at a guide that exists', () => {
    for (const [id, guide] of Object.entries(FINDING_GUIDES)) {
      expect(published.has(guide.slug), `${id} → /guides/${guide.slug}/ does not exist`).toBe(true);
    }
  });

  it('uses the guide’s real title as the link text', () => {
    // The link reads "Read: <title>". A renamed guide would otherwise keep advertising
    // the old headline indefinitely.
    for (const [id, guide] of Object.entries(FINDING_GUIDES)) {
      expect(guide.title, `link text for ${id}`).toBe(published.get(guide.slug));
    }
  });

  it('only maps finding ids that the checker can actually emit', () => {
    const known = new Set<string>(FINDING_IDS);
    for (const id of Object.keys(FINDING_GUIDES)) expect(known.has(id)).toBe(true);
  });

  it('leaves findings with no relevant guide unlinked', () => {
    // Explicitly asserted rather than left implicit: inventing a loose association here
    // is how a "related reading" link becomes noise nobody clicks.
    for (const id of ['mtasts-missing', 'tlsrpt-missing', 'bimi-no-vmc', 'dnssec-missing', 'dkim-weak-key'] as const) {
      expect(guideFor(id)).toBeUndefined();
    }
  });

  it('does not break when a finding id has no entry', () => {
    expect(guideFor('spf-syntax' as FindingId)).toBeUndefined();
  });
});
