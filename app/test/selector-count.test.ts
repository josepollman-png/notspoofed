import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { COMMON_SELECTORS } from '../src/lib/dkim/selectors.js';

/**
 * How many selectors the checker guesses is stated in five places. Three interpolate
 * it — `about.astro` and `DomainForm.astro` read `COMMON_SELECTORS.length`, and the
 * "no DKIM found" finding reads `triedCount` off the result, which is the only one of
 * the five that can report a per-run figure.
 *
 * The two guides are `.md`, and Astro does not evaluate expressions in Markdown — that
 * needs MDX, which this project does not use. So they carry the number as literal text,
 * and this is what notices when the list grows and the prose does not.
 *
 * It matters more here than the usual stale-number case: /guides/dkim-selector-list/
 * exists to tell readers precisely how much confidence to place in a guess, so a
 * checker that overstates its own coverage undercuts the one thing that page sells.
 */

const GUIDES_DIR = join(import.meta.dirname, '../src/content/guides');
const read = (slug: string) => readFileSync(join(GUIDES_DIR, `${slug}.md`), 'utf8');

describe('the stated selector count matches the list', () => {
  const count = COMMON_SELECTORS.length;

  it('has a list worth counting', () => {
    // Guards the assertions below against a list that failed to import.
    expect(count).toBeGreaterThan(20);
  });

  it('carries no duplicate selector names', () => {
    // A duplicate would inflate the stated count without trying anything new.
    const names = COMMON_SELECTORS.map((s) => s.selector);
    expect(new Set(names).size).toBe(names.length);
  });

  for (const slug of ['dkim-selectors', 'dkim-selector-list']) {
    it(`${slug} states ${count}`, () => {
      const source = read(slug);
      const stated = [...source.matchAll(/tries (?:the )?(\d+)/g)].map((m) => Number(m[1]));

      expect(stated.length, `${slug}.md states no selector count`).toBeGreaterThan(0);
      for (const n of stated) expect(n).toBe(count);
    });

    it(`${slug} does not round the number into vagueness`, () => {
      // "around a hundred" was the actual regression: a miscount got written as an
      // approximation, which reads as deliberate hedging rather than as an error.
      expect(read(slug)).not.toMatch(/(around|about|roughly|nearly)\s+(a\s+)?\w+\s+selectors/i);
    });
  }

  it('says the count can grow, because a user-supplied selector is also tried', () => {
    // checkDkim prepends the user's selectors to the guess list, so triedCount exceeds
    // COMMON_SELECTORS.length whenever one is supplied that is not already in it.
    // Stating a bare 50 would be wrong in exactly the case someone is troubleshooting.
    for (const slug of ['dkim-selectors', 'dkim-selector-list']) {
      expect(read(slug), `${slug}.md`).toMatch(/plus any you (enter|supply)/i);
    }
  });
});
