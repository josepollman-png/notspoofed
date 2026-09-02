import type { APIRoute } from 'astro';
import report from '../../data/data-quality-report-2026-09.txt?raw';

/**
 * The audit trail the study's methodology promises: every row excluded, repaired,
 * re-resolved or hand-corrected, itemised by domain. Always the current run; each run's
 * report is also served under a dated name so an older citation keeps its own trail.
 *
 * Served inline rather than as an attachment — it is short, and reviewers checking whether
 * the corrections are honest should be able to read it without a download step.
 */
export const GET: APIRoute = () =>
  new Response(report, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
    },
  });
