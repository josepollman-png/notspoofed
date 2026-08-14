import type { APIRoute } from 'astro';
import report from '../../data/data-quality-report.txt?raw';

/**
 * The audit trail the study's methodology promises: every row excluded, repaired or
 * re-resolved, itemised by domain.
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
