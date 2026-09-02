import type { APIRoute } from 'astro';
import report from '../../data/data-quality-report-2026-08.txt?raw';

/** The audit trail for the August 14, 2026 run, kept at a dated URL now that the undated
 *  one serves the current run. */
export const GET: APIRoute = () =>
  new Response(report, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
    },
  });
