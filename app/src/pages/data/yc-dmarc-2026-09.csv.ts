import type { APIRoute } from 'astro';
import csv from '../../data/yc-dmarc-2026-09.csv?raw';

/**
 * The September 3, 2026 run of the dataset behind /research/yc-email-spoofing-study,
 * released under CC BY 4.0. The study page's figures reconcile against this file; the
 * August run stays published under its own name so existing citations keep resolving.
 *
 * Like the August file this is the corrected output, not the raw scan — see the note on
 * yc-dmarc-2026-08.csv.ts for why the uncorrected file must never be what a citation
 * resolves to. This run adds one hand correction against an authoritative nameserver,
 * itemised in the accompanying data-quality report.
 */
export const GET: APIRoute = () =>
  new Response(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="yc-dmarc-2026-09.csv"',
      'Cache-Control': 'public, max-age=86400',
    },
  });
