import type { APIRoute } from 'astro';
// `?raw` inlines the file into the server bundle at build time. The alternative — dropping
// it in public/ — cannot set Content-Disposition, and this file is a citable research
// artefact that should arrive as a download rather than 6,122 rows rendered in a tab.
import csv from '../../data/yc-dmarc-2026-08.csv?raw';

/**
 * The dataset behind /research/yc-email-spoofing-study, released under CC BY 4.0.
 *
 * This is the corrected file, not the raw scan. The scan's own output over-reports the
 * headline figure by roughly a point, because a DNS timeout and a genuine absence of a
 * DMARC record are indistinguishable unless you insist on an authoritative answer — so
 * the uncorrected file must never be what a citation resolves to.
 */
export const GET: APIRoute = () =>
  new Response(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="yc-dmarc-2026-08.csv"',
      // Immutable in practice: the figures on the study page reconcile against this exact
      // file, so a correction would be published under a new date-stamped name.
      'Cache-Control': 'public, max-age=86400',
    },
  });
