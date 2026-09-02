import type { APIRoute } from 'astro';
import csv from '../../data/yc-dmarc-changes-2026-08-to-2026-09.csv?raw';

/**
 * Every domain whose verdict differed between the August 14 and September 3, 2026 runs:
 * old and new policy, old and new verdict. Derived from the two published CSVs, restricted
 * to domains conclusively classified in both, so it can be reproduced from them.
 */
export const GET: APIRoute = () =>
  new Response(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="yc-dmarc-changes-2026-08-to-2026-09.csv"',
      'Cache-Control': 'public, max-age=86400',
    },
  });
