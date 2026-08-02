import type { APIRoute } from 'astro';
import { readStats } from '../lib/stats.js';

/**
 * Private stats readout.
 *
 * Guarded by a shared secret from the environment rather than a login, because the site
 * has no accounts and adding an auth system to read four counters would be absurd. If
 * STATS_TOKEN is unset the route does not exist at all — failing closed, so a
 * misconfigured deploy cannot accidentally publish traffic figures.
 *
 * Returns 404 rather than 401 on a bad token: there is no reason to confirm the
 * endpoint exists to someone who cannot use it.
 */
export const GET: APIRoute = async ({ url, request }) => {
  const expected = process.env.STATS_TOKEN;
  const provided =
    url.searchParams.get('token') ??
    request.headers.get('authorization')?.replace(/^Bearer\s+/i, '') ??
    '';

  const notFound = () => new Response('Not found', { status: 404 });

  if (!expected || expected.length < 16) return notFound();
  // Length check first so the comparison below is over equal-length strings.
  if (provided.length !== expected.length) return notFound();

  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= expected.charCodeAt(i) ^ provided.charCodeAt(i);
  }
  if (mismatch !== 0) return notFound();

  const days = Math.min(365, Math.max(1, Number(url.searchParams.get('days') ?? 30) || 30));
  const stats = await readStats(days);

  const totals = stats.reduce(
    (acc, d) => {
      acc.checks += d.checks;
      acc.checksBot += d.checksBot;
      acc.api += d.api;
      acc.guideConversions += d.guideConversions;
      for (const [k, v] of Object.entries(d.views)) acc.views[k] = (acc.views[k] ?? 0) + v;
      for (const [k, v] of Object.entries(d.referrers)) acc.referrers[k] = (acc.referrers[k] ?? 0) + v;
      for (const [k, v] of Object.entries(d.bots)) acc.bots[k] = (acc.bots[k] ?? 0) + v;
      for (const [k, v] of Object.entries(d.sources)) acc.sources[k] = (acc.sources[k] ?? 0) + v;
      return acc;
    },
    { checks: 0, checksBot: 0, api: 0, guideConversions: 0, views: {}, referrers: {}, bots: {}, sources: {} } as {
      checks: number; checksBot: number; api: number; guideConversions: number;
      views: Record<string, number>; referrers: Record<string, number>;
      bots: Record<string, number>; sources: Record<string, number>;
    },
  );

  const sortDesc = (o: Record<string, number>) =>
    Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]));

  return new Response(
    JSON.stringify(
      {
        windowDays: days,
        totals: {
          ...totals,
          views: sortDesc(totals.views),
          referrers: sortDesc(totals.referrers),
          sources: sortDesc(totals.sources),
          bots: sortDesc(totals.bots),
        },
        daily: stats,
      },
      null,
      2,
    ),
    {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'X-Robots-Tag': 'noindex, nofollow',
        'Cache-Control': 'no-store',
      },
    },
  );
};
