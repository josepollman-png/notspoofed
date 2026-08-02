import { markRedisDead, redis } from './redis.js';

/**
 * Aggregate, server-side counters. No JavaScript, no cookies, no third party.
 *
 * The deliberate constraint: **nothing here identifies a person or a domain.** We count
 * events, not subjects. Specifically we never record the domain someone checked, their
 * IP, or anything that could reconstruct a session — because the site promises we don't
 * keep what you check, and a metrics feature is not worth making that a lie.
 *
 * One Redis hash per UTC day, expired after 90 days. Fields:
 *
 *   checks            a domain was checked (web or API)
 *   api               … of which came via the JSON API
 *   view:<path>       a page was rendered
 *   ref:<host>        an external referrer, host only — never the full URL
 *   conv:guide        a check whose referrer was one of our own guides
 */

const TTL_DAYS = 90;
const KEY_PREFIX = 'mailcheck:stat';

/** Paths we're willing to key on. Anything else is bucketed, so a crawler hitting
 *  random URLs cannot inflate the hash into an unbounded memory leak. */
function safePath(path: string): string {
  const clean = path.split('?')[0]?.replace(/\/+$/, '') || '/';
  if (['/', '/guides', '/api', '/check', '/headers', '/ip', '/about'].includes(clean)) return clean;
  if (/^\/guides\/[a-z0-9-]{1,60}$/.test(clean)) return clean;
  return '/other';
}

/** `www.example.com` and `example.com` are the same site. Without this, every visitor
 *  arriving via the www redirect was logged as an external referral. */
const bare = (host: string): string => host.toLowerCase().replace(/^www\./, '');

/** Referrer host only. Full URLs can carry query strings with personal data in them. */
function referrerHost(referrer: string | null, selfHost: string): string | null {
  if (!referrer) return null;
  try {
    const host = new URL(referrer).hostname;
    if (host === '' || bare(host) === bare(selfHost)) return null;
    return host.length > 80 ? null : host.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Campaign sources we're willing to key on.
 *
 * Referrer-based attribution alone is blind to most promotion channels: Reddit puts
 * `rel="noopener noreferrer"` on outbound links, mobile apps usually send nothing, and
 * a strict `Referrer-Policy` strips it too. A campaign can be working perfectly while
 * `ref:` stays empty, which is indistinguishable from it not working at all.
 *
 * `?utm_source=` survives all of that, so it is the authoritative signal. Values are
 * allow-listed rather than free-text — an open bucket lets anyone append arbitrary
 * fields to the day's hash by crafting a URL.
 */
const KNOWN_SOURCES = new Set([
  'reddit', 'hn', 'hackernews', 'lobsters', 'indiehackers', 'producthunt',
  'twitter', 'x', 'mastodon', 'bluesky', 'linkedin', 'facebook',
  'discord', 'slack', 'mailop', 'newsletter', 'email',
  'github', 'devto', 'medium', 'youtube', 'directory', 'roundup',
]);

export function campaignSource(utm: string | null): string | null {
  if (!utm) return null;
  const clean = utm.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{0,23}$/.test(clean)) return null;
  // Unrecognised but well-formed values still count — just bucketed, so a typo in a
  // posted link shows up as traffic rather than vanishing.
  return KNOWN_SOURCES.has(clean) ? clean : 'other';
}

function isOwnGuide(referrer: string | null, selfHost: string): boolean {
  if (!referrer) return false;
  try {
    const url = new URL(referrer);
    return bare(url.hostname) === bare(selfHost) && url.pathname.startsWith('/guides/');
  } catch {
    return false;
  }
}

/**
 * Crawlers, counted separately rather than discarded.
 *
 * Mixed into `view:` they drown out the handful of real readers a new site gets —
 * but they are not noise either: seeing Googlebot arrive is the first sign indexing
 * has started, and a Slack or Twitter fetch means someone shared a link.
 */
const BOTS: ReadonlyArray<[RegExp, string]> = [
  [/googlebot|google-inspectiontool/i, 'googlebot'],
  [/bingbot|adidxbot/i, 'bingbot'],
  [/yandexbot/i, 'yandexbot'],
  [/duckduckbot/i, 'duckduckbot'],
  [/applebot/i, 'applebot'],
  [/baiduspider/i, 'baiduspider'],
  [/slackbot|slack-imgproxy/i, 'slack'],
  [/twitterbot/i, 'twitter'],
  [/facebookexternalhit|facebookcatalog/i, 'facebook'],
  [/linkedinbot/i, 'linkedin'],
  [/discordbot/i, 'discord'],
  [/telegrambot/i, 'telegram'],
  [/whatsapp/i, 'whatsapp'],
  [/gptbot|oai-searchbot|chatgpt-user/i, 'openai'],
  [/claudebot|anthropic-ai|claude-web/i, 'anthropic'],
  [/perplexitybot/i, 'perplexity'],
  [/ahrefsbot|semrushbot|mj12bot|dotbot|petalbot|dataforseo/i, 'seo-crawler'],
  [/bytespider/i, 'bytespider'],
  [/uptimerobot|pingdom|statuscake|betteruptime/i, 'uptime-monitor'],
  // Deliberately last: catches everything self-identifying that we have not named.
  [/bot\b|crawler|spider|scrapy|curl\/|wget\/|python-requests|go-http-client/i, 'other-bot'],
];

export function botName(userAgent: string | null): string | null {
  if (!userAgent) return 'no-user-agent';
  for (const [pattern, name] of BOTS) if (pattern.test(userAgent)) return name;
  return null;
}

function todayKey(): string {
  return `${KEY_PREFIX}:${new Date().toISOString().slice(0, 10)}`;
}

async function bump(fields: string[]): Promise<void> {
  const r = redis();
  if (!r || fields.length === 0) return;

  try {
    const key = todayKey();
    const pipeline = r.multi();
    for (const f of fields) pipeline.hincrby(key, f, 1);
    pipeline.expire(key, TTL_DAYS * 86400);
    await pipeline.exec();
  } catch {
    markRedisDead();
  }
}

export interface TrackInput {
  path: string;
  referrer: string | null;
  selfHost: string;
  userAgent?: string | null;
  /** `utm_source` from the query string, if present. */
  utmSource?: string | null;
  /** True for /check and /api/check. */
  isCheck?: boolean;
  viaApi?: boolean;
}

/**
 * Fire-and-forget. Never awaited by a request handler — a slow metrics write must not
 * add latency to a page, and a failed one must not surface as an error to the user.
 */
export function track(
  { path, referrer, selfHost, userAgent, utmSource, isCheck, viaApi }: TrackInput,
): void {
  const fields: string[] = [];
  const bot = botName(userAgent ?? null);

  if (isCheck) {
    // API traffic is expected to be automated, so a bot user-agent there is normal
    // and still a real check. Only page views get the bot/human split.
    fields.push('checks');
    if (viaApi) fields.push('api');
    // The funnel metric the whole content strategy rests on: did a guide reader
    // actually go on to run a check?
    if (isOwnGuide(referrer, selfHost)) fields.push('conv:guide');
  } else if (bot) {
    fields.push(`bot:${bot}`);
  } else {
    fields.push(`view:${safePath(path)}`);
  }

  // Referrers only from apparent humans — crawlers rarely send one, and when they
  // do it is usually spoofed.
  if (!bot) {
    const host = referrerHost(referrer, selfHost);
    if (host) fields.push(`ref:${host}`);

    // Exactly one source bucket per human hit, so the columns sum to something
    // meaningful. `direct` is the important one: previously, traffic arriving with no
    // referrer recorded nothing at all, so an unattributable visit and a nonexistent
    // visit looked identical.
    const src = campaignSource(utmSource ?? null);
    if (src) fields.push(`src:${src}`);
    else if (!host) fields.push('src:direct');
  }

  void bump(fields);
}

export interface DayStats {
  date: string;
  checks: number;
  api: number;
  guideConversions: number;
  /** Page views from apparent humans only. */
  views: Record<string, number>;
  referrers: Record<string, number>;
  /** Crawler hits, by name. Kept separate so they cannot drown out real readers. */
  bots: Record<string, number>;
  /** Campaign attribution from `?utm_source=`, plus a `direct` bucket. */
  sources: Record<string, number>;
}

export async function readStats(days = 30): Promise<DayStats[]> {
  const r = redis();
  if (!r) return [];

  const out: DayStats[] = [];
  const now = Date.now();

  for (let i = 0; i < days; i++) {
    const date = new Date(now - i * 86400_000).toISOString().slice(0, 10);
    let hash: Record<string, string> = {};
    try {
      hash = await r.hgetall(`${KEY_PREFIX}:${date}`);
    } catch {
      markRedisDead();
      break;
    }
    if (Object.keys(hash).length === 0) continue;

    const day: DayStats = {
      date,
      checks: Number(hash['checks'] ?? 0),
      api: Number(hash['api'] ?? 0),
      guideConversions: Number(hash['conv:guide'] ?? 0),
      views: {},
      referrers: {},
      bots: {},
      sources: {},
    };
    for (const [field, value] of Object.entries(hash)) {
      if (field.startsWith('view:')) day.views[field.slice(5)] = Number(value);
      else if (field.startsWith('ref:')) day.referrers[field.slice(4)] = Number(value);
      else if (field.startsWith('bot:')) day.bots[field.slice(4)] = Number(value);
      else if (field.startsWith('src:')) day.sources[field.slice(4)] = Number(value);
    }
    out.push(day);
  }

  return out;
}
