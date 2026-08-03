import { isDatacenterIp } from './origin-asn.js';
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
 *   checks            a domain was checked by an apparent human, or via the JSON API
 *   checks:bot        … by a crawler on the web route. Counted, never conflated
 *   api               … of which came via the JSON API
 *   view:<path>       a page was rendered
 *   bot:<name>        a crawler hit, by name. `datacenter` is the ASN filter, not a
 *                     self-identified crawler — see below
 *   ref:<host>        an external referrer, host only — never the full URL
 *   src:<source>      campaign attribution from ?utm_source=, plus a `direct` bucket
 *   conv:guide        a check whose referrer was one of our own guides
 *
 * Automation is identified two ways, and they are counted separately on purpose. The
 * user-agent list catches whatever admits to being a robot. The origin-AS check catches
 * what does not: the traffic that made the first weeks of numbers meaningless presented
 * ordinary Chrome and Safari strings from rented servers. Keeping `bot:datacenter`
 * distinct means the newer, more fallible filter can be audited rather than trusted.
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

/**
 * User-agents describing a browser that cannot be making this request.
 *
 * Scanners rotate through a canned list of strings harvested years ago, and the list has
 * not aged. Windows Vista and Windows NT 6.1 are long past their last Chrome release,
 * Trident/MSIE is retired, and PhantomJS and HeadlessChrome say what they are. None of
 * these can be a person browsing today.
 *
 * Version-independent patterns only. "Chrome below N" would need maintaining forever and
 * would eventually libel somebody's genuinely old machine.
 */
const IMPOSSIBLE_AGENTS: readonly RegExp[] = [
  /Windows NT (5\.[01]|6\.0)\).*Chrome\//i, // Chrome on XP / Vista
  /Windows NT 6\.1\).*Chrome\/(1[0-9]{2}|[89][0-9])\./i, // modern Chrome on Windows 7
  /Trident\/|MSIE \d/i, // Internet Explorer
  /HeadlessChrome|PhantomJS|Electron\//i, // announced automation
];

export function botName(userAgent: string | null): string | null {
  if (!userAgent) return 'no-user-agent';
  for (const [pattern, name] of BOTS) if (pattern.test(userAgent)) return name;
  for (const pattern of IMPOSSIBLE_AGENTS) if (pattern.test(userAgent)) return 'impossible-agent';
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
  /**
   * Required, not optional — a missing user-agent scores as the `no-user-agent`
   * crawler, so a call site that simply forgot to pass it silently files every event
   * under bot traffic. That is exactly what happened when `checks` gained a bot split:
   * both check routes omitted it and every web check became a crawler check. Making it
   * mandatory turns that into a compile error.
   */
  userAgent: string | null;
  /**
   * Required for the same reason as `userAgent`: the datacenter check is worthless if a
   * call site can quietly not participate in it, and silently-not-filtering is the exact
   * failure mode that made these numbers wrong the first time.
   */
  clientIp: string | null;
  /** `utm_source` from the query string, if present. */
  utmSource?: string | null;
  /** True for /check and /api/check. */
  isCheck?: boolean;
  viaApi?: boolean;
}

/** Resolved by `track` before counting. Separate from TrackInput so `trackFields` stays
 *  pure and synchronous — it is the part worth testing exhaustively. */
export interface TrackContext {
  /** Origin AS is a known hosting network. False when unknown. */
  fromDatacenter?: boolean;
}

/**
 * Which counters a request increments. Pure and exported so the bot/human split can be
 * tested without a Redis — the split decides what every headline number means, and it
 * was wrong once already.
 */
export function trackFields(
  { path, referrer, selfHost, userAgent, utmSource, isCheck, viaApi }: TrackInput,
  { fromDatacenter = false }: TrackContext = {},
): string[] {
  const fields: string[] = [];
  // A rented machine presenting a browser string is the case user-agent matching cannot
  // reach, and it was most of the traffic. Named rather than merged into `other-bot` so
  // the two filters can be told apart in the readout — including if this one is wrong.
  const bot = botName(userAgent ?? null) ?? (fromDatacenter ? 'datacenter' : null);

  if (isCheck) {
    // A script calling the JSON API *is* a real user, so a bot user-agent there is
    // expected and still counts as a check.
    //
    // The web route is different, and used not to be treated differently. The form on
    // the landing page is a GET, so anything that submits forms produces a valid
    // `/check?domain=…` — and every crawler that did was counted as a check. That
    // silently inflated the single number the whole funnel is judged on, which is the
    // worst possible metric to have wrong. Crawler checks are now counted separately
    // rather than discarded: the volume is worth seeing, just not worth believing.
    if (viaApi) fields.push('checks', 'api');
    else if (bot) fields.push('checks:bot');
    else fields.push('checks');

    // The funnel metric the whole content strategy rests on: did a guide reader
    // actually go on to run a check? A crawler walking our own links is not that.
    if (!bot && isOwnGuide(referrer, selfHost)) fields.push('conv:guide');
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

  return fields;
}

/**
 * Fire-and-forget. Never awaited by a request handler — a slow metrics write must not
 * add latency to a page, and a failed one must not surface as an error to the user.
 *
 * The ASN lookup happens inside that detached promise for the same reason: it is a DNS
 * query, cached per /24 for a week, and the page must not wait for it.
 */
export function track(input: TrackInput, context?: TrackContext): void {
  void (async () => {
    const ctx = context
      ?? { fromDatacenter: await isDatacenterIp(input.clientIp).catch(() => false) };
    await bump(trackFields(input, ctx));
  })();
}

/** Exported so a caller that needs the same verdict for something else — the middleware
 *  gates its Umami send on it — can resolve it once and hand it to `track`. */
export async function trafficContext(clientIp: string | null): Promise<TrackContext> {
  return { fromDatacenter: await isDatacenterIp(clientIp).catch(() => false) };
}

export interface DayStats {
  date: string;
  /** Checks from apparent humans, plus JSON API calls. */
  checks: number;
  /** Checks from crawlers on the web route. Kept out of `checks` so the headline
   *  number means what it says. */
  checksBot: number;
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
      checksBot: Number(hash['checks:bot'] ?? 0),
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
