/**
 * Email header parser — RFC 5322, RFC 5321, RFC 8601, RFC 6376.
 *
 * This module runs **in the browser**. Headers contain recipient addresses, subject
 * lines and internal hostnames, so they are parsed client-side and never transmitted;
 * that is a real privacy property, not a nicety, and it is why nothing in here may
 * import a Node API.
 *
 * The one non-obvious structural rule: `Received` headers are *prepended* by each hop,
 * so the list arrives newest-first. Everything downstream wants oldest-first, which is
 * the order the message actually travelled.
 */

export interface RawHeader {
  name: string;
  /** Lower-cased name, for lookups. */
  key: string;
  value: string;
}

export interface ReceivedHop {
  index: number;
  from?: string;
  by?: string;
  with?: string;
  id?: string;
  for?: string;
  date?: Date;
  /** Seconds spent between the previous hop and this one. */
  delaySeconds?: number;
  raw: string;
}

export interface AuthMethod {
  method: string;
  result: string;
  /** e.g. { 'smtp.mailfrom': 'bounce@example.com', 'header.d': 'example.com' } */
  properties: Record<string, string>;
  comment?: string;
}

export interface AuthResults {
  authservId?: string;
  methods: AuthMethod[];
  raw: string;
}

export interface DkimSignature {
  version?: string;
  algorithm?: string;
  domain?: string;
  selector?: string;
  canonicalization?: string;
  signedHeaders: string[];
  /** `i=` — the agent or user identifier, when present. */
  identity?: string;
  raw: string;
}

export interface ParsedHeaders {
  headers: RawHeader[];
  hops: ReceivedHop[];
  auth: AuthResults[];
  dkim: DkimSignature[];
  from?: string;
  fromDomain?: string;
  to?: string;
  subject?: string;
  date?: Date;
  messageId?: string;
  returnPath?: string;
  returnPathDomain?: string;
  replyTo?: string;
  listUnsubscribe?: string;
  /** Total time from the first hop to the last. */
  totalDelaySeconds?: number;
}

// ---------------------------------------------------------------------------
// Field splitting
// ---------------------------------------------------------------------------

/**
 * Unfold and split into fields.
 *
 * RFC 5322 §2.2.3: a field may be wrapped across lines, and continuation lines begin
 * with space or tab. Folding must be undone before anything else is attempted, or a
 * wrapped DKIM-Signature or Received header parses as garbage — and those are exactly
 * the headers that get wrapped, because they are the long ones.
 */
export function splitHeaders(raw: string): RawHeader[] {
  const text = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const out: RawHeader[] = [];
  let current: string | null = null;

  for (const line of text.split('\n')) {
    // A blank line ends the header block; the body is not our business.
    if (line.trim() === '' && current !== null) break;
    if (line.trim() === '') continue;

    if (/^[ \t]/.test(line) && current !== null) {
      current += ' ' + line.trim();
      continue;
    }

    if (current !== null) out.push(toField(current));
    current = line;
  }
  if (current !== null) out.push(toField(current));

  return out.filter((f) => f.name !== '');
}

function toField(line: string): RawHeader {
  const colon = line.indexOf(':');
  if (colon < 0) return { name: '', key: '', value: line.trim() };
  const name = line.slice(0, colon).trim();
  return { name, key: name.toLowerCase(), value: line.slice(colon + 1).trim() };
}

const find = (headers: RawHeader[], key: string): string | undefined =>
  headers.find((h) => h.key === key)?.value;

const findAll = (headers: RawHeader[], key: string): string[] =>
  headers.filter((h) => h.key === key).map((h) => h.value);

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/** Pull the addr-spec out of `Name <user@host>`, `<user@host>` or a bare address. */
export function extractAddress(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const angled = /<([^>]+)>/.exec(value);
  const candidate = (angled ? angled[1] : value).trim();
  const match = /[^\s<>,;"]+@[^\s<>,;"]+/.exec(candidate);
  return match ? match[0] : undefined;
}

export function domainOf(address: string | undefined): string | undefined {
  if (!address) return undefined;
  const at = address.lastIndexOf('@');
  if (at < 0) return undefined;
  const domain = address.slice(at + 1).trim().toLowerCase().replace(/[.>]+$/, '');
  return domain === '' ? undefined : domain;
}

// ---------------------------------------------------------------------------
// Received
// ---------------------------------------------------------------------------

/** Grab a clause like `from foo.example.com (...)` without swallowing the next clause. */
function clause(raw: string, keyword: string): string | undefined {
  const re = new RegExp(`(?:^|\\s)${keyword}\\s+([^\\s;]+)`, 'i');
  const m = re.exec(raw);
  return m?.[1];
}

export function parseReceived(values: string[]): ReceivedHop[] {
  // Each relay prepends its own Received, so the header list is newest-first.
  // Reverse it to get the order the message actually travelled.
  const ordered = [...values].reverse();

  const hops: ReceivedHop[] = ordered.map((raw, index) => {
    // The timestamp is whatever follows the last semicolon.
    const semi = raw.lastIndexOf(';');
    const dateText = semi >= 0 ? raw.slice(semi + 1).trim() : '';
    const parsed = dateText ? new Date(dateText) : null;

    return {
      index: index + 1,
      from: clause(raw, 'from'),
      by: clause(raw, 'by'),
      with: clause(raw, 'with'),
      id: clause(raw, 'id'),
      for: extractAddress(clause(raw, 'for')),
      date: parsed && !Number.isNaN(parsed.getTime()) ? parsed : undefined,
      raw,
    };
  });

  // Delay is measured against the previous hop that actually had a usable timestamp,
  // so one relay with a broken clock does not discard the rest of the timeline.
  let previous: Date | undefined;
  for (const hop of hops) {
    if (hop.date) {
      if (previous) {
        const delta = Math.round((hop.date.getTime() - previous.getTime()) / 1000);
        // Clock skew between relays routinely produces small negatives. Reporting
        // "-3 seconds" as a delay is noise, so clamp rather than pretend precision.
        hop.delaySeconds = delta < 0 ? 0 : delta;
      }
      previous = hop.date;
    }
  }

  return hops;
}

// ---------------------------------------------------------------------------
// Authentication-Results (RFC 8601)
// ---------------------------------------------------------------------------

export function parseAuthResults(raw: string): AuthResults {
  // Split on semicolons that are not inside parentheses — comments frequently
  // contain them, e.g. "(google.com: domain of x; designates ...)".
  const parts: string[] = [];
  let depth = 0;
  let buffer = '';
  for (const ch of raw) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    if (ch === ';' && depth === 0) { parts.push(buffer); buffer = ''; continue; }
    buffer += ch;
  }
  parts.push(buffer);

  const trimmed = parts.map((p) => p.trim()).filter((p) => p !== '');
  const methods: AuthMethod[] = [];
  let authservId: string | undefined;

  for (const [i, part] of trimmed.entries()) {
    // The first segment is the authenticating server's id, unless it already looks
    // like a method assignment.
    if (i === 0 && !/^[a-z-]+\s*=/i.test(part)) {
      authservId = part.split(/\s+/)[0];
      continue;
    }

    const m = /^([a-z-]+)\s*=\s*([a-z]+)/i.exec(part);
    if (!m) continue;

    const rest = part.slice(m[0].length);
    const commentMatch = /\(([^)]*)\)/.exec(rest);
    const properties: Record<string, string> = {};
    for (const p of rest.replace(/\([^)]*\)/g, ' ').matchAll(/([a-z]+\.[a-z-]+)\s*=\s*([^\s;]+)/gi)) {
      properties[p[1]!.toLowerCase()] = p[2]!.replace(/^<|>$/g, '');
    }

    methods.push({
      method: m[1]!.toLowerCase(),
      result: m[2]!.toLowerCase(),
      properties,
      comment: commentMatch?.[1]?.trim(),
    });
  }

  return { authservId, methods, raw };
}

// ---------------------------------------------------------------------------
// DKIM-Signature (RFC 6376)
// ---------------------------------------------------------------------------

export function parseDkimSignature(raw: string): DkimSignature {
  const tags: Record<string, string> = {};
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim().toLowerCase();
    if (name === '') continue;
    tags[name] = part.slice(eq + 1).trim();
  }

  return {
    version: tags['v'],
    algorithm: tags['a'],
    domain: tags['d']?.toLowerCase(),
    selector: tags['s'],
    canonicalization: tags['c'],
    identity: tags['i'],
    signedHeaders: (tags['h'] ?? '').split(':').map((h) => h.trim().toLowerCase()).filter(Boolean),
    raw,
  };
}

// ---------------------------------------------------------------------------

export function parseHeaders(raw: string): ParsedHeaders {
  const headers = splitHeaders(raw);
  const hops = parseReceived(findAll(headers, 'received'));

  const from = extractAddress(find(headers, 'from'));
  const returnPath = extractAddress(find(headers, 'return-path'));
  const dateValue = find(headers, 'date');
  const parsedDate = dateValue ? new Date(dateValue) : null;

  const timed = hops.filter((h) => h.date);
  const first = timed[0]?.date;
  const last = timed[timed.length - 1]?.date;

  return {
    headers,
    hops,
    auth: findAll(headers, 'authentication-results').map(parseAuthResults),
    dkim: findAll(headers, 'dkim-signature').map(parseDkimSignature),
    from,
    fromDomain: domainOf(from),
    to: extractAddress(find(headers, 'to')),
    subject: find(headers, 'subject'),
    date: parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate : undefined,
    messageId: find(headers, 'message-id'),
    returnPath,
    returnPathDomain: domainOf(returnPath),
    replyTo: extractAddress(find(headers, 'reply-to')),
    listUnsubscribe: find(headers, 'list-unsubscribe'),
    totalDelaySeconds:
      first && last ? Math.max(0, Math.round((last.getTime() - first.getTime()) / 1000)) : undefined,
  };
}
