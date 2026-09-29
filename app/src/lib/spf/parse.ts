/**
 * SPF record tokenizer — RFC 7208 §4, §5, §6.
 *
 * The grammar splits into two shapes that a naive parser conflates:
 *
 *   directive = [qualifier] mechanism [":" value] [dual-cidr]     <- colon
 *   modifier  = name "=" macro-string                             <- equals
 *
 * `redirect=` and `exp=` are modifiers. A tokenizer that only recognises `:` drops
 * them silently, and because `redirect=` is the *entire* record on domains like
 * hubspot.com, that yields a confident report of "0 DNS lookups" for a domain with
 * plenty. Silent undercounting is worse than crashing, so `redirect=` has a dedicated
 * regression test.
 *
 * Every term is validated against the ABNF (§4.6.1, §5, §6), and a failure is a syntax
 * error: RFC 7208 §4.6 makes the *whole* check a permerror before a single mechanism is
 * evaluated. That includes the addresses in ip4/ip6, which used to be accepted as any
 * text at all — so `ip6:2620:52:3::214ip4:8.43.84.199`, two terms run together where a
 * record split across TXT strings lost its space, passed as one valid ip6 term.
 *
 * `errors` holds only what makes the record a permerror. Things that are legal but
 * almost certainly unintended — terms after `all`, a redirect that `all` makes dead —
 * go in `warnings`, because calling them permerrors would be its own false alarm.
 */

export type Qualifier = '+' | '-' | '~' | '?';

export const MECHANISMS = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'] as const;
export type MechanismName = (typeof MECHANISMS)[number];

/**
 * RFC 7208 §4.6.4 — exactly these terms count toward the limit of 10.
 * `all`, `ip4`, `ip6` are free (no query). `exp` queries DNS but is explicitly
 * excluded from the count.
 */
const COSTLY = new Set<string>(['include', 'a', 'mx', 'ptr', 'exists', 'redirect']);

export interface Term {
  /** The token exactly as it appeared, for echoing back in the UI. */
  raw: string;
  kind: 'mechanism' | 'modifier' | 'unknown';
  qualifier: Qualifier;
  name: string;
  /** domain-spec, IP network, or modifier value. Undefined for bare `a`/`mx`/`all`. */
  value?: string;
  cidr4?: number;
  cidr6?: number;
  costsLookup: boolean;
  /** Contains a %{…} macro, so it cannot be resolved without a live client IP. */
  hasMacro: boolean;
  error?: string;
  /** For a malformed term that is two valid terms run together: the pair, spaced. */
  suggestion?: string;
}

export interface ParsedRecord {
  raw: string;
  terms: Term[];
  /** Syntax errors. Any one of them makes the record a permerror (RFC 7208 §4.6). */
  errors: string[];
  /** Errors that belong to the record rather than to one term, e.g. a repeated redirect=. */
  recordErrors: string[];
  /** Legal, but almost certainly not what the author meant. Not a permerror. */
  warnings: string[];
}

const MACRO = /%\{/;

// ---------------------------------------------------------------------------
// Strict validators for the ABNF's value productions
// ---------------------------------------------------------------------------

/** ip4-network: four decimal octets, no leading zeros beyond a lone 0. */
export function isIp4(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

/** ip6-network: RFC 4291 text form, `::` at most once, optional trailing IPv4. */
export function isIp6(value: string): boolean {
  if (!/^[0-9A-Fa-f:.]+$/.test(value)) return false;
  let groups = value;
  let extra = 0;

  // An embedded IPv4 tail (::ffff:192.0.2.1) stands in for the last two groups.
  const lastColon = groups.lastIndexOf(':');
  const tail = groups.slice(lastColon + 1);
  if (tail.includes('.')) {
    if (!isIp4(tail)) return false;
    groups = groups.slice(0, lastColon + 1) + '0';
    extra = 1;
  }

  const halves = groups.split('::');
  if (halves.length > 2) return false;
  const hex = /^[0-9A-Fa-f]{1,4}$/;
  const count = (h: string) => (h === '' ? 0 : h.split(':').length);
  for (const half of halves) {
    if (half !== '' && !half.split(':').every((g) => hex.test(g))) return false;
  }
  const total = halves.reduce((n, h) => n + count(h), 0) + extra;
  return halves.length === 2 ? total <= 7 : total === 8;
}

/** A prefix length, as digits, within range. `undefined` means none was given. */
function cidrOk(raw: string | undefined, max: number): boolean {
  return raw === undefined || (/^(0|[1-9]\d*)$/.test(raw) && Number(raw) <= max);
}

/**
 * domain-spec = macro-string domain-end. The part that goes wrong in practice is the
 * end: it must be a top label with a letter in it (or a macro), which is what rejects
 * `include:spf` and `include:192.0.2.1` — both permerrors, both seen in the wild.
 */
function domainSpecError(spec: string): string | undefined {
  if (spec === '') return 'is empty';
  if (/[^\x21-\x7e]/.test(spec)) return 'contains characters a domain cannot';
  const bare = spec.replace(/\.$/, '');
  if (/%\{[^}]*\}$/.test(bare)) return undefined;
  const top = bare.slice(bare.lastIndexOf('.') + 1);
  if (!bare.includes('.')) return 'is not a fully qualified domain';
  const toplabel = /^([0-9A-Za-z]*[A-Za-z][0-9A-Za-z]*|[0-9A-Za-z]+-[0-9A-Za-z-]*[0-9A-Za-z])$/;
  if (!toplabel.test(top)) return `ends in "${top}", which is not a valid top-level label`;
  return undefined;
}

/** Strip the dual-cidr suffix used by `a` and `mx`: /24, //64, or /24//64. */
function splitDualCidr(input: string): { rest: string; cidr4?: number; cidr6?: number } {
  const m = /^(.*?)(?:\/(\d+))?(?:\/\/(\d+))?$/.exec(input);
  if (!m) return { rest: input };
  return {
    rest: m[1] ?? input,
    cidr4: m[2] === undefined ? undefined : Number(m[2]),
    cidr6: m[3] === undefined ? undefined : Number(m[3]),
  };
}

const prefixed = (what: string, problem: string | undefined) =>
  problem === undefined ? undefined : `${what} ${problem}`;

/**
 * Two valid terms with the space between them missing — the usual result of a record
 * split into TXT strings where the first string lost its trailing space, since strings
 * join with nothing between them (§3.3). Offered only when both halves parse cleanly and
 * the second begins with an unambiguous term, so `a` and `mx` inside hostnames never
 * produce a suggestion.
 */
function runTogether(raw: string): string | undefined {
  const start = /[+\-~?]?(?:ip4:|ip6:|include:|exists:|redirect=|exp=|all$)/gi;
  for (let m = start.exec(raw); m; m = start.exec(raw)) {
    if (m.index === 0) continue;
    const first = raw.slice(0, m.index);
    const second = raw.slice(m.index);
    if (!parseTerm(first).error && !parseTerm(second).error) return `${first} ${second}`;
  }
  return undefined;
}

function parseTerm(raw: string): Term {
  // Modifiers are `name=value`. Check first: an `=` before any `:` settles it, and
  // no mechanism name may contain `=`.
  const mod = /^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$/.exec(raw);
  if (mod) {
    const name = mod[1]!.toLowerCase();
    const value = mod[2]!;
    const known = name === 'redirect' || name === 'exp';
    return {
      raw,
      kind: known ? 'modifier' : 'unknown',
      qualifier: '+',
      name,
      value,
      costsLookup: COSTLY.has(name),
      hasMacro: MACRO.test(value),
      // Unknown modifiers are legal and MUST be ignored (RFC 7208 §6). Not an error.
      error: known
        ? value === '' ? `${name}= has no value` : prefixed(`${name}= target`, domainSpecError(value))
        : undefined,
    };
  }

  const first = raw[0] ?? '';
  const hasQualifier = first === '+' || first === '-' || first === '~' || first === '?';
  const qualifier = (hasQualifier ? first : '+') as Qualifier;
  const body = hasQualifier ? raw.slice(1) : raw;

  // Mechanism names are alphabetic; ip4/ip6 carry digits, so allow them in the name.
  const nameMatch = /^[A-Za-z][A-Za-z0-9]*/.exec(body);
  if (!nameMatch) {
    return {
      raw, kind: 'unknown', qualifier, name: body,
      costsLookup: false, hasMacro: false, error: `unrecognised term "${raw}"`,
    };
  }

  const name = nameMatch[0]!.toLowerCase();
  let remainder = body.slice(nameMatch[0]!.length);

  if (!MECHANISMS.includes(name as MechanismName)) {
    return {
      raw, kind: 'unknown', qualifier, name,
      costsLookup: false, hasMacro: MACRO.test(raw),
      error: `unknown mechanism "${name}"`,
    };
  }

  let value: string | undefined;
  let cidr4: number | undefined;
  let cidr6: number | undefined;
  let error: string | undefined;

  if (remainder.startsWith(':')) {
    value = remainder.slice(1);
  } else if (remainder.startsWith('/') && (name === 'a' || name === 'mx')) {
    // Bare `a/24` — cidr applies to the current domain.
    value = undefined;
  } else if (remainder !== '') {
    error = `unexpected "${remainder}" after ${name}`;
  }

  if (!error) {
    if (name === 'all') {
      if (value !== undefined) error = 'all takes no value';
    } else if (name === 'ip4' || name === 'ip6') {
      // The prefix length stays part of the network literal, but is checked apart
      // from the address so that a bad /33 and a bad address read differently.
      if (value === undefined || value === '') {
        error = `${name} requires an address`;
      } else {
        const slash = value.indexOf('/');
        const addr = slash < 0 ? value : value.slice(0, slash);
        const len = slash < 0 ? undefined : value.slice(slash + 1);
        const max = name === 'ip4' ? 32 : 128;
        if (!(name === 'ip4' ? isIp4(addr) : isIp6(addr))) {
          error = `"${addr}" is not a valid ${name === 'ip4' ? 'IPv4' : 'IPv6'} address`;
        } else if (!cidrOk(len, max)) {
          error = `/${len} is not a valid ${name === 'ip4' ? 'IPv4' : 'IPv6'} prefix length (0–${max})`;
        }
      }
    } else if (name === 'a' || name === 'mx') {
      const target = value ?? remainder;
      const m = /^(.*?)(?:\/([^/]*))?(?:\/\/([^/]*))?$/.exec(target);
      const rest = m?.[1] ?? target;
      if (!cidrOk(m?.[2], 32) || !cidrOk(m?.[3], 128)) {
        error = `"${target.slice(rest.length)}" is not a valid dual-cidr length`;
      } else {
        const split = splitDualCidr(target);
        cidr4 = split.cidr4;
        cidr6 = split.cidr6;
        value = split.rest === '' ? undefined : split.rest;
        if (value !== undefined) error = prefixed(`${name} target`, domainSpecError(value));
      }
    } else if (name === 'include' || name === 'exists') {
      error = value ? prefixed(`${name} target`, domainSpecError(value)) : `${name} requires a domain`;
    } else if (name === 'ptr' && value !== undefined) {
      error = prefixed('ptr target', domainSpecError(value));
    }
  }

  return {
    raw,
    kind: 'mechanism',
    qualifier,
    name,
    value,
    cidr4,
    cidr6,
    costsLookup: COSTLY.has(name),
    hasMacro: MACRO.test(raw),
    error,
  };
}

/** True if `txt` is an SPF record. Matches the version token case-insensitively and
 *  requires a terminator, so `v=spf10` is correctly rejected. */
export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

export function parseSpf(raw: string): ParsedRecord {
  const errors: string[] = [];
  const trimmed = raw.trim();

  if (!isSpfRecord(trimmed)) {
    const e = 'not an SPF record (must begin with v=spf1)';
    return { raw, terms: [], errors: [e], recordErrors: [e], warnings: [] };
  }

  const tokens = trimmed.split(/\s+/).slice(1).filter((t) => t !== '');
  const terms = tokens.map(parseTerm);
  const recordErrors: string[] = [];
  const warnings: string[] = [];

  for (const t of terms) {
    if (!t.error) continue;
    t.suggestion = runTogether(t.raw);
    errors.push(`malformed term "${t.raw}": ${t.error}`);
  }

  // RFC 7208 §6: redirect= and exp= may each appear at most once.
  for (const name of ['redirect', 'exp']) {
    const n = terms.filter((t) => t.kind === 'modifier' && t.name === name).length;
    if (n > 1) recordErrors.push(`${name}= appears ${n} times; RFC 7208 §6 allows it once`);
  }
  errors.push(...recordErrors);

  // `all` short-circuits evaluation, so any *mechanism* after it is unreachable and is
  // almost always a mistake the author has not noticed. Modifiers are position-
  // independent (RFC 7208 §6) and so are exempt from this check.
  const allIndex = terms.findIndex((t) => t.name === 'all' && t.kind === 'mechanism');
  if (allIndex >= 0) {
    const dead = terms.slice(allIndex + 1).filter((t) => t.kind === 'mechanism');
    if (dead.length > 0) {
      warnings.push(
        `terms after "all" are never evaluated: ${dead.map((t) => t.raw).join(' ')}`,
      );
    }
    // `all` always matches, so evaluation never falls through to the redirect.
    // The redirect target's policy is dead code — worth saying, because authors add
    // a redirect expecting it to take effect.
    if (terms.some((t) => t.name === 'redirect')) {
      warnings.push('redirect= is ignored because an "all" mechanism is present');
    }
  }

  return { raw: trimmed, terms, errors, recordErrors, warnings };
}
