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
}

export interface ParsedRecord {
  raw: string;
  terms: Term[];
  errors: string[];
}

const MACRO = /%\{/;

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
      error: known && value === '' ? `${name}= has no value` : undefined,
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
  } else if (remainder.startsWith('/')) {
    // Bare `a/24` — cidr applies to the current domain.
    value = undefined;
  } else if (remainder !== '') {
    error = `unexpected "${remainder}" after ${name}`;
  }

  // ip4/ip6 keep their prefix length as part of the network literal; everything else
  // uses dual-cidr syntax that must be split off before the value is a hostname.
  if (name === 'ip4' || name === 'ip6') {
    if (value === undefined) error = `${name} requires an address`;
  } else if (name === 'a' || name === 'mx') {
    const target = value ?? remainder;
    const split = splitDualCidr(target);
    cidr4 = split.cidr4;
    cidr6 = split.cidr6;
    value = split.rest === '' ? undefined : split.rest;
  }

  if ((name === 'include' || name === 'exists') && !value) {
    error = `${name} requires a domain`;
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
    return { raw, terms: [], errors: ['not an SPF record (must begin with v=spf1)'] };
  }

  const tokens = trimmed.split(/\s+/).slice(1).filter((t) => t !== '');
  const terms = tokens.map(parseTerm);

  for (const t of terms) if (t.error) errors.push(t.error);

  // `all` short-circuits evaluation, so any *mechanism* after it is unreachable and is
  // almost always a mistake the author has not noticed. Modifiers are position-
  // independent (RFC 7208 §6) and so are exempt from this check.
  const allIndex = terms.findIndex((t) => t.name === 'all' && t.kind === 'mechanism');
  if (allIndex >= 0) {
    const dead = terms.slice(allIndex + 1).filter((t) => t.kind === 'mechanism');
    if (dead.length > 0) {
      errors.push(
        `terms after "all" are never evaluated: ${dead.map((t) => t.raw).join(' ')}`,
      );
    }
    // `all` always matches, so evaluation never falls through to the redirect.
    // The redirect target's policy is dead code — worth saying, because authors add
    // a redirect expecting it to take effect.
    if (terms.some((t) => t.name === 'redirect')) {
      errors.push('redirect= is ignored because an "all" mechanism is present');
    }
  }

  return { raw: trimmed, terms, errors };
}
