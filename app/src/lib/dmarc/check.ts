import { getDomain } from 'tldts';
import type { DnsBackend } from '../dns/resolver.js';

/**
 * DMARC lookup, policy inheritance, and external destination verification.
 *
 * Tracks RFC 9989 (May 2026), which obsoletes RFC 7489 and RFC 9091. Three parts here
 * are routinely got wrong by free checkers:
 *
 * 1. **Inheritance, via the tree walk (§4.10).** A subdomain with no `_dmarc` record of
 *    its own is not unprotected — it inherits from further up, and `sp=`/`np=` override
 *    `p=` when it does. Reporting "no DMARC record" for mail.example.com when
 *    example.com publishes `p=reject` is simply wrong.
 *
 *    9989 replaced the Public Suffix List with an upward walk, and the difference is
 *    not cosmetic. Jumping straight from `a.b.example.com` to the PSL-derived
 *    `example.com` steps over `b.example.com`, so a policy published there is missed
 *    entirely and the wrong policy is reported as the effective one.
 *
 * 2. **`np=` is not `sp=` (§4.7).** `sp=` governs subdomains that exist; `np=` governs
 *    ones that do not. Since the subdomains attackers invent are almost never real,
 *    `np=` is usually the tag actually deciding the outcome — so it has to be resolved
 *    against the DNS rather than assumed.
 *
 * 3. **External destination verification (RFC 9990 §5.4, formerly 7489 §7.1).** When
 *    `rua=` points at a different organizational domain, that destination must publish
 *    `<your-domain>._report._dmarc.<destination-host>` containing `v=DMARC1`, or
 *    conforming reporters will refuse to send. Verified live: PayPal points rua at
 *    rua.agari.com, and `paypal.com._report._dmarc.rua.agari.com` exists.
 *
 *    Without this check a domain can look perfectly configured while its reports go
 *    nowhere — which is exactly the failure that leaves someone blind for months.
 */

export type Policy = 'none' | 'quarantine' | 'reject';
export type Alignment = 'r' | 's';

export interface DmarcUri {
  raw: string;
  scheme: string;
  address: string;
  host: string;
  /** Optional size limit suffix, e.g. `!10m`. */
  sizeLimit?: string;
}

export interface ExternalDestination {
  uri: DmarcUri;
  /** Whether §7.1 authorisation is required at all. */
  required: boolean;
  authorised: boolean;
  /** The exact name that must carry `v=DMARC1`. */
  expectedRecord: string;
}

export interface DmarcRecord {
  raw: string;
  /** The name the record was actually found at — may be the org domain. */
  foundAt: string;
  /** True when the record came from the org domain rather than the queried name. */
  inherited: boolean;
  policy: Policy | null;
  subdomainPolicy: Policy | null;
  /** `np=` — policy for subdomains that do not exist at all (RFC 9989 §4.7). */
  nonExistentPolicy: Policy | null;
  /** The policy that actually applies to the queried name. */
  effectivePolicy: Policy | null;
  /** Which tag `effectivePolicy` came from, so findings can name the right one. */
  appliedTag: 'p' | 'sp' | 'np';
  /**
   * `t=y` — the domain owner is testing. Receivers apply handling one level below the
   * stated policy, so a record can read `p=reject` and reject nothing.
   */
  testMode: boolean;
  pct: number;
  adkim: Alignment;
  aspf: Alignment;
  rua: DmarcUri[];
  ruf: DmarcUri[];
  fo: string[];
  ri: number;
  unknownTags: string[];
  /** Tags RFC 9989 removed. Still parsed — published records are full of them. */
  deprecatedTags: string[];
  errors: string[];
}

export interface DmarcResult {
  domain: string;
  orgDomain: string | null;
  found: boolean;
  record: DmarcRecord | null;
  /** More than one `_dmarc` TXT record — receivers treat this as no policy at all. */
  multipleRecords: boolean;
  externalDestinations: ExternalDestination[];
}

const POLICIES = new Set<string>(['none', 'quarantine', 'reject']);

function parseUri(raw: string): DmarcUri | null {
  const trimmed = raw.trim();
  if (trimmed === '') return null;

  // `mailto:a@b.com!10m` — the size limit is part of the URI, not the address.
  const bang = trimmed.lastIndexOf('!');
  const sizeLimit = bang > 0 ? trimmed.slice(bang + 1) : undefined;
  const withoutSize = bang > 0 ? trimmed.slice(0, bang) : trimmed;

  const colon = withoutSize.indexOf(':');
  if (colon < 0) return null;

  const scheme = withoutSize.slice(0, colon).toLowerCase();
  const address = withoutSize.slice(colon + 1);
  const at = address.lastIndexOf('@');
  if (scheme !== 'mailto' || at < 0) return null;

  return { raw: trimmed, scheme, address, host: address.slice(at + 1).toLowerCase(), sizeLimit };
}

export function parseDmarcRecord(raw: string, foundAt: string, inherited: boolean): DmarcRecord {
  const errors: string[] = [];
  const unknownTags: string[] = [];
  const deprecatedTags: string[] = [];
  const tags = new Map<string, string>();

  const parts = raw.split(';').map((p) => p.trim()).filter((p) => p !== '');
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq < 0) { errors.push(`malformed tag "${part}"`); continue; }
    const name = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (tags.has(name)) errors.push(`tag "${name}" appears more than once`);
    tags.set(name, value);
  }

  // RFC 9989 §4.6: v must be present and first.
  const first = parts[0]?.split('=')[0]?.trim().toLowerCase();
  if (first !== 'v') errors.push('the v=DMARC1 tag must come first');
  if ((tags.get('v') ?? '').toUpperCase() !== 'DMARC1') errors.push('v= must be exactly DMARC1');

  const readPolicy = (tag: string): Policy | null => {
    const v = tags.get(tag);
    if (v === undefined) return null;
    const lower = v.toLowerCase();
    if (!POLICIES.has(lower)) {
      errors.push(`${tag}=${v} is not one of none, quarantine, reject`);
      return null;
    }
    return lower as Policy;
  };

  const policy = readPolicy('p');
  const subdomainPolicy = readPolicy('sp');
  const nonExistentPolicy = readPolicy('np');

  if (!tags.has('p')) errors.push('p= is required');

  // t=y means "apply one level below what p= says". Anything other than y/n is a
  // syntax error rather than a silent default, because guessing wrong here inverts
  // whether the domain is enforcing at all.
  let testMode = false;
  if (tags.has('t')) {
    const v = (tags.get('t') ?? '').toLowerCase();
    if (v !== 'y' && v !== 'n') errors.push(`t=${tags.get('t')} must be y or n`);
    else testMode = v === 'y';
  }

  let pct = 100;
  if (tags.has('pct')) {
    const n = Number(tags.get('pct'));
    if (!Number.isInteger(n) || n < 0 || n > 100) {
      errors.push(`pct=${tags.get('pct')} must be an integer from 0 to 100`);
    } else {
      pct = n;
    }
  }

  let ri = 86400;
  if (tags.has('ri')) {
    const n = Number(tags.get('ri'));
    if (!Number.isInteger(n) || n <= 0) errors.push(`ri=${tags.get('ri')} must be a positive integer`);
    else ri = n;
  }

  const readAlignment = (tag: string): Alignment => {
    const v = (tags.get(tag) ?? 'r').toLowerCase();
    if (v !== 'r' && v !== 's') { errors.push(`${tag}=${v} must be r or s`); return 'r'; }
    return v;
  };

  const readUris = (tag: string): DmarcUri[] => {
    const v = tags.get(tag);
    if (v === undefined || v === '') return [];
    const out: DmarcUri[] = [];
    for (const chunk of v.split(',')) {
      const uri = parseUri(chunk);
      if (uri) out.push(uri);
      else errors.push(`${tag} contains an unusable URI "${chunk.trim()}" (only mailto: is widely supported)`);
    }
    return out;
  };

  // Removed by RFC 9989 but still widely published, so they parse and are reported as
  // deprecated rather than as typos. Calling a live `pct=` tag "unrecognised" would
  // send people looking for a spelling mistake that isn't there.
  const deprecated = new Set(['pct', 'rf', 'ri']);
  const known = new Set([
    'v', 'p', 'sp', 'np', 't', 'psd', 'rua', 'ruf', 'adkim', 'aspf', 'fo', ...deprecated,
  ]);
  for (const name of tags.keys()) {
    if (deprecated.has(name)) deprecatedTags.push(name);
    else if (!known.has(name)) unknownTags.push(name);
  }

  // For the queried name: a subdomain uses sp= when the record was inherited and sp is
  // present; otherwise p= applies. np= can outrank sp=, but only for a name that does
  // not exist — which needs DNS, so checkDmarc refines this afterwards.
  const effectivePolicy = inherited ? (subdomainPolicy ?? policy) : policy;
  const appliedTag: 'p' | 'sp' | 'np' = inherited && subdomainPolicy !== null ? 'sp' : 'p';

  return {
    raw,
    foundAt,
    inherited,
    policy,
    subdomainPolicy,
    nonExistentPolicy,
    effectivePolicy,
    appliedTag,
    testMode,
    pct,
    adkim: readAlignment('adkim'),
    aspf: readAlignment('aspf'),
    rua: readUris('rua'),
    ruf: readUris('ruf'),
    fo: (tags.get('fo') ?? '0').split(':').map((s) => s.trim()).filter(Boolean),
    ri,
    unknownTags,
    deprecatedTags,
    errors,
  };
}

/** RFC 9990 §5.4 — reports may only be sent off-domain with the destination's consent. */
async function verifyExternal(
  dns: DnsBackend,
  publishingDomain: string,
  uris: readonly DmarcUri[],
): Promise<ExternalDestination[]> {
  const publisherOrg = getDomain(publishingDomain);
  const seen = new Set<string>();
  const out: ExternalDestination[] = [];

  for (const uri of uris) {
    if (seen.has(uri.host)) continue;
    seen.add(uri.host);

    const destOrg = getDomain(uri.host);
    const expectedRecord = `${publishingDomain}._report._dmarc.${uri.host}`;

    // Same organizational domain: no authorisation needed.
    if (destOrg !== null && publisherOrg !== null && destOrg === publisherOrg) {
      out.push({ uri, required: false, authorised: true, expectedRecord });
      continue;
    }

    const answer = await dns.txt(expectedRecord);
    const authorised = answer.values.some((v) => /^v=DMARC1(\s*;|\s*$)/i.test(v.trim()));
    out.push({ uri, required: true, authorised, expectedRecord });
  }

  return out;
}

/** RFC 9989 §4.10 caps the walk at eight queries however deep the name is. */
const TREE_WALK_MAX = 8;

/**
 * The names to query, nearest first, per the §4.10 tree walk.
 *
 * Stops at two labels rather than walking into the TLD: a public suffix publishes no
 * policy an ordinary domain owner inherits, and querying `_dmarc.com` on every check
 * is noise the root servers do not need from us.
 */
export function treeWalkNames(domain: string): string[] {
  const labels = domain.split('.').filter(Boolean);
  const names = [domain];

  // §4.10 step 4: at eight labels or more, jump to the top seven before walking, so a
  // deeply nested name costs no more queries than a shallow one.
  let rest = labels.length >= 8 ? labels.slice(labels.length - 7) : labels.slice(1);
  while (rest.length >= 2) {
    names.push(rest.join('.'));
    rest = rest.slice(1);
  }

  return names.slice(0, TREE_WALK_MAX);
}

/**
 * Whether the name exists in the DNS at all — the test `np=` turns on (§4.7).
 *
 * "Non-existent" means NXDOMAIN, not "has no address records". A subdomain with an MX
 * and no A still exists, and `sp=` governs it. Anything other than a clean NXDOMAIN
 * counts as existing, so a timeout or SERVFAIL falls back to `sp=`/`p=` rather than
 * reporting a stricter policy than the domain is actually getting.
 */
async function nameExists(dns: DnsBackend, name: string): Promise<boolean> {
  const a = await dns.a(name);
  if (a.error !== 'NXDOMAIN') return true;
  // RFC 8020 says nothing exists below an NXDOMAIN, but enough resolvers get that
  // wrong that one corroborating query is worth the budget.
  const mx = await dns.mx(name);
  return mx.error !== 'NXDOMAIN';
}

export async function checkDmarc(dns: DnsBackend, domain: string): Promise<DmarcResult> {
  // Still the PSL, and only for the reporting-authorisation comparison below, which is
  // a question about who owns two names rather than about where a policy lives.
  const orgDomain = getDomain(domain);

  const fetch = async (name: string): Promise<{ records: string[] }> => {
    const answer = await dns.txt(`_dmarc.${name}`);
    return { records: answer.values.filter((v) => /^v=DMARC1/i.test(v.trim())) };
  };

  let records: string[] = [];
  let foundAt = domain;

  // Nearest ancestor wins: the walk stops at the first name that answers, so a policy
  // on an intermediate label is honoured instead of being stepped over.
  for (const name of treeWalkNames(domain)) {
    const found = (await fetch(name)).records;
    if (found.length > 0) { records = found; foundAt = name; break; }
  }

  const inherited = foundAt !== domain;

  if (records.length === 0) {
    return { domain, orgDomain, found: false, record: null, multipleRecords: false, externalDestinations: [] };
  }

  const record = parseDmarcRecord(records[0]!, foundAt, inherited);

  // np= outranks sp=, but only for a name that is not in the DNS. Probing costs up to
  // two queries, so it runs only where it can actually change the answer.
  if (inherited && record.nonExistentPolicy !== null && !(await nameExists(dns, domain))) {
    record.effectivePolicy = record.nonExistentPolicy;
    record.appliedTag = 'np';
  }

  if (records.length > 1) {
    record.errors.push(
      `${records.length} DMARC records published at _dmarc.${foundAt}; receivers treat this as no policy at all`,
    );
  }

  const externalDestinations = await verifyExternal(dns, foundAt, [...record.rua, ...record.ruf]);

  return {
    domain,
    orgDomain,
    found: true,
    record,
    multipleRecords: records.length > 1,
    externalDestinations,
  };
}
