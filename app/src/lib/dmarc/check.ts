import { getDomain } from 'tldts';
import type { DnsBackend } from '../dns/resolver.js';

/**
 * DMARC lookup, policy inheritance, and external destination verification.
 *
 * Two parts here are routinely got wrong by free checkers:
 *
 * 1. **Inheritance.** A subdomain with no `_dmarc` record of its own is not unprotected —
 *    it inherits from the organizational domain, and `sp=` overrides `p=` when it does.
 *    Reporting "no DMARC record" for mail.example.com when example.com publishes
 *    `p=reject` is simply wrong.
 *
 * 2. **External destination verification (RFC 7489 §7.1).** When `rua=` points at a
 *    different organizational domain, that destination must publish
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
  /** The policy that actually applies to the queried name. */
  effectivePolicy: Policy | null;
  pct: number;
  adkim: Alignment;
  aspf: Alignment;
  rua: DmarcUri[];
  ruf: DmarcUri[];
  fo: string[];
  ri: number;
  unknownTags: string[];
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

  // RFC 7489 §6.3: v must be present and first.
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

  if (!tags.has('p')) errors.push('p= is required');

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

  const known = new Set(['v', 'p', 'sp', 'rua', 'ruf', 'adkim', 'aspf', 'pct', 'fo', 'rf', 'ri']);
  for (const name of tags.keys()) if (!known.has(name)) unknownTags.push(name);

  // For the queried name: a subdomain uses sp= when the record was inherited and sp
  // is present; otherwise p= applies.
  const effectivePolicy = inherited ? (subdomainPolicy ?? policy) : policy;

  return {
    raw,
    foundAt,
    inherited,
    policy,
    subdomainPolicy,
    effectivePolicy,
    pct,
    adkim: readAlignment('adkim'),
    aspf: readAlignment('aspf'),
    rua: readUris('rua'),
    ruf: readUris('ruf'),
    fo: (tags.get('fo') ?? '0').split(':').map((s) => s.trim()).filter(Boolean),
    ri,
    unknownTags,
    errors,
  };
}

/** RFC 7489 §7.1 — reports may only be sent off-domain with the destination's consent. */
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

export async function checkDmarc(dns: DnsBackend, domain: string): Promise<DmarcResult> {
  const orgDomain = getDomain(domain);

  const fetch = async (name: string): Promise<{ records: string[] }> => {
    const answer = await dns.txt(`_dmarc.${name}`);
    return { records: answer.values.filter((v) => /^v=DMARC1/i.test(v.trim())) };
  };

  let records = (await fetch(domain)).records;
  let foundAt = domain;
  let inherited = false;

  // A subdomain with no record of its own inherits the organizational domain's policy.
  if (records.length === 0 && orgDomain && orgDomain !== domain) {
    records = (await fetch(orgDomain)).records;
    if (records.length > 0) { foundAt = orgDomain; inherited = true; }
  }

  if (records.length === 0) {
    return { domain, orgDomain, found: false, record: null, multipleRecords: false, externalDestinations: [] };
  }

  const record = parseDmarcRecord(records[0]!, foundAt, inherited);
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
