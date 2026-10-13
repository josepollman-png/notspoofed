import type { MxRecord } from './dns/resolver.js';
import { authorisesNothing, type SpfEvaluation, type SpfNode } from './spf/evaluate.js';

/**
 * Which platform guide fits the domain, worked out from records the check already has.
 *
 * No queries of its own: the MX answer and the SPF include tree are both in hand by the
 * time the report renders, and a link is not worth slowing the check down for. That is
 * why Cloudflare is absent — spotting it needs the NS records, which nothing here looks
 * up.
 *
 * A suffix must match a whole label. `endsWith('google.com')` alone would send
 * `notgoogle.com` to the Workspace guide.
 */

export interface PlatformGuide {
  name: string;
  href: string;
}

const under = (host: string, suffix: string) => host === suffix || host.endsWith(`.${suffix}`);
const clean = (host: string) => host.toLowerCase().replace(/\.$/, '');

/**
 * Every include and redirect target anywhere in the evaluated tree — except targets
 * whose record authorises nothing. An include like that is a leftover, not a sign the
 * platform sends for the domain: isc.org carries include:shops.shopify.com, which
 * answers `v=spf1 ~all`, and was shown a Shopify setup guide on the strength of it.
 */
function spfTargets(node: SpfNode | null, out = new Set<string>()): Set<string> {
  for (const child of node?.children ?? []) {
    if (
      (child.term.name === 'include' || child.term.name === 'redirect') &&
      child.term.value &&
      !authorisesNothing(child.node)
    ) {
      out.add(clean(child.term.value));
    }
    spfTargets(child.node, out);
  }
  return out;
}

export function detectPlatforms(mx: readonly MxRecord[], spf: SpfEvaluation): PlatformGuide[] {
  const hosts = mx.map((m) => clean(m.exchange));
  const includes = spfTargets(spf.tree);
  const out: PlatformGuide[] = [];

  if (hosts.some((h) => under(h, 'google.com') || under(h, 'googlemail.com')) || includes.has('_spf.google.com')) {
    out.push({ name: 'Google Workspace', href: '/guide/dmarc-google-workspace' });
  }
  if (hosts.some((h) => under(h, 'mail.protection.outlook.com')) || includes.has('spf.protection.outlook.com')) {
    out.push({ name: 'Microsoft 365', href: '/guide/dmarc-microsoft-365' });
  }
  if (includes.has('shops.shopify.com')) {
    out.push({ name: 'Shopify', href: '/guide/dmarc-shopify' });
  }
  return out;
}
