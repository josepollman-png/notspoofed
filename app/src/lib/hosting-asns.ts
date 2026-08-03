/**
 * Autonomous systems that host machines rather than connect people.
 *
 * A visitor arriving from AWS, Hetzner or a bulletproof VPS reseller is not somebody
 * reading about DMARC. User-agent matching cannot see this — the traffic that made the
 * visitor count meaningless presents a plausible Chrome or Safari string and comes from
 * rented hardware, and no amount of string matching will ever separate the two.
 *
 * **This list is a heuristic and is deliberately not exhaustive.** It names the networks
 * that carry the overwhelming majority of automated traffic; it will always miss
 * somebody's new box, and it is not evidence about any individual visit. It exists to
 * stop a headline number being wrong by an order of magnitude, which is the only thing
 * the counters are used for.
 *
 * Two categories are kept out on purpose:
 *
 * - **Consumer VPN and privacy networks** (Cloudflare WARP, Mullvad, iCloud Private
 *   Relay). Those carry real readers who have merely declined to be tracked, and the
 *   site is built for exactly that person. Counting them as robots would be both wrong
 *   and against the spirit of the thing.
 * - **Transit carriers** (Cogent, Level3, Telia). They move everyone's traffic including
 *   residential, so an origin AS of a pure transit network says nothing.
 */

/** AS numbers, without the `AS` prefix — Team Cymru returns them bare. */
export const HOSTING_ASNS: ReadonlySet<string> = new Set([
  // --- Hyperscale cloud ---
  '16509', '14618', '8987', '39111',              // Amazon AWS
  '15169', '396982', '19527', '139070',           // Google / Google Cloud
  '8075', '8068', '8069', '8070', '8071', '12076', // Microsoft / Azure
  '31898', '7160',                                 // Oracle Cloud
  '45102', '37963', '134963',                      // Alibaba Cloud
  '132203', '45090',                               // Tencent Cloud
  '55990', '136907',                               // Huawei Cloud
  '135377',                                        // UCloud

  // --- Mainstream VPS and dedicated hosting ---
  '14061',           // DigitalOcean
  '24940', '213230', // Hetzner
  '16276',           // OVH
  '63949',           // Akamai / Linode
  '20473',           // Vultr (Choopa)
  '12876',           // Scaleway / Online SAS
  '51167',           // Contabo
  '197540',          // netcup
  '47583',           // Hostinger
  '29802',           // Hivelocity
  '53667',           // FranTech / BuyVM
  '36352',           // ColoCrossing
  '8100',            // QuadraNet
  '49981',           // WorldStream
  '60781', '28753', '395954', '30633', // Leaseweb
  '199524',          // G-Core Labs
  '21859',           // Zenlayer
  '26496', '30083',  // GoDaddy hosting
  '22612',           // Namecheap
  '46606',           // Unified Layer
  '55293',           // A2 Hosting
  '32475',           // SingleHop
  '9009',            // M247
  '60068', '212238', // Datacamp / CDN77
  '62240',           // Clouvider
  '396356',          // Latitude.sh
  '137409',          // GSL Networks
  '206092',          // IPXO
  '49505',           // Selectel
  '200651',          // FlokiNET
  '35916',           // MULTA-ASN1
  '43350',           // NForce
  '51852',           // Private Layer

  // --- Networks that are predominantly scanning or abuse infrastructure ---
  '398324',          // Censys
  '396190', '398705', // Shodan
  '211298', '208843', '400304', // Internet measurement projects
  '202425',          // IP Volume
  '210644',          // AEZA
  '44477',           // Stark Industries
  '62904',           // Eonix
  '20454',           // SecuredConnectivity
]);

export function isHostingAsn(asn: string | null | undefined): boolean {
  return asn ? HOSTING_ASNS.has(asn.replace(/^AS/i, '').trim()) : false;
}
