/**
 * DKIM selectors cannot be enumerated. There is no DNS query that lists them — the
 * selector is chosen by whoever set up the signing, and the only way to find one is
 * to know it or guess it.
 *
 * So this list is a *guess list*, and the UI must say so. A domain reporting "no DKIM
 * found" here has not been proven to lack DKIM; it may simply use a selector we did
 * not try. Amazon SES, for instance, issues random tokens that are unguessable by
 * construction, and HubSpot embeds a per-account hub ID.
 *
 * Ordered roughly by how often they appear in the wild, since we stop early on a hit
 * when the caller asks for a quick check.
 */

export interface SelectorGuess {
  selector: string;
  /** Shown next to a hit so the user learns which vendor signs their mail. */
  provider: string;
}

export const COMMON_SELECTORS: readonly SelectorGuess[] = [
  { selector: 'google', provider: 'Google Workspace' },
  { selector: 'selector1', provider: 'Microsoft 365' },
  { selector: 'selector2', provider: 'Microsoft 365' },
  // Cloudflare Email Routing publishes exactly this selector, and its user base is
  // growing fast. Omitting it made the tool report "no DKIM found" on domains that
  // had a perfectly good key — including our own.
  { selector: 'cf2024-1', provider: 'Cloudflare Email Routing' },
  { selector: 'fm1', provider: 'Fastmail' },
  { selector: 'fm2', provider: 'Fastmail' },
  { selector: 'fm3', provider: 'Fastmail' },
  { selector: 'titan1', provider: 'Titan Mail' },
  { selector: 'k1', provider: 'Mailchimp / Mandrill' },
  { selector: 'k2', provider: 'Mailchimp / Mandrill' },
  { selector: 'k3', provider: 'Mailchimp / Mandrill' },
  { selector: 's1', provider: 'SendGrid / generic' },
  { selector: 's2', provider: 'SendGrid / generic' },
  { selector: 'dkim', provider: 'generic' },
  { selector: 'default', provider: 'generic' },
  { selector: 'mail', provider: 'generic' },
  { selector: 'smtp', provider: 'generic' },
  { selector: 'mandrill', provider: 'Mandrill' },
  { selector: 'sendgrid', provider: 'SendGrid' },
  { selector: 'zoho', provider: 'Zoho Mail' },
  { selector: 'zmail', provider: 'Zoho Mail' },
  { selector: 'protonmail', provider: 'Proton Mail' },
  { selector: 'protonmail2', provider: 'Proton Mail' },
  { selector: 'protonmail3', provider: 'Proton Mail' },
  { selector: 'pm', provider: 'Postmark' },
  { selector: 'klaviyo', provider: 'Klaviyo' },
  { selector: 'mailjet', provider: 'Mailjet' },
  { selector: 'ctct1', provider: 'Constant Contact' },
  { selector: 'ctct2', provider: 'Constant Contact' },
  { selector: 'zendesk1', provider: 'Zendesk' },
  { selector: 'zendesk2', provider: 'Zendesk' },
  { selector: 'freshdesk', provider: 'Freshdesk' },
  { selector: 'sig1', provider: 'generic' },
  { selector: 'dkim1', provider: 'generic' },
  { selector: 'dkim2', provider: 'generic' },
  { selector: 'mesmtp', provider: 'generic' },
  { selector: 'everlytickey1', provider: 'Everlytic' },
  { selector: 'everlytickey2', provider: 'Everlytic' },
  { selector: 'bf1', provider: 'generic' },
  { selector: 'bf2', provider: 'generic' },
  { selector: 'hs1', provider: 'HubSpot' },
  { selector: 'hs2', provider: 'HubSpot' },
  { selector: 'mx', provider: 'generic' },
  { selector: 'email', provider: 'generic' },
  { selector: 'key1', provider: 'generic' },
  { selector: 'key2', provider: 'generic' },
  { selector: '20161025', provider: 'Google (legacy dated selector)' },
  { selector: 'm1', provider: 'generic' },
  { selector: 'mailer', provider: 'generic' },
  { selector: 'turbo-smtp', provider: 'TurboSMTP' },
];

/** Providers whose selectors are randomised and therefore never guessable. */
export const UNGUESSABLE_PROVIDERS = [
  'Amazon SES (random 3-token selectors)',
  'SparkPost (date-stamped selectors)',
  'HubSpot (per-account hub ID in the selector)',
] as const;
