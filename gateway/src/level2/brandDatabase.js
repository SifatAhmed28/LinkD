/**
 * brandDatabase.js
 *
 * Expanded brand catalog for domain mismatch detection.
 * ~60 brands across finance, tech, social, cloud, streaming, shopping,
 * government, shipping, telecom, and gaming — the categories most commonly
 * impersonated in phishing campaigns.
 *
 * Each brand entry includes:
 *   canonicalDomains — legitimate domains owned by the brand (primary + regional)
 *   aliases          — common textual variants / abbreviations that also refer to the brand
 *   category         — industry grouping for analysis
 *
 * Also exports:
 *   TLD_RISK_MAP    — TLD → phishing risk score (0–1)
 *   TRUST_KEYWORDS  — set of words commonly appended by combosquatters
 *
 * @module brandDatabase
 */

// ── Brand Catalog ──────────────────────────────────────────────────────────────

const BRAND_DB = {
  // ─── Finance / Banking ────────────────────────────────────────────────────
  paypal: {
    canonicalDomains: ['paypal.com', 'paypal.co.uk', 'paypal.de', 'paypal.fr'],
    aliases: ['paypal-me', 'paypalme'],
    category: 'finance',
  },
  venmo: {
    canonicalDomains: ['venmo.com'],
    aliases: [],
    category: 'finance',
  },
  cashapp: {
    canonicalDomains: ['cash.app', 'cashapp.com'],
    aliases: ['cash-app', 'square-cash'],
    category: 'finance',
  },
  stripe: {
    canonicalDomains: ['stripe.com'],
    aliases: [],
    category: 'finance',
  },
  chase: {
    canonicalDomains: ['chase.com', 'chase.co.uk'],
    aliases: ['jpmorgan', 'jpmorganchase'],
    category: 'finance',
  },
  wellsfargo: {
    canonicalDomains: ['wellsfargo.com', 'wellsfargo.net'],
    aliases: ['wells-fargo'],
    category: 'finance',
  },
  bankofamerica: {
    canonicalDomains: ['bankofamerica.com', 'bofa.com'],
    aliases: ['bank-of-america', 'boa'],
    category: 'finance',
  },
  citi: {
    canonicalDomains: ['citi.com', 'citibank.com', 'citigroup.com'],
    aliases: ['citibank', 'citigroup'],
    category: 'finance',
  },
  capitalone: {
    canonicalDomains: ['capitalone.com'],
    aliases: ['capital-one'],
    category: 'finance',
  },
  amex: {
    canonicalDomains: ['americanexpress.com', 'amex.com'],
    aliases: ['american-express'],
    category: 'finance',
  },
  discover: {
    canonicalDomains: ['discover.com', 'discovercard.com'],
    aliases: [],
    category: 'finance',
  },
  fidelity: {
    canonicalDomains: ['fidelity.com', 'fidelityinvestments.com'],
    aliases: [],
    category: 'finance',
  },
  vanguard: {
    canonicalDomains: ['vanguard.com'],
    aliases: [],
    category: 'finance',
  },
  schwab: {
    canonicalDomains: ['schwab.com', 'charlesschwab.com'],
    aliases: ['charles-schwab'],
    category: 'finance',
  },
  td_bank: {
    canonicalDomains: ['td.com', 'tdbank.com', 'tdbank.us'],
    aliases: ['td-bank', 'tdbank'],
    category: 'finance',
  },

  // ─── Tech ─────────────────────────────────────────────────────────────────
  google: {
    canonicalDomains: ['google.com', 'google.co.uk', 'google.de', 'google.fr', 'google.ca', 'google.com.au'],
    aliases: ['googl'],
    category: 'tech',
  },
  microsoft: {
    canonicalDomains: ['microsoft.com', 'microsoft365.com', 'live.com', 'outlook.com', 'office.com'],
    aliases: ['ms', 'm365'],
    category: 'tech',
  },
  apple: {
    canonicalDomains: ['apple.com', 'icloud.com'],
    aliases: [],
    category: 'tech',
  },
  amazon: {
    canonicalDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.in', 'amazon.fr'],
    aliases: ['amzn'],
    category: 'tech',
  },
  meta: {
    canonicalDomains: ['meta.com', 'meta.ai'],
    aliases: [],
    category: 'tech',
  },
  samsung: {
    canonicalDomains: ['samsung.com', 'samsung.com/us'],
    aliases: [],
    category: 'tech',
  },
  sony: {
    canonicalDomains: ['sony.com', 'sony.net'],
    aliases: [],
    category: 'tech',
  },
  nvidia: {
    canonicalDomains: ['nvidia.com', 'nvidia.cn'],
    aliases: [],
    category: 'tech',
  },
  ibm: {
    canonicalDomains: ['ibm.com'],
    aliases: [],
    category: 'tech',
  },

  // ─── Social Media ─────────────────────────────────────────────────────────
  facebook: {
    canonicalDomains: ['facebook.com', 'fb.com', 'fb.watch'],
    aliases: ['fb'],
    category: 'social',
  },
  instagram: {
    canonicalDomains: ['instagram.com'],
    aliases: ['insta', 'ig'],
    category: 'social',
  },
  twitter: {
    canonicalDomains: ['twitter.com', 'x.com'],
    aliases: ['x'],
    category: 'social',
  },
  linkedin: {
    canonicalDomains: ['linkedin.com', 'linkedin.jp'],
    aliases: [],
    category: 'social',
  },
  tiktok: {
    canonicalDomains: ['tiktok.com'],
    aliases: ['tt'],
    category: 'social',
  },
  snapchat: {
    canonicalDomains: ['snapchat.com'],
    aliases: ['snap'],
    category: 'social',
  },
  reddit: {
    canonicalDomains: ['reddit.com', 'redd.it'],
    aliases: [],
    category: 'social',
  },
  pinterest: {
    canonicalDomains: ['pinterest.com', 'pin.it'],
    aliases: ['pin'],
    category: 'social',
  },

  // ─── Cloud / SaaS ─────────────────────────────────────────────────────────
  aws: {
    canonicalDomains: ['aws.amazon.com', 'amazonaws.com', 'aws.com'],
    aliases: ['amazon-web-services'],
    category: 'cloud',
  },
  azure: {
    canonicalDomains: ['azure.com', 'microsoftazure.com'],
    aliases: [],
    category: 'cloud',
  },
  dropbox: {
    canonicalDomains: ['dropbox.com'],
    aliases: [],
    category: 'cloud',
  },
  slack: {
    canonicalDomains: ['slack.com'],
    aliases: [],
    category: 'cloud',
  },
  zoom: {
    canonicalDomains: ['zoom.us', 'zoom.com'],
    aliases: [],
    category: 'cloud',
  },
  salesforce: {
    canonicalDomains: ['salesforce.com', 'force.com', 'salesforce.it'],
    aliases: ['sf'],
    category: 'cloud',
  },
  adobe: {
    canonicalDomains: ['adobe.com', 'adobe.io'],
    aliases: [],
    category: 'cloud',
  },
  github: {
    canonicalDomains: ['github.com', 'github.io', 'github.dev'],
    aliases: [],
    category: 'cloud',
  },
  gitlab: {
    canonicalDomains: ['gitlab.com'],
    aliases: [],
    category: 'cloud',
  },
  notion: {
    canonicalDomains: ['notion.so', 'notion.site'],
    aliases: [],
    category: 'cloud',
  },

  // ─── Streaming / Entertainment ────────────────────────────────────────────
  netflix: {
    canonicalDomains: ['netflix.com'],
    aliases: ['nflx'],
    category: 'streaming',
  },
  spotify: {
    canonicalDomains: ['spotify.com'],
    aliases: [],
    category: 'streaming',
  },
  hulu: {
    canonicalDomains: ['hulu.com'],
    aliases: [],
    category: 'streaming',
  },
  disney: {
    canonicalDomains: ['disney.com', 'disneyplus.com', 'disney-plus.com'],
    aliases: ['disneyplus', 'disney-plus'],
    category: 'streaming',
  },
  youtube: {
    canonicalDomains: ['youtube.com', 'youtu.be', 'youtube-nocookie.com'],
    aliases: ['yt'],
    category: 'streaming',
  },
  twitch: {
    canonicalDomains: ['twitch.tv', 'twitch.com'],
    aliases: [],
    category: 'streaming',
  },

  // ─── Shopping ─────────────────────────────────────────────────────────────
  ebay: {
    canonicalDomains: ['ebay.com', 'ebay.co.uk', 'ebay.de'],
    aliases: [],
    category: 'shopping',
  },
  walmart: {
    canonicalDomains: ['walmart.com'],
    aliases: [],
    category: 'shopping',
  },
  target: {
    canonicalDomains: ['target.com'],
    aliases: [],
    category: 'shopping',
  },
  alibaba: {
    canonicalDomains: ['alibaba.com', 'alibaba.cloud'],
    aliases: [],
    category: 'shopping',
  },
  aliexpress: {
    canonicalDomains: ['aliexpress.com'],
    aliases: ['ali-express'],
    category: 'shopping',
  },
  etsy: {
    canonicalDomains: ['etsy.com'],
    aliases: [],
    category: 'shopping',
  },
  bestbuy: {
    canonicalDomains: ['bestbuy.com'],
    aliases: ['best-buy'],
    category: 'shopping',
  },

  // ─── Government / Postal ──────────────────────────────────────────────────
  irs: {
    canonicalDomains: ['irs.gov', 'irs.com'],
    aliases: ['internal-revenue-service'],
    category: 'government',
  },
  ssa: {
    canonicalDomains: ['ssa.gov', 'socialsecurity.gov'],
    aliases: ['social-security', 'socialsecurity'],
    category: 'government',
  },
  usps: {
    canonicalDomains: ['usps.com', 'usps.org'],
    aliases: ['us postal', 'postal-service'],
    category: 'government',
  },
  medicare: {
    canonicalDomains: ['medicare.gov'],
    aliases: [],
    category: 'government',
  },

  // ─── Shipping ─────────────────────────────────────────────────────────────
  fedex: {
    canonicalDomains: ['fedex.com'],
    aliases: ['fed-ex', 'fedex.com/us'],
    category: 'shipping',
  },
  ups: {
    canonicalDomains: ['ups.com', 'theupsstore.com'],
    aliases: ['united-parcel'],
    category: 'shipping',
  },
  dhl: {
    canonicalDomains: ['dhl.com', 'dhl.de', 'dhl.co.uk'],
    aliases: ['dhl-express'],
    category: 'shipping',
  },

  // ─── Telecom ──────────────────────────────────────────────────────────────
  verizon: {
    canonicalDomains: ['verizon.com', 'verizonwireless.com'],
    aliases: [],
    category: 'telecom',
  },
  att: {
    canonicalDomains: ['att.com', 'sbcglobal.net', 'att.net'],
    aliases: ['at-and-t', 'attwireless'],
    category: 'telecom',
  },
  tmobile: {
    canonicalDomains: ['t-mobile.com', 'tmobile.com'],
    aliases: ['t-mobile', 'tmobile'],
    category: 'telecom',
  },
  comcast: {
    canonicalDomains: ['comcast.com', 'xfinity.com'],
    aliases: ['xfinity'],
    category: 'telecom',
  },

  // ─── Gaming ───────────────────────────────────────────────────────────────
  roblox: {
    canonicalDomains: ['roblox.com'],
    aliases: [],
    category: 'gaming',
  },
  epicgames: {
    canonicalDomains: ['epicgames.com', 'epic-games.com'],
    aliases: ['epic-games', 'epicgames'],
    category: 'gaming',
  },
  steam: {
    canonicalDomains: ['steampowered.com', 'steamcommunity.com', 'store.steampowered.com'],
    aliases: ['valve', 'steampowered'],
    category: 'gaming',
  },
  playstation: {
    canonicalDomains: ['playstation.com', 'playstation.com/us', 'psn.com'],
    aliases: ['psn', 'sony-playstation'],
    category: 'gaming',
  },
};

// ── Derived Structures ──────────────────────────────────────────────────────────

/** Sorted array of all brand name keys (lowercase) */
const BRAND_NAMES = Object.keys(BRAND_DB).sort();

/**
 * Flat Set of every canonical domain across all brands.
 * Used for quick O(1) checks: "is this domain a known brand domain?"
 */
const ALL_CANONICAL_DOMAINS = new Set();
for (const brand of Object.values(BRAND_DB)) {
  for (const d of brand.canonicalDomains) {
    ALL_CANONICAL_DOMAINS.add(d.toLowerCase());
  }
}

// ── TLD Risk Map ───────────────────────────────────────────────────────────────

/**
 * Phishing prevalence–based risk scores for TLDs.
 * Derived from APWG eCrime reports and PhishTank statistics.
 *
 * 0.0  = low risk   (commonly used by legitimate businesses)
 * 0.3  = medium     (legitimate but occasionally abused)
 * 0.5  = medium-high (frequently seen in phishing)
 * 0.9  = very high  (free/cheap TLDs with minimal verification)
 */
const TLD_RISK_MAP = {
  // Very high risk — free or near-zero-cost TLDs with minimal registration verification
  tk: 0.9, ml: 0.9, ga: 0.9, cf: 0.9, gq: 0.9,

  // High risk — cheap bulk-registration TLDs heavily used in phishing
  xyz: 0.5, top: 0.5, buzz: 0.5, click: 0.5, work: 0.5,
  online: 0.5, site: 0.5, icu: 0.5, space: 0.5, club: 0.5,
  fun: 0.5, uno: 0.5, cam: 0.5, hair: 0.5, diy: 0.5,
  mov: 0.5, new: 0.5,

  // Medium risk — legitimate but occasionally abused
  info: 0.3, biz: 0.3, name: 0.3, mobi: 0.3,
  net: 0.3, org: 0.3,

  // Low-medium risk — ccTLDs with loose registration
  co: 0.1, me: 0.1, tv: 0.1, cc: 0.1, la: 0.1, im: 0.1,

  // Low risk — standard TLDs expected for legitimate brands
  com: 0.0,
};

// Country-code TLDs that are generally low risk but have some abuse
const LOW_RISK_CCTLS = new Set([
  'co.uk', 'co.nz', 'co.jp', 'co.kr', 'co.in', 'co.za',
  'de', 'fr', 'it', 'es', 'nl', 'be', 'at', 'ch', 'pl', 'se', 'no', 'dk', 'fi',
  'ca', 'au', 'nz', 'ie', 'sg', 'hk', 'jp', 'kr', 'tw',
  'gov', 'edu', 'mil',
]);

// ── Combosquatting Trust Keywords ──────────────────────────────────────────────

/**
 * Keywords commonly appended to brand names in combosquatting domains.
 * e.g., paypal-secure-login.com, google-account-verify.com
 */
const TRUST_KEYWORDS = new Set([
  'secure', 'security', 'login', 'signin', 'sign-in', 'signup', 'sign-up',
  'verify', 'verification', 'validate', 'validation',
  'update', 'upgrade', 'confirm', 'confirmation',
  'account', 'accounts', 'portal', 'auth', 'sso', 'sso-login',
  'billing', 'payment', 'checkout', 'wallet',
  'support', 'help', 'service', 'helpdesk', 'assist',
  'restore', 'recovery', 'recover', 'reset',
  'id', 'identity', 'pass', 'password', 'credentials',
  'online', 'web', 'app', 'mobile', 'm',
  'office', '365', 'workspace', 'cloud',
  'delivery', 'tracking', 'track', 'package', 'shipment',
  'tax', 'refund', 'benefits', 'claim', 'file',
]);

module.exports = {
  BRAND_DB,
  BRAND_NAMES,
  ALL_CANONICAL_DOMAINS,
  TLD_RISK_MAP,
  LOW_RISK_CCTLS,
  TRUST_KEYWORDS,
};
