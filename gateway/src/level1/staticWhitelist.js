const logger = require('../utils/logger');

// ── Trusted top-level domains (fast-path SAFE — no L2/L3 needed) ──────────────
// These are canonical, brand-owned registered domains.
// Subdomains (e.g. evil.google.com) are NOT trusted via this set —
// they are caught by the WILDCARD_HOSTING guard below and sent to L2.
const TRUSTED_DOMAINS = new Set([
  // Search / Productivity
  'google.com', 'google.co.uk', 'google.ca', 'google.com.au',
  'youtube.com', 'gmail.com', 'googlemail.com', 'googleapis.com',

  // Microsoft
  'microsoft.com', 'outlook.com', 'hotmail.com', 'live.com',
  'office.com', 'office365.com', 'microsoftonline.com',
  'azure.com', 'bing.com', 'xbox.com',

  // Apple
  'apple.com', 'icloud.com',

  // Meta
  'facebook.com', 'fb.com', 'instagram.com', 'messenger.com',
  'whatsapp.com', 'meta.com',

  // Amazon
  'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
  'amazon.ca', 'amazon.com.au', 'aws.amazon.com', 'amazonaws.com',

  // Developer / Code
  'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'stackoverflow.com', 'stackexchange.com', 'npmjs.com', 'pypi.org',

  // Social / Media
  'twitter.com', 'x.com', 'linkedin.com', 'reddit.com', 'pinterest.com',
  'tiktok.com', 'snapchat.com', 'discord.com', 'twitch.tv',

  // Payments / Finance
  'paypal.com', 'stripe.com', 'square.com', 'venmo.com',
  'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citi.com',
  'capitalone.com', 'americanexpress.com',

  // Entertainment / Streaming
  'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com',
  'primevideo.com', 'twitch.tv',

  // Cloud / Infra
  'cloudflare.com', 'vercel.com', 'netlify.com', 'heroku.com',
  'digitalocean.com', 'linode.com', 'fastly.com',

  // Commerce / SaaS
  'shopify.com', 'ebay.com', 'etsy.com', 'alibaba.com',
  'salesforce.com', 'hubspot.com', 'zendesk.com', 'atlassian.com',
  'slack.com', 'zoom.us', 'dropbox.com', 'box.com', 'notion.so',

  // News / Reference
  'wikipedia.org', 'wikimedia.org',
  'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com',

  // Government / Education (generic TLDs)
  // Not enumerated here — .gov / .edu TLDs are handled by TLD check if desired
]);

// ── Wildcard hosting platforms ─────────────────────────────────────────────────
// Subdomains on these platforms are controlled by arbitrary users — they must NOT
// be trusted even if the root domain appears in a whitelist.
// Any URL on these platforms is sent to L2 with whitelistPartialMatch=true.
const WILDCARD_HOSTING = new Set([
  // Git hosting / Pages
  'github.io', 'gitlab.io', 'bitbucket.io',

  // Vercel / Netlify / Cloudflare
  'vercel.app', 'netlify.app', 'netlify.live', 'pages.dev', 'workers.dev',

  // Firebase / Google
  'firebaseapp.com', 'web.app', 'appspot.com',

  // Microsoft Azure
  'azurewebsites.net', 'azurestaticapps.net', 'cloudapp.net',

  // AWS
  'amazonaws.com', 'elasticbeanstalk.com', 'amplifyapp.com',

  // Oracle / IBM
  'oraclecloud.com', 'mybluemix.net',

  // Railway / Render / Fly
  'onrender.com', 'railway.app', 'fly.dev', 'fly.io',

  // Heroku
  'herokuapp.com', 'herokudns.com',

  // DigitalOcean
  'ondigitalocean.app',

  // Glitch / Replit / Codespaces
  'glitch.me', 'replit.app', 'repl.co', 'replit.dev', 'githubpreview.dev',

  // Cloud IDEs
  'gitpod.io', 'codesandbox.io', 'stackblitz.io',

  // Surge / Static hosting
  'surge.sh', 'pages.fm', 'tiiny.site',

  // Free hosting
  'epizy.com', 'rf.gd', '42web.io', 'infy.uk', 'free.nf',
  '000webhostapp.com',

  // Blogger / Wordpress
  'blogspot.com', 'wordpress.com',

  // Wix / Weebly / Squarespace
  'wixsite.com', 'weebly.com', 'square.site',

  // Google Sites / Notion
  'sites.google.com', 'notion.site',

  // Low-code / No-code
  'carrd.co', 'tilda.ws', 'webflow.io', 'bubbleapps.io', 'softr.app',
  'framer.website', 'framer.app', 'typedream.app', 'webnode.page',
  'mystrikingly.com', 'jimdosite.com', 'cargo.site',

  // Docs / Dev platforms
  'readthedocs.io', 'gitbook.io', 'hashnode.dev', 'hashnode.com',
  'dev.to', 'codeberg.page', 'sourcehut.io',

  // CMS / Blogging
  'myshopify.com', 'tumblr.com', 'medium.com', 'substack.com',
  'ghost.io',

  // Misc cloud
  'neocities.org', 'glitch.global', 'pantheonsite.io', 'kinsta.cloud',
  'zeabur.app', 'northflank.app', 'cyclic.app', 'deno.dev',
  'edgeone.app',

  // IPFS gateways
  'ipfs.dweb.link', 'ipfs.cf-ipfs.com',

  // Tunnel services (very high risk)
  'loca.lt', 'serveo.net', 'trycloudflare.com', 'ngrok-free.app',

  // Dynamic DNS (high phishing abuse)
  'duckdns.org', 'ddns.net', 'hopto.org', 'zapto.org',
  'serveftp.net', 'sytes.net', 'dynu.net', 'mywire.org',
  'mooo.com', 'dyndns.org', 'homeip.net', 'duckdns.info',

  // Misc free hosting
  'yolasite.com', 'hstgr.io', 'easywp.com', 'zohosites.com',
  'pythonanywhere.com', 'alwaysdata.net', 'awardspace.info',
  'altervista.org', 'byethost.com', 'hostingerapp.com',
  'lovestoblog.com', 'great-site.net',
  'hoppy.jp', 'pagexl.com',
]);

/**
 * Checks whether a hostname/domain should be fast-pathed as SAFE (Level 1),
 * flagged as a wildcard hosting platform (→ L2), or treated as unknown (→ L2).
 *
 * @param {string} hostname        - Full hostname (e.g. "paypal.com", "evil.github.io")
 * @param {string} registeredDomain - Registered domain from tldts (e.g. "github.io")
 * @returns {{ fastPath: boolean, whitelistPartialMatch: boolean, isWildcardHosting?: boolean }}
 */
function trustScore(hostname, registeredDomain) {
  const domainToCheck = registeredDomain || hostname;

  // 1. Wildcard hosting check (takes priority — even if root is "trusted")
  if (WILDCARD_HOSTING.has(domainToCheck)) {
    logger.info(`⚠️  Wildcard hosting domain: ${domainToCheck} — sending to L2`);
    return {
      fastPath: false,
      whitelistPartialMatch: true,
      isWildcardHosting: true,
    };
  }

  // 2. Trusted domain exact match
  if (TRUSTED_DOMAINS.has(domainToCheck)) {
    logger.info(`✅ L1 Trusted domain HIT: ${domainToCheck}`);
    return {
      fastPath: true,
      whitelistPartialMatch: false,
    };
  }

  // 3. Unknown — proceed to L2
  return {
    fastPath: false,
    whitelistPartialMatch: false,
  };
}

module.exports = { trustScore, TRUSTED_DOMAINS, WILDCARD_HOSTING };