const { URL } = require('url');
const { parse } = require('tldts');

/**
 * Normalizes and parses a URL into its components.
 * @param {string} rawUrl
 * @returns {{ href, protocol, hostname, pathname, search, registeredDomain, subdomain, isIP }}
 */
function parseUrl(rawUrl) {
  let href = rawUrl.trim();

  // Add protocol if missing
  if (!/^https?:\/\//i.test(href)) {
    href = 'https://' + href;
  }

  const parsed = new URL(href);
  const tld = parse(parsed.hostname);

  return {
    href: parsed.href,
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    pathname: parsed.pathname,
    search: parsed.search,
    params: Object.fromEntries(parsed.searchParams),
    registeredDomain: tld.domain || parsed.hostname,
    subdomain: tld.subdomain || '',
    isIP: /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname),
    isLocalhost: parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
  };
}

/**
 * Extracts the brand name heuristically from a URL or text string.
 * @param {string} text
 * @returns {string|null}
 */
function extractBrandHint(text) {
  const knownBrands = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'instagram', 'twitter', 'linkedin', 'github', 'dropbox', 'netflix',
    'spotify', 'slack', 'zoom', 'stripe', 'shopify', 'ebay'
  ];
  const lower = text.toLowerCase();
  return knownBrands.find((b) => lower.includes(b)) || null;
}

module.exports = { parseUrl, extractBrandHint };
