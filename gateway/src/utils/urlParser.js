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
 * Uses word-boundary regex against the full brand database to avoid
 * false positives (e.g., "apple" inside "Snapple").
 *
 * @param {string} text
 * @returns {string|null}
 */
function extractBrandHint(text) {
  const { BRAND_DB, BRAND_NAMES } = require('../level2/brandDatabase');
  const lower = text.toLowerCase();

  // Try longest brand names first (more specific matches win)
  let bestMatch = null;
  let bestLen = 0;

  for (const brand of BRAND_NAMES) {
    const entry = BRAND_DB[brand];
    const variants = [brand, ...entry.aliases];

    for (const variant of variants) {
      if (variant.length < 3) continue;
      // Escape regex special chars and use word boundaries
      const escaped = variant.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(`\\b${escaped}\\b`, 'i');
      if (regex.test(lower) && variant.length > bestLen) {
        bestMatch = brand;
        bestLen = variant.length;
      }
    }
  }

  return bestMatch;
}

module.exports = { parseUrl, extractBrandHint };
