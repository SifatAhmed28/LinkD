const { parse } = require('tldts');
const { extractBrandHint } = require('../utils/urlParser');

// Known brands and their canonical domains
const BRAND_DOMAIN_MAP = {
  paypal: 'paypal.com',
  google: 'google.com',
  microsoft: 'microsoft.com',
  apple: 'apple.com',
  amazon: 'amazon.com',
  facebook: 'facebook.com',
  instagram: 'instagram.com',
  twitter: 'twitter.com',
  linkedin: 'linkedin.com',
  github: 'github.com',
  dropbox: 'dropbox.com',
  netflix: 'netflix.com',
  spotify: 'spotify.com',
  slack: 'slack.com',
  zoom: 'zoom.us',
  stripe: 'stripe.com',
  shopify: 'shopify.com',
  ebay: 'ebay.com',
  chase: 'chase.com',
  wellsfargo: 'wellsfargo.com',
  bankofamerica: 'bankofamerica.com',
};

/**
 * Analyzes anchor tags for brand name vs. href domain mismatches.
 * A mismatch means an anchor displays a brand name but points elsewhere.
 *
 * @param {Array<{href: string, text: string}>} anchors
 * @param {string} pageHostname - The hostname of the page being scanned
 * @returns {{ mismatchFound: boolean, mismatchScore: number, mismatches: Array }}
 */
function detectDomainMismatch(anchors, pageHostname) {
  const mismatches = [];

  for (const { href, text } of anchors) {
    if (!href || !text) continue;

    // Check if anchor text hints at a known brand
    const brandInText = extractBrandHint(text);
    if (!brandInText) continue;

    const expectedDomain = BRAND_DOMAIN_MAP[brandInText];
    if (!expectedDomain) continue;

    // Parse the href to get its registered domain
    let hrefDomain = null;
    try {
      // Handle relative URLs
      const fullUrl = href.startsWith('http')
        ? href
        : `https://${pageHostname}${href.startsWith('/') ? '' : '/'}${href}`;

      const { domain } = parse(fullUrl);
      hrefDomain = domain;
    } catch {
      continue;
    }

    if (!hrefDomain) continue;

    // If the link's domain doesn't match the expected brand domain → mismatch
    if (hrefDomain !== expectedDomain && !hrefDomain.endsWith(expectedDomain)) {
      mismatches.push({
        anchorText: text.substring(0, 100),
        href: href.substring(0, 200),
        expectedDomain,
        actualDomain: hrefDomain,
        brand: brandInText,
      });
    }
  }

  const mismatchScore = Math.min(mismatches.length * 0.3, 1.0);

  return {
    mismatchFound: mismatches.length > 0,
    mismatchScore: parseFloat(mismatchScore.toFixed(3)),
    mismatches: mismatches.slice(0, 10), // Cap at 10 for response size
  };
}

module.exports = { detectDomainMismatch };
