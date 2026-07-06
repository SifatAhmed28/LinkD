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
 * Infers which brand a page is impersonating from its visible text and title.
 * Checks against BRAND_DOMAIN_MAP keys for any brand-name mention.
 *
 * @param {string} visibleText - Page body text
 * @param {string} title       - Page <title> content
 * @param {string} pageHostname - The hostname being scanned
 * @returns {{ inferred_brand: string|null, brand_domain_match: boolean|null }}
 */
function inferBrandFromPage(visibleText, title, pageHostname) {
  const searchText = `${title} ${visibleText}`.toLowerCase();
  const brands = Object.keys(BRAND_DOMAIN_MAP);

  for (const brand of brands) {
    if (searchText.includes(brand)) {
      const canonicalDomain = BRAND_DOMAIN_MAP[brand];
      // brand_domain_match: true if the actual page domain IS the brand's domain
      const brandDomainMatch = pageHostname === canonicalDomain ||
        pageHostname.endsWith('.' + canonicalDomain);
      return { inferred_brand: brand, brand_domain_match: brandDomainMatch };
    }
  }

  return { inferred_brand: null, brand_domain_match: null };
}

/**
 * Analyzes anchor tags for brand name vs. href domain mismatches.
 * Also infers the brand the page is impersonating from visible text and title.
 *
 * @param {Array<{href: string, text: string}>} anchors
 * @param {string} pageHostname - The hostname of the page being scanned
 * @param {string} [visibleText=''] - Page visible text (for brand inference)
 * @param {string} [title='']       - Page title (for brand inference)
 * @returns {{ mismatchFound: boolean, mismatchScore: number, mismatches: Array,
 *             inferred_brand: string|null, brand_domain_match: boolean|null }}
 */
function detectDomainMismatch(anchors, pageHostname, visibleText = '', title = '') {
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

  // Page-level brand inference from visible text + title
  const brandInference = inferBrandFromPage(visibleText, title, pageHostname);

  return {
    mismatchFound: mismatches.length > 0,
    mismatchScore: parseFloat(mismatchScore.toFixed(3)),
    mismatches: mismatches.slice(0, 10), // Cap at 10 for response size
    inferred_brand:    brandInference.inferred_brand,
    brand_domain_match: brandInference.brand_domain_match,
  };
}

module.exports = { detectDomainMismatch, inferBrandFromPage };
