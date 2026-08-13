/**
 * domainMismatch.js — 6-Layer Phishing Domain Mismatch Detection
 *
 * Sophisticated detection of brand impersonation and domain-based phishing
 * indicators. Each layer produces a normalized signal (0–1) that feeds into
 * a composite mismatch score. The layered output is also exported as
 * structured features for the L3 ML model.
 *
 * Layers:
 *   1. Page-Level Brand Impersonation  (weight 0.35)
 *      — Does the page's own hostname contradict the brand it's displaying?
 *   2. Anchor-Level Text-vs-Href      (weight 0.25)
 *      — Do any <a> links say one brand but point to a different domain?
 *   3. Domain Fuzzy Similarity         (weight 0.20)
 *      — Is the hostname a typosquat of a known brand domain?
 *   4. Combosquatting Detection        (weight 0.10)
 *      — Is the hostname a brand name combined with trust keywords?
 *   5. Phonetic Similarity             (weight 0.05)
 *      — Does the hostname *sound like* a brand name?
 *   6. TLD Risk Assessment             (weight 0.05)
 *      — Is the TLD commonly abused in phishing?
 *
 * Backward-compatible: returns all original keys (mismatchFound, mismatchScore,
 * mismatches, inferred_brand, brand_domain_match) plus new layer-level signals.
 *
 * @module domainMismatch
 */

const { parse } = require('tldts');
const { phoneticallySimilar } = require('../utils/doubleMetaphone');
const {
  computeSimilarityScore,
  levenshteinDistance,
} = require('../utils/domainSimilarity');
const {
  BRAND_DB,
  BRAND_NAMES,
  ALL_CANONICAL_DOMAINS,
  TLD_RISK_MAP,
  LOW_RISK_CCTLS,
  TRUST_KEYWORDS,
} = require('./brandDatabase');

// ── Scoring Weights ────────────────────────────────────────────────────────────

const LAYER_WEIGHTS = {
  pageBrandMismatch:  0.35,
  anchorMismatch:     0.25,
  domainSimilarity:   0.20,
  combosquatting:     0.10,
  phoneticMatch:      0.05,
  tldRisk:            0.05,
};

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Word-boundary-aware brand extraction from text.
 * Uses regex word boundaries to avoid false positives like "apple" inside
 * "Snapple" or "facebook" inside "facebooking".
 *
 * @param {string} text
 * @returns {{ brand: string, startIndex: number } | null}
 */
function extractBrandFromText(text) {
  if (!text) return null;
  const lower = text.toLowerCase();

  // Try all brand names and aliases; prefer longer matches (more specific)
  let bestMatch = null;
  let bestLen = 0;

  for (const brand of BRAND_NAMES) {
    const entry = BRAND_DB[brand];
    const variants = [brand, ...entry.aliases];

    for (const variant of variants) {
      if (variant.length < 3) continue; // skip very short aliases to avoid noise

      const regex = new RegExp(`\\b${escapeRegex(variant)}\\b`, 'i');
      const match = regex.exec(lower);
      if (match && variant.length > bestLen) {
        bestMatch = { brand, startIndex: match.index };
        bestLen = variant.length;
      }
    }
  }

  return bestMatch;
}

/**
 * Extract ALL brand mentions from text (not just the first).
 * Returns deduplicated brand names.
 * @param {string} text
 * @returns {string[]}
 */
function extractAllBrandsFromText(text) {
  if (!text) return [];
  const lower = text.toLowerCase();
  const found = new Set();

  for (const brand of BRAND_NAMES) {
    const entry = BRAND_DB[brand];
    const variants = [brand, ...entry.aliases];

    for (const variant of variants) {
      if (variant.length < 3) continue;
      const regex = new RegExp(`\\b${escapeRegex(variant)}\\b`, 'i');
      if (regex.test(lower)) {
        found.add(brand);
        break;
      }
    }
  }

  return [...found];
}

/**
 * Escape special regex characters in a string.
 * @param {string} str
 * @returns {string}
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Get the TLD from a hostname.
 * @param {string} hostname
 * @returns {string} — e.g., "com", "co.uk", "tk"
 */
function extractTld(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 1) return '';

  // Check for compound TLDs (co.uk, com.au, etc.)
  const twoPart = parts.slice(-2).join('.');
  if (LOW_RISK_CCTLS.has(twoPart)) return twoPart;

  return parts[parts.length - 1];
}

// ══════════════════════════════════════════════════════════════════════════════
//  LAYER 1 — Page-Level Brand Impersonation
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Infer brand from page content and check if the hostname is actually
 * the brand's legitimate domain.
 *
 * @param {string} visibleText
 * @param {string} title
 * @param {string[]} imageAlts
 * @param {string} metaDescription
 * @param {string} hostname — the hostname being scanned
 * @param {string} registeredDomain
 * @returns {{ inferred_brand: string|null, brand_domain_match: boolean|null,
 *             page_brand_mismatch: number, subdomain_spoofing: boolean }}
 */
function layer1_pageBrandImpersonation(visibleText, title, imageAlts, metaDescription, hostname, registeredDomain) {
  // Combine all text signals for brand inference
  const combinedText = `${title} ${visibleText} ${(imageAlts || []).join(' ')} ${metaDescription || ''}`;
  const brandsInPage = extractAllBrandsFromText(combinedText);

  if (brandsInPage.length === 0) {
    return {
      inferred_brand: null,
      brand_domain_match: null,
      page_brand_mismatch: 0,
      subdomain_spoofing: false,
    };
  }

  // Use the most prominent brand (longest match wins in extractAllBrands)
  // Re-derive with priority: check combinedText more carefully
  const primaryBrand = brandsInPage[0];
  const brandEntry = BRAND_DB[primaryBrand];
  const canonicalDomains = brandEntry.canonicalDomains.map((d) => d.toLowerCase());

  // Check if hostname IS the brand's domain
  const hostLower = hostname.toLowerCase();
  const regDomLower = registeredDomain.toLowerCase();

  const isCanonical = canonicalDomains.some(
    (d) => hostLower === d || hostLower.endsWith('.' + d) || regDomLower === d
  );

  // Subdomain spoofing: brand appears as a subdomain of a non-brand domain
  // e.g., paypal.evil.com, paypal-secure.github.io, microsoft.fraud.net
  let subdomainSpoofing = false;
  if (!isCanonical) {
    const hostParts = hostLower.split('.');
    const brandTokens = [primaryBrand, ...brandEntry.aliases];
    subdomainSpoofing = hostParts.some((part) => {
      const cleanPart = part.replace(/[-_0-9]/g, '');
      return brandTokens.some((token) => {
        const cleanToken = token.replace(/[-_0-9]/g, '');
        return (
          part === token ||
          cleanPart === cleanToken ||
          cleanPart.startsWith(cleanToken) ||  // paypal-secure → starts with paypal
          cleanPart.endsWith(cleanToken)         // secure-paypal → ends with paypal
        );
      });
    });
  }

  // Compute mismatch score
  let pageBrandMismatch = 0;

  if (isCanonical) {
    // Legitimate — no mismatch
    pageBrandMismatch = 0;
  } else if (subdomainSpoofing) {
    // Brand used as subdomain of non-brand = very high confidence phishing
    pageBrandMismatch = 0.95;
  } else if (hostLower.includes(primaryBrand) && !isCanonical) {
    // Brand appears in hostname but it's NOT the canonical domain
    // e.g., paypal-login.com, secure-microsoft.net
    pageBrandMismatch = 0.85;
  } else {
    // Page content displays brand X, but hostname is completely unrelated
    // Score based on how many brand signals are present (more = more suspicious)
    const brandSignalCount = brandsInPage.length;
    pageBrandMismatch = Math.min(0.4 + brandSignalCount * 0.15, 0.9);
  }

  return {
    inferred_brand: primaryBrand,
    brand_domain_match: isCanonical,
    page_brand_mismatch: parseFloat(pageBrandMismatch.toFixed(3)),
    subdomain_spoofing: subdomainSpoofing,
    _allBrandsInPage: brandsInPage, // internal, not exported
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LAYER 2 — Anchor-Level Brand vs. Href Domain Mismatch
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Analyze <a> tags: does the anchor text suggest a brand but the href
 * points to a different, potentially malicious domain?
 *
 * Improvements over the original:
 *   - Word-boundary-aware brand extraction (no false positives)
 *   - Deduplication by (brand, actualDomain)
 *   - Severity weighting per mismatch (based on target domain trust)
 *   - Relative URL handling
 *
 * @param {Array<{href: string, text: string}>} anchors
 * @param {string} pageHostname
 * @returns {{ mismatchScore: number, mismatches: Array, anchorMatchCount: number }}
 */
function layer2_anchorMismatch(anchors, pageHostname) {
  const mismatches = [];
  const seen = new Set(); // dedup key: "brand::domain"

  for (const { href, text } of anchors) {
    if (!href || !text) continue;

    const brandResult = extractBrandFromText(text);
    if (!brandResult) continue;

    const { brand } = brandResult;
    const brandEntry = BRAND_DB[brand];
    const expectedDomains = brandEntry.canonicalDomains.map((d) => d.toLowerCase());

    // Parse the href
    let hrefDomain = null;
    try {
      const fullUrl = href.startsWith('http')
        ? href
        : `https://${pageHostname}${href.startsWith('/') ? '' : '/'}${href}`;
      const { domain } = parse(fullUrl);
      hrefDomain = domain ? domain.toLowerCase() : null;
    } catch {
      continue;
    }
    if (!hrefDomain) continue;

    // Check if href domain matches any canonical domain for the brand
    const isExpected = expectedDomains.some(
      (d) => hrefDomain === d || hrefDomain.endsWith('.' + d)
    );
    if (isExpected) continue;

    // Dedup
    const dedupKey = `${brand}::${hrefDomain}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    // Compute severity for this mismatch
    let severity = 0.5; // default
    if (ALL_CANONICAL_DOMAINS.has(hrefDomain)) {
      // Link points to a DIFFERENT known brand — less suspicious (could be legitimate cross-link)
      severity = 0.2;
    } else if (hrefDomain.endsWith('.github.io') || hrefDomain.endsWith('.vercel.app') ||
               hrefDomain.endsWith('.netlify.app') || hrefDomain.endsWith('.web.app')) {
      // Free hosting platform — common in phishing
      severity = 0.7;
    } else if (hrefDomain.includes(brand)) {
      // Brand name in a non-canonical domain — strong phishing signal
      severity = 0.9;
    }

    mismatches.push({
      anchorText: text.substring(0, 100),
      href: href.substring(0, 200),
      expectedDomain: expectedDomains[0],
      actualDomain: hrefDomain,
      brand,
      severity,
    });
  }

  // Score: weighted by severity, diminishing returns after 3 mismatches
  let score = 0;
  const sortedBySeverity = mismatches.sort((a, b) => b.severity - a.severity);
  for (let i = 0; i < sortedBySeverity.length; i++) {
    const weight = i < 3 ? 1.0 : 0.3; // diminishing returns
    score += sortedBySeverity[i].severity * weight;
  }
  const normalizedScore = Math.min(score / 2.5, 1.0); // normalize to [0,1]

  return {
    mismatchScore: parseFloat(normalizedScore.toFixed(3)),
    mismatches: mismatches.slice(0, 10), // cap for response size
    anchorMatchCount: mismatches.length,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LAYER 3 — Domain Fuzzy Similarity (Typosquatting Detection)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Detect typosquatting by computing edit distance and Jaro-Winkler similarity
 * between the hostname and all known brand domains.
 *
 * A high similarity score combined with a non-canonical domain = likely phishing.
 *
 * @param {string} registeredDomain
 * @param {string} inferredBrand — from Layer 1 (if available)
 * @returns {{ domain_edit_distance: number, domain_similarity_score: number,
 *             closest_brand: string|null, similarity_layer_score: number }}
 */
function layer3_domainSimilarity(registeredDomain, inferredBrand) {
  if (!registeredDomain) {
    return {
      domain_edit_distance: -1,
      domain_similarity_score: 0,
      closest_brand: null,
      similarity_layer_score: 0,
    };
  }

  // If we know the brand from Layer 1, prioritize that brand's domains
  let brandToCheck = inferredBrand;
  let domainsToCheck = [];

  if (brandToCheck && BRAND_DB[brandToCheck]) {
    domainsToCheck = BRAND_DB[brandToCheck].canonicalDomains;
  }

  // Also check ALL brand domains to find the closest match regardless
  // (catches cases where the brand inference might be wrong)
  const allBrandDomains = [];
  for (const [brand, entry] of Object.entries(BRAND_DB)) {
    for (const d of entry.canonicalDomains) {
      allBrandDomains.push({ domain: d, brand });
    }
  }

  let bestResult = {
    editDistance: Infinity,
    similarityScore: 0,
    lcsRatio: 0,
    closestBrand: null,
    closestBrandKey: null,
  };

  for (const { domain: brandDomain, brand } of allBrandDomains) {
    // Compare against the registered domain (without TLD for cleaner comparison)
    const hostLabel = registeredDomain.split('.')[0].toLowerCase();
    const brandLabel = brandDomain.split('.')[0].toLowerCase();

    // Skip trivial comparisons
    if (hostLabel === brandLabel) {
      // Exact match — this IS the brand domain, not a typosquat
      bestResult = {
        editDistance: 0,
        similarityScore: 1.0,
        lcsRatio: 1.0,
        closestBrand: brandDomain,
        closestBrandKey: brand,
      };
      break;
    }

    const result = computeSimilarityScore(registeredDomain, [brandDomain], brand);
    if (result.similarityScore > bestResult.similarityScore) {
      bestResult = { ...result, closestBrandKey: brand };
    }
  }

  // The layer score: how suspicious is this similarity?
  // High similarity to a brand + not being the brand itself = suspicious
  let layerScore = 0;
  if (bestResult.closestBrandKey && bestResult.similarityScore > 0.7) {
    // Check if this domain IS the canonical domain for that brand
    const isCanonical = BRAND_DB[bestResult.closestBrandKey]?.canonicalDomains
      .some((d) => d.toLowerCase() === registeredDomain.toLowerCase());

    if (!isCanonical) {
      // Close to a brand but NOT the brand — likely typosquatting
      // Scale: 0.7 → ~0.3, 0.85 → ~0.7, 1.0 → 1.0
      layerScore = Math.pow((bestResult.similarityScore - 0.7) / 0.3, 1.5);
      layerScore = Math.min(Math.max(layerScore, 0), 1.0);
    }
  }

  return {
    domain_edit_distance: bestResult.editDistance === Infinity ? -1 : bestResult.editDistance,
    domain_similarity_score: parseFloat(bestResult.similarityScore.toFixed(4)),
    closest_brand: bestResult.closestBrand,
    similarity_layer_score: parseFloat(layerScore.toFixed(3)),
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LAYER 4 — Combosquatting Detection
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Detect combosquatting: brand name combined with trust-inducing keywords
 * in the hostname. e.g., paypal-secure-login.com, google-account-verify.net
 *
 * @param {string} hostname
 * @param {string|null} inferredBrand — from Layer 1
 * @returns {{ combosquatting_detected: boolean, combosquatting_score: number,
 *             combosquatting_pattern: string|null }}
 */
function layer4_combosquatting(hostname, inferredBrand) {
  if (!hostname) {
    return { combosquatting_detected: false, combosquatting_score: 0, combosquatting_pattern: null };
  }

  // Tokenize the hostname: split on non-alphanumeric
  const tokens = hostname.toLowerCase().split(/[^a-z0-9]/).filter(Boolean);

  // Find which tokens are brand names
  const brandTokens = [];
  const otherTokens = [];

  for (const token of tokens) {
    if (BRAND_DB[token]) {
      brandTokens.push(token);
    } else {
      otherTokens.push(token);
    }
  }

  // Also check partial matches (e.g., "paypal" inside "paypal-login")
  if (brandTokens.length === 0 && inferredBrand) {
    const hostLower = hostname.toLowerCase();
    if (hostLower.includes(inferredBrand)) {
      brandTokens.push(inferredBrand);
    }
  }

  if (brandTokens.length === 0) {
    return { combosquatting_detected: false, combosquatting_score: 0, combosquatting_pattern: null };
  }

  // Check how many trust keywords appear among the other tokens
  const trustHits = otherTokens.filter((t) => TRUST_KEYWORDS.has(t));

  if (trustHits.length === 0) {
    return { combosquatting_detected: false, combosquatting_score: 0, combosquatting_pattern: null };
  }

  // Combosquatting detected! Score based on number of trust keywords
  const score = Math.min(0.5 + trustHits.length * 0.2, 1.0);
  const pattern = `${brandTokens.join(' + ')} + ${trustHits.join(' + ')}`;

  return {
    combosquatting_detected: true,
    combosquatting_score: parseFloat(score.toFixed(3)),
    combosquatting_pattern: pattern,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LAYER 5 — Phonetic Similarity
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Detect domains that phonetically resemble known brand names.
 * Uses Double Metaphone encoding comparison.
 *
 * @param {string} hostname
 * @param {string|null} inferredBrand — from Layer 1
 * @returns {{ phonetic_match: boolean, phonetic_brand: string|null, phonetic_layer_score: number }}
 */
function layer5_phoneticMatch(hostname, inferredBrand) {
  if (!hostname) {
    return { phonetic_match: false, phonetic_brand: null, phonetic_layer_score: 0 };
  }

  const hostLabel = hostname.split('.')[0].toLowerCase();
  // Remove digits and hyphens for cleaner phonetic comparison
  const cleanLabel = hostLabel.replace(/[-_0-9]/g, '');

  if (cleanLabel.length < 3) {
    return { phonetic_match: false, phonetic_brand: null, phonetic_layer_score: 0 };
  }

  // If brand is known, only check that brand (fast path)
  if (inferredBrand && BRAND_DB[inferredBrand]) {
    const brandClean = inferredBrand.replace(/[_-]/g, '');
    // Only check if the strings are different but might sound alike
    if (cleanLabel !== brandClean) {
      if (phoneticallySimilar(cleanLabel, brandClean)) {
        return {
          phonetic_match: true,
          phonetic_brand: inferredBrand,
          phonetic_layer_score: 0.8,
        };
      }
    }
    return { phonetic_match: false, phonetic_brand: null, phonetic_layer_score: 0 };
  }

  // No known brand — check against all brands (slower but thorough)
  for (const brand of BRAND_NAMES) {
    const brandClean = brand.replace(/[_-]/g, '');
    if (cleanLabel !== brandClean && phoneticallySimilar(cleanLabel, brandClean)) {
      return {
        phonetic_match: true,
        phonetic_brand: brand,
        phonetic_layer_score: 0.7,
      };
    }
  }

  return { phonetic_match: false, phonetic_brand: null, phonetic_layer_score: 0 };
}

// ══════════════════════════════════════════════════════════════════════════════
//  LAYER 6 — TLD Risk Assessment
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Assess the risk level of the TLD used by the hostname.
 *
 * @param {string} hostname
 * @returns {{ tld_risk_score: number, suspicious_tld: boolean, tld: string }}
 */
function layer6_tldRisk(hostname) {
  if (!hostname) {
    return { tld_risk_score: 0, suspicious_tld: false, tld: '' };
  }

  const tld = extractTld(hostname);
  const riskScore = TLD_RISK_MAP[tld] !== undefined ? TLD_RISK_MAP[tld] : 0.1;
  const suspicious = riskScore >= 0.3;

  return {
    tld_risk_score: riskScore,
    suspicious_tld: suspicious,
    tld,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  Main Export: detectDomainMismatch
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Analyze a page for brand impersonation and domain-based phishing signals.
 *
 * @param {Array<{href: string, text: string}>} anchors — parsed <a> tags
 * @param {string}   pageHostname      — hostname being scanned
 * @param {string}   [visibleText='']  — page body text
 * @param {string}   [title='']        — page <title>
 * @param {string[]} [imageAlts=[]]    — alt text from <img> tags
 * @param {string}   [metaDescription=''] — meta description content
 * @param {Object}   [parsedUrl]       — output of urlParser.parseUrl() (optional)
 *
 * @returns {Object} Backward-compatible result with additional layer signals.
 */
function detectDomainMismatch(anchors, pageHostname, visibleText = '', title = '', imageAlts = [], metaDescription = '', parsedUrl = null) {
  const registeredDomain = parsedUrl?.registeredDomain || pageHostname;

  // ── Layer 1: Page-Level Brand Impersonation ─────────────────────────────
  const L1 = layer1_pageBrandImpersonation(
    visibleText, title, imageAlts, metaDescription, pageHostname, registeredDomain
  );

  // ── Layer 2: Anchor-Level Mismatch ──────────────────────────────────────
  const L2 = layer2_anchorMismatch(anchors, pageHostname);

  // ── Layer 3: Domain Fuzzy Similarity ────────────────────────────────────
  const L3 = layer3_domainSimilarity(registeredDomain, L1.inferred_brand);

  // ── Layer 4: Combosquatting ─────────────────────────────────────────────
  const L4 = layer4_combosquatting(pageHostname, L1.inferred_brand);

  // ── Layer 5: Phonetic Similarity ────────────────────────────────────────
  const L5 = layer5_phoneticMatch(pageHostname, L1.inferred_brand);

  // ── Layer 6: TLD Risk ──────────────────────────────────────────────────
  const L6 = layer6_tldRisk(pageHostname);

  // ── Composite Score ────────────────────────────────────────────────────
  const mismatchScore = parseFloat(Math.min(
    L1.page_brand_mismatch   * LAYER_WEIGHTS.pageBrandMismatch +
    L2.mismatchScore         * LAYER_WEIGHTS.anchorMismatch +
    L3.similarity_layer_score * LAYER_WEIGHTS.domainSimilarity +
    L4.combosquatting_score  * LAYER_WEIGHTS.combosquatting +
    L5.phonetic_layer_score  * LAYER_WEIGHTS.phoneticMatch +
    L6.tld_risk_score        * LAYER_WEIGHTS.tldRisk,
    1.0
  ).toFixed(3));

  // ── Backward-compatible return ─────────────────────────────────────────
  return {
    // Original keys (backward compatibility)
    mismatchFound: mismatchScore > 0,
    mismatchScore,
    mismatches: L2.mismatches,
    inferred_brand: L1.inferred_brand,
    brand_domain_match: L1.brand_domain_match,

    // New layer-level signals
    page_brand_mismatch: L1.page_brand_mismatch,
    subdomain_spoofing: L1.subdomain_spoofing,
    anchor_mismatch_count: L2.anchorMatchCount,
    domain_edit_distance: L3.domain_edit_distance,
    domain_similarity_score: L3.domain_similarity_score,
    closest_brand: L3.closest_brand,
    combosquatting_detected: L4.combosquatting_detected,
    combosquatting_pattern: L4.combosquatting_pattern,
    phonetic_match: L5.phonetic_match,
    phonetic_brand: L5.phonetic_brand,
    tld_risk_score: L6.tld_risk_score,
    suspicious_tld: L6.suspicious_tld,
  };
}

module.exports = { detectDomainMismatch, extractBrandFromText };
