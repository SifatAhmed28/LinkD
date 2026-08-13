/**
 * Feature Schema Version
 *
 * Increment this constant whenever the shape of the L2 feature vector changes
 * (new keys added, keys removed, or semantics of existing keys change).
 *
 * Redis cache entries with a different cache_version are treated as misses,
 * forcing a fresh scan so stale feature shapes never reach L3.
 */
const FEATURE_SCHEMA_VERSION = 2;

/**
 * Canonical ordered list of every feature key in the L2 feature vector.
 * Used for documentation and future ML training data export.
 *
 * Grouped by source module:
 *   PATTERN  — patternDetector.js
 *   MISMATCH — domainMismatch.js
 *   OBFUSC   — urlObfuscation.js  (structural URL features)
 *   HTML     — htmlParser.js  (phishing-kit fingerprints)
 *   FORM     — scan.js form-behavior checks
 *   GITHUB   — githubContext.js
 *   WHOIS    — whoisFeatures.js  (Phase 2)
 *   RANK     — domainRankFeatures.js  (Phase 2)
 *   META     — scan-level signals (fetchFailed, httpsDowngrade, …)
 */
const FEATURE_KEYS = [
  // PATTERN
  'urgencyScore',
  'fearDetected',
  'credentialDetected',

  // MISMATCH — domainMismatch.js (6-layer detection)
  'domainMismatch',              // Composite mismatch score (0–1)
  'inferred_brand',              // Brand name inferred from page content
  'brand_domain_match',          // Boolean: page hostname IS the brand's canonical domain
  'page_brand_mismatch',         // Layer 1: page hostname vs inferred brand (0–1)
  'subdomain_spoofing',          // Layer 1: brand as subdomain of non-brand domain
  'closest_brand',               // Layer 3: brand domain most similar to hostname
  'domain_edit_distance',        // Layer 3: Levenshtein distance to closest brand domain
  'domain_similarity_score',     // Layer 3: Jaro-Winkler + LCS similarity (0–1)
  'combosquatting_detected',     // Layer 4: brand + trust keywords in hostname
  'phonetic_match',              // Layer 5: hostname phonetically resembles a brand
  'tld_risk_score',              // Layer 6: TLD phishing risk score (0–1)

  // OBFUSC — existing scalar
  'urlObfuscation',
  // OBFUSC — new structural
  'url_entropy',
  'url_digit_ratio',
  'url_letter_ratio',
  'url_num_dots',
  'url_num_slashes',
  'url_num_hyphens',
  'url_num_equals',
  'url_num_question',
  'url_num_ampersand',
  'url_num_percent',
  'url_num_double_slash',
  'url_num_sensitive_words',
  'url_has_at_symbol',
  'url_prefix_suffix_hyphen',

  // HTML — phishing-kit fingerprints
  'html_num_eval_calls',
  'html_num_unescape_calls',
  'html_has_right_click_disabled',
  'sfh_is_empty',
  'sfh_is_about_blank',
  'html_has_favicon',
  'html_num_hidden_inputs',

  // FORM
  'formPassword',
  'crossOriginForm',
  'httpsDowngrade',

  // GITHUB
  'githubNewRepo',
  'githubFewCommits',
  'githubPasswordInReadme',

  // META
  'ipBasedUrl',
  'fetchFailed',
  'whitelistPartialMatch',  // Phase 3 (staticWhitelist.js extension)

  // WHOIS (Phase 2 — null until whoisFeatures.js is wired in)
  'domain_age_days',
  'domain_expiry_days',
  'days_since_last_update',
  'registrar_category',
  'has_registrant_org',
  'has_registrant_email',
  'has_registrant_phone',
  'domain_name_match',

  // RANK (Phase 2 — null until domainRankFeatures.js is wired in)
  'tranco_in_top10k',
  'tranco_rank_bucket',
];

module.exports = { FEATURE_SCHEMA_VERSION, FEATURE_KEYS };
