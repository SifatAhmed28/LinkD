const { parse } = require('tldts');

// ── Shannon Entropy ────────────────────────────────────────────────────────────
/**
 * Computes the Shannon entropy of a string (bits per character).
 * High entropy → random/DGA-style strings common in phishing URLs.
 * @param {string} str
 * @returns {number}
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

// ── Sensitive words that appear in phishing URL paths / subdomains ─────────────
const URL_SENSITIVE_WORDS = ['secure', 'account', 'verify', 'update', 'login', 'banking'];

// ── Known URL Shortener Domains ───────────────────────────────────────────────
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'buff.ly',
  'ift.tt', 'dlvr.it', 'su.pr', 'bl.ink', 'rebrand.ly', 'short.io',
  'cutt.ly', 'rb.gy', 'is.gd', 'v.gd', 'cli.gs', 'yfrog.com',
  'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'tr.im', 'twurl.nl',
  'snipurl.com', 'short.to', 'budurl.com', 'ping.fm', 'post.ly',
  'just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
  'doiop.com', 'disq.us', 'deck.ly', 'link.ly', 'mcaf.ee',
]);

// ── IDN Homograph Detection (Punycode) ────────────────────────────────────────
// Domains that appear visually similar to trusted brands using unicode chars
const IDN_PREFIX = 'xn--';

// ── Base64 Regex (URL-safe or standard) ───────────────────────────────────────
const BASE64_REGEX = /(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/;
const BASE64_URL_REGEX = /[A-Za-z0-9_-]{20,}/; // URL-safe base64

/**
 * Decodes a Base64 or Base64URL string safely.
 * @param {string} str
 * @returns {string|null}
 */
function tryBase64Decode(str) {
  try {
    const padded = str.padEnd(Math.ceil(str.length / 4) * 4, '=');
    const decoded = Buffer.from(padded, 'base64').toString('utf-8');
    // Only return if it looks like readable text or a URL
    if (/^[\x20-\x7E]+$/.test(decoded)) return decoded;
    return null;
  } catch {
    return null;
  }
}

/**
 * Analyzes a URL for obfuscation indicators.
 *
 * @param {string} url - The full URL string
 * @param {Object} parsedUrl - Output from urlParser.parseUrl()
 * @returns {{ obfuscationScore: number, flags: string[], decodedPayloads: string[] }}
 */
function detectObfuscation(url, parsedUrl) {
  const flags = [];
  const decodedPayloads = [];
  let score = 0;

  const { registeredDomain, hostname, isIP, params } = parsedUrl;

  // 1. URL Shortener
  if (URL_SHORTENERS.has(registeredDomain)) {
    flags.push('url_shortener');
    score += 0.4;
  }

  // 2. IP-based URL
  if (isIP) {
    flags.push('ip_based_url');
    score += 0.35;
  }

  // 3. IDN Homograph (Punycode)
  if (hostname.includes(IDN_PREFIX)) {
    flags.push('idn_homograph');
    score += 0.45;
  }

  // 4. Excessive subdomains (e.g., paypal.com.evil.com)
  const subdomainParts = hostname.split('.');
  if (subdomainParts.length > 4) {
    flags.push('excessive_subdomains');
    score += 0.25;
  }

  // 5. Base64 encoded parameters
  for (const [key, value] of Object.entries(params || {})) {
    if (BASE64_URL_REGEX.test(value) && value.length > 20) {
      const decoded = tryBase64Decode(value);
      if (decoded && (decoded.includes('http') || decoded.includes('password') || decoded.includes('login'))) {
        flags.push(`base64_param_${key}`);
        decodedPayloads.push(decoded.substring(0, 200));
        score += 0.3;
      }
    }
  }

  // 6. Multiple redirects in URL (redirect chains)
  const urlCount = (url.match(/https?:\/\//g) || []).length;
  if (urlCount > 1) {
    flags.push('url_in_url_redirect');
    score += 0.35;
  }

  // 7. @ symbol in URL (user:pass@host trick)
  if (url.includes('@') && /https?:\/\/[^@]+@/i.test(url)) {
    flags.push('at_symbol_trick');
    score += 0.5;
  }

  // 8. Hyphenated brand impersonation (e.g., paypal-secure-login.com)
  // Score raised to 1.0 — brand name in a non-brand domain is a near-definitive phishing indicator.
  const BRANDS = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix'];
  for (const brand of BRANDS) {
    if (hostname.includes(brand) && !hostname.endsWith(`.${brand}.com`) && hostname !== `${brand}.com`) {
      flags.push(`brand_impersonation_${brand}`);
      score += 1.0;
      break;
    }
  }

  // ── Structural URL Feature Vector ─────────────────────────────────────────
  // All features below are cheap arithmetic / regex; no external calls.

  const urlLen = url.length;
  const digits = (url.match(/\d/g) || []).length;
  const letters = (url.match(/[a-zA-Z]/g) || []).length;

  // Double-slash count beyond the protocol (e.g. evil.com//paypal.com)
  const doubleSlashMatches = (url.match(/\/\//g) || []);
  const numDoubleSlash = Math.max(0, doubleSlashMatches.length - 1); // subtract protocol's //

  // Sensitive words appearing in the full URL (path + subdomain)
  const urlLower = url.toLowerCase();
  const sensHits = URL_SENSITIVE_WORDS.filter((w) => urlLower.includes(w)).length;

  // Hyphenated brand impersonation in the registered domain itself
  // (e.g. paypal-secure.com  — brand appears but domain is NOT brand.com)
  const hasPrefixSuffixHyphen = (() => {
    if (!registeredDomain) return false;
    const domLower = registeredDomain.toLowerCase();
    const BRANDS_LOWER = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix'];
    return BRANDS_LOWER.some((b) => domLower.includes(b) && domLower.includes('-'));
  })();

  const structuralFeatures = {
    url_entropy:               parseFloat(shannonEntropy(url).toFixed(4)),
    url_digit_ratio:           urlLen > 0 ? parseFloat((digits / urlLen).toFixed(4)) : 0,
    url_letter_ratio:          urlLen > 0 ? parseFloat((letters / urlLen).toFixed(4)) : 0,
    url_num_dots:              (url.match(/\./g) || []).length,
    url_num_slashes:           (url.match(/\//g) || []).length,
    url_num_hyphens:           (url.match(/-/g) || []).length,
    url_num_equals:            (url.match(/=/g) || []).length,
    url_num_question:          (url.match(/\?/g) || []).length,
    url_num_ampersand:         (url.match(/&/g) || []).length,
    url_num_percent:           (url.match(/%/g) || []).length,
    url_num_double_slash:      numDoubleSlash,
    url_num_sensitive_words:   sensHits,
    url_has_at_symbol:         url.includes('@'),
    url_prefix_suffix_hyphen:  hasPrefixSuffixHyphen,
  };

  return {
    obfuscationScore: parseFloat(Math.min(score, 1.0).toFixed(3)),
    flags,
    decodedPayloads,
    structuralFeatures,
  };
}

module.exports = { detectObfuscation, shannonEntropy };
