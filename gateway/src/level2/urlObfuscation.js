const { parse } = require('tldts');

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

  return {
    obfuscationScore: parseFloat(Math.min(score, 1.0).toFixed(3)),
    flags,
    decodedPayloads,
  };
}

module.exports = { detectObfuscation };
