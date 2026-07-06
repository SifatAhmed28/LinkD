const path = require('path');
const logger = require('../utils/logger');
const { parse } = require('tldts');

let whitelistDomains = new Set();
let whitelistExact = new Set();

/**
 * Loads the static whitelist from whitelist.json into memory at startup.
 * Called once during server initialization.
 */
function loadWhitelist() {
  try {
    const data = require(path.resolve(__dirname, '../../config/whitelist.json'));
    whitelistDomains = new Set(data.domains || []);
    whitelistExact = new Set(data.subdomains_exact || []);
    logger.info(`✅ Static whitelist loaded: ${whitelistDomains.size} domains, ${whitelistExact.size} exact subdomains`);
  } catch (err) {
    logger.error('Failed to load whitelist.json:', err.message);
  }
}

/**
 * Computes a trust score for a hostname and returns gating instructions.
 *
 * | Case                                                   | score | fastPath | whitelistPartialMatch |
 * |--------------------------------------------------------|-------|----------|-----------------------|
 * | Exact hostname in subdomains_exact                     |  1.0  |  true    | false                 |
 * | eTLD+1 in domains AND hostname === registeredDomain    |  1.0  |  true    | false                 |
 * | eTLD+1 in domains AND one standard subdomain (no extra)|  1.0  |  true    | false                 |
 * | eTLD+1 in domains BUT extra subdomain levels present   |  0.4  |  false   | true  (send to L2)    |
 * | Not in whitelist                                       |  0.0  |  false   | false                 |
 *
 * The whitelistPartialMatch flag catches spoofed subdomain attacks like:
 *   accounts.google.com.verify-login.xyz  (eTLD+1 is verify-login.xyz, not google.com)
 *
 * @param {string} hostname         - e.g. "accounts.google.com"
 * @param {string} registeredDomain - eTLD+1, e.g. "google.com"
 * @returns {{ score: number, fastPath: boolean, whitelistPartialMatch: boolean }}
 */
function trustScore(hostname, registeredDomain) {
  // 1. Exact subdomain match (highest priority)
  if (whitelistExact.has(hostname)) {
    return { score: 1.0, fastPath: true, whitelistPartialMatch: false };
  }

  // 2. eTLD+1 match
  if (whitelistDomains.has(registeredDomain)) {
    // Bare domain match (hostname IS the registered domain, e.g. google.com → google.com)
    if (hostname === registeredDomain) {
      return { score: 1.0, fastPath: true, whitelistPartialMatch: false };
    }

    // Check whether hostname has only one subdomain level (e.g. www.google.com, accounts.google.com)
    const suffix = '.' + registeredDomain;
    if (hostname.endsWith(suffix)) {
      const subdomain = hostname.slice(0, hostname.length - suffix.length);
      // Reject if subdomain itself has dots (e.g. evil.accounts.google.com)
      if (!subdomain.includes('.')) {
        return { score: 1.0, fastPath: true, whitelistPartialMatch: false };
      }
    }
    // Multi-level subdomain on a whitelisted domain — partial match, send to L2
    return { score: 0.4, fastPath: false, whitelistPartialMatch: true };
  }

  // 3. No match
  return { score: 0.0, fastPath: false, whitelistPartialMatch: false };
}

/**
 * @deprecated Use trustScore() instead.
 * Kept for backward compatibility with any direct callers outside scan.js.
 */
function isWhitelisted(hostname, registeredDomain) {
  return trustScore(hostname, registeredDomain).fastPath;
}

// Load on module initialization
loadWhitelist();

module.exports = { trustScore, isWhitelisted, loadWhitelist };
