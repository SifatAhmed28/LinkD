const path = require('path');
const logger = require('../utils/logger');

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
 * Checks if a hostname is in the static whitelist.
 * Supports both exact subdomain matches and registered domain matches.
 *
 * @param {string} hostname - e.g. "accounts.google.com"
 * @param {string} registeredDomain - e.g. "google.com"
 * @returns {boolean}
 */
function isWhitelisted(hostname, registeredDomain) {
  if (whitelistExact.has(hostname)) return true;
  if (whitelistDomains.has(registeredDomain)) return true;
  // Check if hostname ends with a whitelisted domain (subdomain check)
  for (const domain of whitelistDomains) {
    if (hostname === domain || hostname.endsWith('.' + domain)) return true;
  }
  return false;
}

// Load on module initialization
loadWhitelist();

module.exports = { isWhitelisted, loadWhitelist };
