const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const logger = require('../utils/logger');

/**
 * Fetches the current page body HTML and computes a SHA-256 hash.
 * Dynamic <script> tags are stripped to reduce noise from ad injection.
 *
 * @param {string} url
 * @returns {Promise<string|null>} SHA-256 hex hash or null on failure
 */
async function computeContentHash(url) {
  const timeout = parseInt(process.env.CONTENT_HASH_TIMEOUT || '5000');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; LinkD-Scanner/1.0)',
        'Accept': 'text/html,application/xhtml+xml',
      },
      redirect: 'follow',
    });

    clearTimeout(timer);

    if (!response.ok) {
      logger.warn(`Content hash fetch failed (${response.status}) for: ${url}`);
      return null;
    }

    let html = await response.text();

    // Strip <script> tags (removes dynamic ad/analytics noise)
    html = html.replace(/<script[\s\S]*?<\/script>/gi, '');

    // Extract and normalize <body> content
    const bodyMatch = html.match(/<body[\s\S]*?>([\s\S]*)<\/body>/i);
    const body = bodyMatch ? bodyMatch[1] : html;

    // Normalize whitespace for consistent hashing
    const normalized = body.replace(/\s+/g, ' ').trim();

    return crypto.createHash('sha256').update(normalized).digest('hex');
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      logger.warn(`Content hash timeout for: ${url}`);
    } else {
      logger.warn(`Content hash error for ${url}: ${err.message}`);
    }
    return null;
  }
}

/**
 * Verifies that the current page content matches the cached hash.
 * Returns true if content is unchanged (cache is valid), false if changed.
 *
 * @param {string} url
 * @param {string} cachedHash
 * @returns {Promise<boolean>}
 */
async function verifyContentHash(url, cachedHash) {
  const currentHash = await computeContentHash(url);
  if (!currentHash) {
    // On fetch failure, assume content may have changed (fail open → re-scan)
    logger.warn(`Cannot verify content hash — treating as changed for: ${url}`);
    return false;
  }

  const isMatch = currentHash === cachedHash;
  if (!isMatch) {
    logger.info(`🔄 Content hash mismatch detected for: ${url}`);
  }
  return isMatch;
}

module.exports = { computeContentHash, verifyContentHash };
