/**
 * domainRankFeatures.js
 *
 * Provides a fast-path Tranco top-10k domain rank lookup.
 * The Tranco list is loaded once from disk at startup into a Set — O(1) lookup per scan.
 *
 * Run gateway/scripts/sync-tranco.js on a schedule to keep the list fresh.
 * If the list file is missing, all features default to null (scan proceeds normally).
 *
 * Features emitted:
 *   tranco_in_top10k   {boolean|null}  — domain appears in Tranco top-10k
 *   tranco_rank_bucket {string|null}   — 'top1k' | 'top10k' | 'none'
 *
 * Reference: Bhuiyan et al. SHAP analysis — indexing/traffic signals are the
 * single highest-importance feature category for phishing detection.
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

// ── Load Tranco list at startup ───────────────────────────────────────────────
const TRANCO_PATH = path.resolve(__dirname, '../../config/tranco_top10k.txt');

// top1k: first 1000 domains (highest-confidence legitimate)
// top10k: all 10000 domains (broader prior)
let trancoTop1k = new Set();
let trancoTop10k = new Set();
let listLoaded = false;

function loadTrancoList() {
  try {
    const raw = fs.readFileSync(TRANCO_PATH, 'utf-8');
    const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);

    trancoTop10k = new Set(lines);
    trancoTop1k  = new Set(lines.slice(0, 1000));
    listLoaded = true;

    logger.info(`✅ Tranco list loaded: ${trancoTop10k.size} domains (top-1k set: ${trancoTop1k.size})`);
  } catch (err) {
    if (err.code === 'ENOENT') {
      logger.warn('Tranco list not found — run scripts/sync-tranco.js to generate it. Rank features will be null.');
    } else {
      logger.error(`Failed to load Tranco list: ${err.message}`);
    }
    listLoaded = false;
  }
}

// Load on module initialisation
loadTrancoList();

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Returns Tranco rank features for a registered domain.
 *
 * @param {string} registeredDomain - e.g. "google.com"
 * @returns {{ tranco_in_top10k: boolean|null, tranco_rank_bucket: string|null }}
 */
function getDomainRankFeatures(registeredDomain) {
  if (!listLoaded || !registeredDomain) {
    return { tranco_in_top10k: null, tranco_rank_bucket: null };
  }

  const domain = registeredDomain.toLowerCase();
  const inTop10k = trancoTop10k.has(domain);
  const inTop1k  = trancoTop1k.has(domain);

  return {
    tranco_in_top10k:   inTop10k,
    tranco_rank_bucket: inTop1k ? 'top1k' : inTop10k ? 'top10k' : 'none',
  };
}

module.exports = { getDomainRankFeatures, loadTrancoList };
