/**
 * whoisFeatures.js
 *
 * General-purpose WHOIS lookup and feature extraction.
 * Uses the `whois` npm package for raw socket queries and normalises the
 * text output into structured features. Results are cached per-domain in
 * Redis (or in-memory LRU) with a 24-hour TTL — WHOIS data changes slowly.
 *
 * Features emitted (mirrors Aksoy et al. Table 9 WHOIS group):
 *   domain_age_days         — days since domain creation (strongest single signal)
 *   domain_expiry_days      — days until expiry (short window is suspicious)
 *   days_since_last_update  — days since last-modified date
 *   registrar_category      — 'major' | 'budget' | 'unknown'
 *   has_registrant_org      — bool: registrant org field populated (not privacy-shielded)
 *   has_registrant_email    — bool: registrant email populated
 *   has_registrant_phone    — bool: registrant phone populated
 *   domain_name_match       — bool: registrant org loosely contains the inferred brand name
 *
 * On any failure (WHOIS timeout, parse error, rate-limit) all features are null
 * and the scan continues without WHOIS signals.
 *
 * @module whoisFeatures
 */

const logger = require('../utils/logger');

// ── Redis cache (shared with main scan cache, different key prefix) ────────────
// We import the raw Redis client via a lightweight accessor rather than re-wiring
// the full redisCache module (which has its own TTL and versioning logic).
let _redisClient = null;
const _memCache = new Map();          // in-memory fallback for WHOIS-specific cache
const WHOIS_TTL_MS = 24 * 60 * 60 * 1000;  // 24 h

function setWhoisRedis(client) { _redisClient = client; }

async function _getCached(domain) {
  const key = `linkd:whois:${domain}`;
  try {
    if (_redisClient) {
      const raw = await _redisClient.get(key);
      return raw ? JSON.parse(raw) : null;
    }
  } catch { /* fall through to in-memory */ }
  const entry = _memCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > WHOIS_TTL_MS) { _memCache.delete(key); return null; }
  return entry.data;
}

async function _setCached(domain, data) {
  const key = `linkd:whois:${domain}`;
  try {
    if (_redisClient) {
      await _redisClient.setex(key, 86400, JSON.stringify(data));
      return;
    }
  } catch { /* fall through */ }
  _memCache.set(key, { ts: Date.now(), data });
}

// ── Registrar categorisation ──────────────────────────────────────────────────
// Major registrars: well-known brands with fraud-monitoring programs.
// Budget/anonymous-friendly registrars correlate with phishing abuse.
const MAJOR_REGISTRARS = new Set([
  'godaddy', 'network solutions', 'enom', 'tucows', 'register.com',
  'name.com', 'google domains', 'squarespace domains', '1&1',
  'ionos', 'gandi', 'cloudflare', 'amazon registrar', 'markmonitor',
]);
const BUDGET_REGISTRARS = new Set([
  'namecheap', 'namesilo', 'porkbun', 'dynadot', 'hostgator',
  'bluehost', 'epik', 'internet.bs', 'registrar.eu',
]);

function categoriseRegistrar(registrar) {
  if (!registrar) return 'unknown';
  const lower = registrar.toLowerCase();
  if ([...MAJOR_REGISTRARS].some((r) => lower.includes(r))) return 'major';
  if ([...BUDGET_REGISTRARS].some((r) => lower.includes(r))) return 'budget';
  return 'unknown';
}

// ── Date parsing helpers ──────────────────────────────────────────────────────
const DATE_FORMATS = [
  // ISO 8601: 2023-04-12T10:00:00Z
  /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/,
  // Space-separated: 2023-04-12 10:00:00
  /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/,
  // Date only: 2023-04-12
  /(\d{4}-\d{2}-\d{2})/,
  // DD-Mon-YYYY: 12-Apr-2023
  /(\d{2}-[A-Za-z]{3}-\d{4})/,
];

function parseWhoisDate(raw) {
  if (!raw) return null;
  for (const re of DATE_FORMATS) {
    const m = raw.match(re);
    if (m) {
      const d = new Date(m[1]);
      if (!isNaN(d.getTime())) return d;
    }
  }
  return null;
}

function daysBetween(a, b = new Date()) {
  if (!a) return null;
  return Math.round((b - a) / (1000 * 60 * 60 * 24));
}

// ── WHOIS text parser ─────────────────────────────────────────────────────────
function parseWhoisText(raw) {
  const lines = raw.split('\n');
  const find = (patterns) => {
    for (const line of lines) {
      for (const p of patterns) {
        const m = line.match(new RegExp(`^\\s*${p}\\s*:\\s*(.+)$`, 'i'));
        if (m && m[1].trim()) return m[1].trim();
      }
    }
    return null;
  };

  return {
    createdDate:  parseWhoisDate(find(['creation date', 'created', 'domain create date', 'registered on', 'registered'])),
    expiryDate:   parseWhoisDate(find(['registry expiry date', 'expiration date', 'expires on', 'expiry date', 'paid-till'])),
    updatedDate:  parseWhoisDate(find(['updated date', 'last updated', 'last-update', 'modified'])),
    registrar:    find(['registrar', 'registrar name', 'sponsoring registrar']),
    registrantOrg:   find(['registrant organization', 'registrant org', 'registrant company', 'org-name']),
    registrantEmail: find(['registrant email', 'registrant e-mail']),
    registrantPhone: find(['registrant phone', 'registrant tel']),
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Performs a WHOIS lookup and returns structured phishing-signal features.
 *
 * @param {string} domain          - Registered domain (e.g. "evil-paypal.com")
 * @param {string|null} inferredBrand - Brand the page appears to impersonate (from domainMismatch.js)
 * @returns {Promise<Object>}      - Feature object (all keys present, may be null)
 */
async function getWhoisFeatures(domain, inferredBrand = null) {
  const nullResult = {
    domain_age_days:        null,
    domain_expiry_days:     null,
    days_since_last_update: null,
    registrar_category:     null,
    has_registrant_org:     null,
    has_registrant_email:   null,
    has_registrant_phone:   null,
    domain_name_match:      null,
  };

  if (!domain) return nullResult;

  // ── Check cache ─────────────────────────────────────────────────────────────
  const cached = await _getCached(domain);
  if (cached) {
    logger.debug(`WHOIS cache HIT: ${domain}`);
    return cached;
  }

  // ── Perform WHOIS lookup ────────────────────────────────────────────────────
  let whoisRaw;
  try {
    const whois = require('whois');
    whoisRaw = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('WHOIS timeout')), 5000);
      whois.lookup(domain, (err, data) => {
        clearTimeout(timer);
        if (err) reject(err);
        else resolve(data || '');
      });
    });
  } catch (err) {
    logger.warn(`WHOIS lookup failed for ${domain}: ${err.message}`);
    return nullResult;
  }

  // ── Parse ───────────────────────────────────────────────────────────────────
  let parsed;
  try {
    parsed = parseWhoisText(whoisRaw);
  } catch (err) {
    logger.warn(`WHOIS parse failed for ${domain}: ${err.message}`);
    return nullResult;
  }

  const now = new Date();
  const features = {
    domain_age_days:        daysBetween(parsed.createdDate, now),
    domain_expiry_days:     parsed.expiryDate ? daysBetween(now, parsed.expiryDate) : null,
    days_since_last_update: daysBetween(parsed.updatedDate, now),
    registrar_category:     categoriseRegistrar(parsed.registrar),
    has_registrant_org:     !!parsed.registrantOrg,
    has_registrant_email:   !!parsed.registrantEmail,
    has_registrant_phone:   !!parsed.registrantPhone,
    // Loose match: does the registrant org mention the brand being impersonated?
    domain_name_match: inferredBrand && parsed.registrantOrg
      ? parsed.registrantOrg.toLowerCase().includes(inferredBrand.toLowerCase())
      : null,
  };

  await _setCached(domain, features);
  logger.info(`WHOIS features for ${domain}: age=${features.domain_age_days}d, registrar=${features.registrar_category}`);
  return features;
}

module.exports = { getWhoisFeatures, setWhoisRedis };
