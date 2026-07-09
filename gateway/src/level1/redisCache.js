const Redis = require('ioredis');
const crypto = require('crypto');
const { LRUCache } = require('lru-cache');
const logger = require('../utils/logger');
const { FEATURE_SCHEMA_VERSION } = require('../config/feature_schema');

// ─── Redis Client ─────────────────────────────────────────────────────────────
let redisClient = null;
let useRedis = false;

async function connectRedis() {
  try {
    redisClient = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD || undefined,
      maxRetriesPerRequest: 1,
      lazyConnect: true,
      connectTimeout: 3000,
    });

    redisClient.on('error', (err) => {
      if (useRedis) {
        logger.warn(`Redis error — falling back to in-memory LRU: ${err.message}`);
        useRedis = false;
      }
    });

    await redisClient.connect();
    useRedis = true;
    logger.info('✅ Redis connected — using Redis LRU cache');
  } catch (err) {
    logger.warn(`Redis unavailable (${err.message}) — using in-memory LRU cache fallback`);
    useRedis = false;
  }
}

// ─── In-Memory LRU Fallback ──────────────────────────────────────────────────
const memCache = new LRUCache({
  max: 2000,                      // max 2000 entries
  ttl: 1000 * 60 * 60 * 24,       // 24-hour default TTL
  updateAgeOnGet: true,
});

// ─── Cache Key ────────────────────────────────────────────────────────────────
function cacheKey(url) {
  return `linkd:scan:${crypto.createHash('sha256').update(url).digest('hex')}`;
}

/**
 * Get a cached scan result for a URL.
 * @param {string} url
 * @returns {Object|null} cached entry or null
 */
async function getCachedResult(url) {
  const key = cacheKey(url);
  try {
    let entry;
    if (useRedis) {
      const raw = await redisClient.get(key);
      entry = raw ? JSON.parse(raw) : null;
    } else {
      entry = memCache.get(key) || null;
    }

    if (!entry) return null;

    // Invalidate stale feature schema — forces a fresh scan so L3 never
    // receives a feature vector with a different shape than the current schema.
    if (entry.cache_version !== FEATURE_SCHEMA_VERSION) {
      logger.info(`♻️  Cache schema version mismatch (stored=${entry.cache_version}, current=${FEATURE_SCHEMA_VERSION}) — invalidating: ${url}`);
      return null;
    }

    return entry;
  } catch (err) {
    logger.warn(`Cache read error: ${err.message}`);
    return null;
  }
}

/**
 * Store a scan result in cache.
 * @param {string} url
 * @param {Object} result - { verdict, score, html_hash, breakdown, features, timestamp }
 *                          `features` is the full L2 feature vector; stored so it can
 *                          be re-scored when weights/models change without re-fetching HTML.
 */
async function setCachedResult(url, result) {
  const key = cacheKey(url);
  const ttlSeconds = result.verdict === 'MALICIOUS'
    ? parseInt(process.env.REDIS_TTL_MALICIOUS || '259200')
    : parseInt(process.env.REDIS_TTL_SAFE || '86400');

  // Stamp the current schema version so stale entries are auto-invalidated
  const payload = { ...result, cache_version: FEATURE_SCHEMA_VERSION };

  try {
    if (useRedis) {
      await redisClient.setex(key, ttlSeconds, JSON.stringify(payload));
    } else {
      memCache.set(key, payload, { ttl: ttlSeconds * 1000 });
    }
  } catch (err) {
    logger.warn(`Cache write error: ${err.message}`);
  }
}

/**
 * Invalidate (delete) a cached entry for a URL.
 * @param {string} url
 */
async function invalidateCache(url) {
  const key = cacheKey(url);
  try {
    if (useRedis) {
      await redisClient.del(key);
    } else {
      memCache.delete(key);
    }
    logger.info(`🗑️  Cache invalidated for: ${url}`);
  } catch (err) {
    logger.warn(`Cache invalidation error: ${err.message}`);
  }
}

// Initialize Redis connection on module load
connectRedis();

module.exports = { getCachedResult, setCachedResult, invalidateCache };
