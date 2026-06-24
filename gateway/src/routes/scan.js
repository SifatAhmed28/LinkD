const express = require('express');
const axios = require('axios');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const { parseUrl } = require('../utils/urlParser');
const { aggregateScore } = require('../utils/scorer');
const logger = require('../utils/logger');

// Level 1
const { isWhitelisted } = require('../level1/staticWhitelist');
const { getCachedResult, setCachedResult, invalidateCache } = require('../level1/redisCache');
const { computeContentHash, verifyContentHash } = require('../level1/contentHash');

// Level 2
const { parseHtml } = require('../level2/htmlParser');
const { detectPatterns } = require('../level2/patternDetector');
const { detectDomainMismatch } = require('../level2/domainMismatch');
const { detectObfuscation } = require('../level2/urlObfuscation');
const { analyzeGitHubContext } = require('../level2/githubContext');

const router = express.Router();

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:8000';

/**
 * POST /api/scan
 * Main endpoint: accepts a URL and returns a phishing verdict.
 *
 * Body: { url: string }
 * Response: {
 *   url, verdict, score, confidence, level_caught,
 *   breakdown, cached, timestamp
 * }
 */
router.post('/scan', async (req, res) => {
  const startTime = Date.now();
  const { url: rawUrl } = req.body;

  if (!rawUrl || typeof rawUrl !== 'string') {
    return res.status(400).json({ error: 'url is required and must be a string' });
  }

  // ── URL Parsing ───────────────────────────────────────────────────────────
  let parsedUrl;
  try {
    parsedUrl = parseUrl(rawUrl);
  } catch (err) {
    return res.status(400).json({ error: `Invalid URL: ${err.message}` });
  }

  const { href: url, hostname, registeredDomain } = parsedUrl;

  logger.info(`Scanning: ${url}`);

  // ════════════════════════════════════════════════════════════════════════
  //  LEVEL 1 — Static Whitelist Check
  // ════════════════════════════════════════════════════════════════════════
  if (isWhitelisted(hostname, registeredDomain)) {
    logger.info(`✅ L1 Whitelist HIT: ${url}`);
    return res.json(buildResponse(url, 'SAFE', 0.0, 1.0, 'L1_WHITELIST', {}, true, startTime));
  }

  // ════════════════════════════════════════════════════════════════════════
  //  LEVEL 1 — Redis/LRU Cache Check
  // ════════════════════════════════════════════════════════════════════════
  const cached = await getCachedResult(url);
  if (cached) {
    logger.info(`📦 L1 Cache HIT: ${url} (verdict: ${cached.verdict})`);

    // Content hash verification — only for SAFE cached entries
    if (cached.verdict === 'SAFE' && cached.html_hash) {
      const hashMatch = await verifyContentHash(url, cached.html_hash);
      if (!hashMatch) {
        logger.info(`⚠️  Content changed for cached SAFE URL — re-scanning: ${url}`);
        await invalidateCache(url);
        // Fall through to Level 2
      } else {
        return res.json(buildResponse(url, cached.verdict, cached.score, cached.confidence, cached.level_caught, cached.breakdown, true, startTime));
      }
    } else if (cached.verdict !== 'SAFE') {
      // Malicious/Suspicious cached results served directly (no hash check needed)
      return res.json(buildResponse(url, cached.verdict, cached.score, cached.confidence, cached.level_caught, cached.breakdown, true, startTime));
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  //  LEVEL 2 — Heuristics & Contextual Extraction
  // ════════════════════════════════════════════════════════════════════════
  logger.info(`🔍 L2 Heuristics: ${url}`);

  let rawHtml = '';
  let parsedHtml = { anchors: [], forms: [], passwordInputs: [], visibleText: '', hasPasswordInput: false, hasForm: false };
  let fetchFailed = false;

  // Fetch page HTML
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; LinkD-Scanner/1.0)' },
      redirect: 'follow',
    });
    clearTimeout(timeout);
    if (response.ok) {
      rawHtml = await response.text();
      parsedHtml = parseHtml(rawHtml);
    } else {
      fetchFailed = true; // Non-2xx response is suspicious
    }
  } catch (err) {
    logger.warn(`Failed to fetch HTML for ${url}: ${err.message}`);
    fetchFailed = true; // Unreachable domain is suspicious
  }

  // Compute content hash for future cache validation
  const htmlHash = rawHtml
    ? require('crypto').createHash('sha256')
        .update(rawHtml.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/\s+/g, ' ').trim())
        .digest('hex')
    : null;

  // Run Level 2 analyzers
  const [patternResult, mismatchResult, obfuscationResult, githubResult] = await Promise.all([
    Promise.resolve(detectPatterns(parsedHtml.visibleText)),
    Promise.resolve(detectDomainMismatch(parsedHtml.anchors, hostname)),
    Promise.resolve(detectObfuscation(url, parsedUrl)),
    analyzeGitHubContext(url, parsedHtml),
  ]);

  // Form behavior signals
  let crossOriginForm = false;
  let httpsDowngrade = false;
  for (const form of parsedHtml.forms) {
    if (form.action?.startsWith('http')) {
      try {
        const formOrigin = new URL(form.action).hostname;
        if (formOrigin !== hostname) crossOriginForm = true;
        if (parsedUrl.protocol === 'https:' && form.action.startsWith('http:')) {
          httpsDowngrade = true;
        }
      } catch { /* skip */ }
    }
  }

  // Aggregate signals
  const signals = {
    urgencyKeyword: patternResult.urgencyScore,
    domainMismatch: mismatchResult.mismatchScore,
    urlObfuscation: obfuscationResult.obfuscationScore,
    formPasswordField: parsedHtml.hasPasswordInput,
    crossOriginForm,
    githubNewRepo: githubResult.flags.includes('repo_very_new'),
    githubFewCommits: githubResult.flags.includes('very_few_commits'),
    githubPasswordInReadme: githubResult.flags.includes('CRITICAL_password_in_github_pages'),
    httpsDowngrade,
    ipBasedUrl: parsedUrl.isIP,
    fetchFailed, // Unreachable or error-returning pages are themselves suspicious
  };

  const { score, verdict, breakdown } = aggregateScore(signals);

  const level2Breakdown = {
    ...breakdown,
    patterns: patternResult,
    domainMismatches: mismatchResult.mismatches,
    obfuscationFlags: obfuscationResult.flags,
    githubFlags: githubResult.flags,
    githubSignals: githubResult.signals,
  };

  logger.info(`L2 result: score=${score}, verdict=${verdict}`);

  // ── Short-circuit if L2 is definitive ────────────────────────────────────
  if (verdict !== 'SUSPICIOUS') {
    const result = buildResponse(url, verdict, score, null, 'L2_HEURISTICS', level2Breakdown, false, startTime);
    await setCachedResult(url, { ...result, html_hash: htmlHash });
    return res.json(result);
  }

  // ════════════════════════════════════════════════════════════════════════
  //  LEVEL 3 — ML Inference (FastAPI)
  // ════════════════════════════════════════════════════════════════════════
  logger.info(`🧠 L3 ML Inference: ${url}`);

  try {
    const mlResponse = await axios.post(
      `${ML_SERVICE_URL}/analyze`,
      {
        url,
        html: rawHtml.substring(0, 50000), // Cap at 50KB
        visible_text: parsedHtml.visibleText.substring(0, 5000),
        forms: parsedHtml.forms,
        l2_score: score,
        l2_breakdown: level2Breakdown,
      },
      { timeout: 30000 }
    );

    const mlData = mlResponse.data;
    const finalVerdict = mlData.verdict;
    const finalScore = mlData.final_score;
    const finalBreakdown = { ...level2Breakdown, ml: mlData.breakdown };

    const result = buildResponse(url, finalVerdict, finalScore, mlData.confidence, 'L3_ML', finalBreakdown, false, startTime);
    result.screenshot_url = mlData.screenshot_url || null;
    result.ocr_text = mlData.ocr_text || null;

    await setCachedResult(url, { ...result, html_hash: htmlHash });
    return res.json(result);

  } catch (mlErr) {
    logger.error(`ML service error: ${mlErr.message}. Falling back to L2 verdict.`);
    // Graceful degradation: use L2 SUSPICIOUS result
    const result = buildResponse(url, 'SUSPICIOUS', score, 0.5, 'L2_FALLBACK', level2Breakdown, false, startTime);
    return res.json(result);
  }
});

/**
 * GET /api/scan/health
 * Returns gateway and ML service health status.
 */
router.get('/scan/health', async (req, res) => {
  let mlStatus = 'unavailable';
  try {
    const r = await axios.get(`${ML_SERVICE_URL}/health`, { timeout: 3000 });
    mlStatus = r.data?.status || 'ok';
  } catch { /* ML offline */ }

  res.json({
    gateway: 'ok',
    ml_service: mlStatus,
    timestamp: new Date().toISOString(),
  });
});

// ── Response Builder ──────────────────────────────────────────────────────────
function buildResponse(url, verdict, score, confidence, levelCaught, breakdown, cached, startTime) {
  return {
    url,
    verdict,
    score,
    confidence,
    level_caught: levelCaught,
    breakdown,
    cached,
    response_ms: Date.now() - startTime,
    timestamp: new Date().toISOString(),
  };
}

module.exports = router;
