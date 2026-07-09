const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const { parseUrl } = require('../utils/urlParser');
const { aggregateScore } = require('../utils/scorer');
const logger = require('../utils/logger');

// Level 1
const { trustScore } = require('../level1/staticWhitelist');
const { getCachedResult, setCachedResult, invalidateCache } = require('../level1/redisCache');
const { computeContentHash, verifyContentHash } = require('../level1/contentHash');

// Level 2
const { parseHtml } = require('../level2/htmlParser');
const { detectPatterns } = require('../level2/patternDetector');
const { detectDomainMismatch } = require('../level2/domainMismatch');
const { detectObfuscation } = require('../level2/urlObfuscation');
const { analyzeGitHubContext } = require('../level2/githubContext');
const { getDomainRankFeatures } = require('../level2/domainRankFeatures');
const { getWhoisFeatures } = require('../level2/whoisFeatures');

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
    if (rawUrl.length > 2048) {
        return res.status(400).json({ error: 'url exceeds maximum allowed length of 2048 characters' });
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
    //  LEVEL 1 — Static Whitelist Check (trust-score gating)
    // ════════════════════════════════════════════════════════════════════════
    const whitelistResult = await trustScore(hostname, registeredDomain);
    if (whitelistResult.fastPath) {
        logger.info(`✅ L1 Whitelist HIT: ${url}`);
        return res.json(buildResponse(url, 'SAFE', 0.0, 1.0, 'L1_WHITELIST', {}, true, startTime));
    }
    // Partial match: continues to L2 but carries the flag into the feature vector
    const whitelistPartialMatch = whitelistResult.whitelistPartialMatch;
    if (whitelistPartialMatch) {
        logger.info(`⚠️  Whitelist partial match (subdomain spoofing risk) — sending to L2: ${url}`);
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
        } else if (cached.verdict === 'MALICIOUS' && cached.html_hash) {
            // MALICIOUS re-verification: once per day (configurable) to catch pages that
            // scrub their content to slip through repeat scans, or were legitimately fixed.
            const reverifyInterval = parseInt(process.env.MALICIOUS_REVERIFY_INTERVAL_MS || String(24 * 60 * 60 * 1000));
            const ageMs = Date.now() - (cached.timestamp ? new Date(cached.timestamp).getTime() : 0);
            if (ageMs > reverifyInterval) {
                logger.info(`🔁 MALICIOUS re-verify triggered (age ${Math.round(ageMs / 3600000)}h): ${url}`);
                const hashMatch = await verifyContentHash(url, cached.html_hash);
                if (!hashMatch) {
                    // Content changed — force full re-scan, do NOT auto-flip to SAFE
                    logger.info(`⚠️  MALICIOUS page content changed — full re-scan: ${url}`);
                    await invalidateCache(url);
                    // Fall through to Level 2
                } else {
                    return res.json(buildResponse(url, cached.verdict, cached.score, cached.confidence, cached.level_caught, cached.breakdown, true, startTime));
                }
            } else {
                return res.json(buildResponse(url, cached.verdict, cached.score, cached.confidence, cached.level_caught, cached.breakdown, true, startTime));
            }
        } else if (cached.verdict !== 'SAFE') {
            // Suspicious cached results served directly
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
        ? crypto.createHash('sha256')
            .update(rawHtml.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/\s+/g, ' ').trim())
            .digest('hex')
        : null;

    // Run Level 2 analyzers — synchronous ones run directly, async ones run concurrently
    const patternResult     = detectPatterns(parsedHtml.visibleText);
    const mismatchResult    = detectDomainMismatch(
        parsedHtml.anchors,
        hostname,
        parsedHtml.visibleText,
        parsedHtml.title,
    );
    const obfuscationResult = detectObfuscation(url, parsedUrl);

    // GitHub context and WHOIS are both I/O-bound — run concurrently
    const [githubResult, rankFeatures, whoisFeatureResult] = await Promise.all([
        analyzeGitHubContext(url, parsedHtml),
        Promise.resolve(getDomainRankFeatures(registeredDomain)),
        getWhoisFeatures(registeredDomain, mismatchResult.inferred_brand),
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

    // Aggregate signals — pass structural URL + HTML fingerprint features as extraFeatures
    // so scorer.js can embed them in the structured feature vector.
    const extraFeatures = {
        ...obfuscationResult.structuralFeatures,
        html_num_eval_calls: parsedHtml.html_num_eval_calls,
        html_num_unescape_calls: parsedHtml.html_num_unescape_calls,
        html_has_right_click_disabled: parsedHtml.html_has_right_click_disabled,
        sfh_is_empty: parsedHtml.sfh_is_empty,
        sfh_is_about_blank: parsedHtml.sfh_is_about_blank,
        html_has_favicon: parsedHtml.html_has_favicon,
        html_num_hidden_inputs: parsedHtml.html_num_hidden_inputs,
        fearDetected: patternResult.fearDetected,
        credentialDetected: patternResult.credentialDetected,
        // Brand inference from domainMismatch.js
        inferred_brand: mismatchResult.inferred_brand,
        brand_domain_match: mismatchResult.brand_domain_match,
        // Whitelist partial-match flag (Phase 3)
        whitelistPartialMatch: whitelistPartialMatch,
        // Tranco rank features (Phase 2)
        ...rankFeatures,
        // WHOIS features (Phase 2)
        ...whoisFeatureResult,
    };

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

    const { score, verdict, breakdown, features } = aggregateScore(signals, extraFeatures);

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
        await setCachedResult(url, { ...result, html_hash: htmlHash, features });
        return res.json(result);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  LEVEL 3 — ML Inference (FastAPI)
    // ════════════════════════════════════════════════════════════════════════
    logger.info(`🧠 L3 ML Inference: ${url}`);

    try {
        const mlResponse = await axios.post(
            `${ML_SERVICE_URL}/analyze`, {
                url,
                html: rawHtml.substring(0, 50000), // Cap at 50KB
                visible_text: parsedHtml.visibleText.substring(0, 5000),
                forms: parsedHtml.forms,
                l2_score: score,
                l2_breakdown: level2Breakdown,
                l2_features: features, // ← structured feature vector for L3 fusion
            }, { timeout: 30000 }
        );

        const mlData = mlResponse.data;
        const finalVerdict = mlData.verdict;
        const finalScore = mlData.final_score;
        const finalBreakdown = { ...level2Breakdown, ml: mlData.breakdown };

        const result = buildResponse(url, finalVerdict, finalScore, mlData.confidence, 'L3_ML', finalBreakdown, false, startTime);
        result.screenshot_url = mlData.screenshot_url || null;
        result.ocr_text = mlData.ocr_text || null;

        await setCachedResult(url, { ...result, html_hash: htmlHash, features });
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