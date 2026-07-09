/**
 * Aggregates Level 2 heuristic signals into a single threat score (0.0 – 1.0)
 * AND a structured feature vector for consumption by L3 and the cache.
 *
 * Signal weights are tuned to match empirical phishing datasets.
 * The final score is used to decide whether to escalate to Level 3 ML inference.
 *
 * Thresholds (from .env):
 *   score < SCORE_SAFE_THRESHOLD      → SAFE (skip ML)
 *   score > SCORE_MALICIOUS_THRESHOLD → MALICIOUS (skip ML)
 *   otherwise                          → SUSPICIOUS (escalate to ML)
 */

const WEIGHTS = {
  urgencyKeyword: 0.25,       // Phishing language / social engineering
  domainMismatch: 0.30,       // Anchor text brand ≠ href domain
  urlObfuscation: 0.20,       // Shorteners, Base64, IP URLs, IDN
  formPasswordField: 0.35,    // Password input on unusual platform
  crossOriginForm: 0.30,      // Form posts to different origin
  githubNewRepo: 0.40,        // Very new GitHub repo
  githubFewCommits: 0.30,     // Repo with < 3 commits
  githubPasswordInReadme: 0.80, // Password field in README (critical)
  httpsDowngrade: 0.25,       // HTTPS page with HTTP links/forms
  ipBasedUrl: 0.20,           // URL uses raw IP address
  fetchFailed: 0.25,          // Domain unreachable or returned error — suspicious
};

/**
 * @param {Object} signals      - Map of signal names to boolean or float (0-1)
 * @param {Object} extraFeatures - Additional structured features to include in the
 *                                 feature vector (URL structural, HTML kit fingerprints,
 *                                 WHOIS, rank — passed through verbatim, not weighted).
 * @returns {{ score: number, breakdown: Object, verdict: string, features: Object }}
 */
function aggregateScore(signals, extraFeatures = {}) {
  let totalScore = 0;
  const breakdown = {};

  for (const [signal, value] of Object.entries(signals)) {
    if (!WEIGHTS[signal]) continue;
    const contribution = WEIGHTS[signal] * (typeof value === 'boolean' ? (value ? 1 : 0) : value);
    breakdown[signal] = parseFloat(contribution.toFixed(3));
    totalScore += contribution;
  }

  // Clamp to [0, 1]
  const score = Math.min(parseFloat(totalScore.toFixed(3)), 1.0);

  const safeThreshold = parseFloat(process.env.SCORE_SAFE_THRESHOLD || '0.2');
  const maliciousThreshold = parseFloat(process.env.SCORE_MALICIOUS_THRESHOLD || '0.85');

  let verdict;
  if (score < safeThreshold) verdict = 'SAFE';
  else if (score >= maliciousThreshold) verdict = 'MALICIOUS';
  else verdict = 'SUSPICIOUS';

  // ── Structured feature vector ────────────────────────────────────────────────
  // Combines the scorer's input signals (normalised to 0/1 floats) with any extra
  // features passed in from URL/HTML/WHOIS/rank modules. This vector is:
  //   • stored in the Redis cache (for version-stable re-scoring)
  //   • forwarded to L3's /analyze endpoint as l2_features
  const features = {
    // Core heuristic signals (normalised)
    urgencyScore:         typeof signals.urgencyKeyword === 'number' ? signals.urgencyKeyword : (signals.urgencyKeyword ? 1 : 0),
    domainMismatch:       typeof signals.domainMismatch === 'number' ? signals.domainMismatch : (signals.domainMismatch ? 1 : 0),
    urlObfuscation:       typeof signals.urlObfuscation === 'number' ? signals.urlObfuscation : (signals.urlObfuscation ? 1 : 0),
    formPassword:         signals.formPasswordField ? 1 : 0,
    crossOriginForm:      signals.crossOriginForm ? 1 : 0,
    httpsDowngrade:       signals.httpsDowngrade ? 1 : 0,
    githubNewRepo:        signals.githubNewRepo ? 1 : 0,
    githubFewCommits:     signals.githubFewCommits ? 1 : 0,
    githubPasswordInReadme: signals.githubPasswordInReadme ? 1 : 0,
    ipBasedUrl:           signals.ipBasedUrl ? 1 : 0,
    fetchFailed:          signals.fetchFailed ? 1 : 0,
    // Extra features passed verbatim (structural URL, HTML kit fingerprints, etc.)
    ...extraFeatures,
  };

  return {
    score,
    verdict,
    breakdown,
    features,
  };
}

module.exports = { aggregateScore, WEIGHTS };
