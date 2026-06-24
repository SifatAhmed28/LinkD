/**
 * Aggregates Level 2 heuristic signals into a single threat score (0.0 – 1.0).
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
 * @param {Object} signals - Map of signal names to boolean or float (0-1)
 * @returns {{ score: number, breakdown: Object, verdict: string }}
 */
function aggregateScore(signals) {
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

  return { score, verdict, breakdown };
}

module.exports = { aggregateScore, WEIGHTS };
