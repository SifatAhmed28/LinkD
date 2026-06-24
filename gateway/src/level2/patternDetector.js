/**
 * Pattern-Based Phishing Detector
 *
 * Uses a curated regex dictionary and keyword lists to detect:
 * 1. Urgency / social engineering language
 * 2. Credential harvesting patterns
 * 3. Brand impersonation cues in visible text
 */

// ── Urgency Keyword Categories ────────────────────────────────────────────────
const URGENCY_PATTERNS = [
  /action\s+required/i,
  /verify\s+(your\s+)?(account|identity|email|information)/i,
  /account\s+(suspended|locked|disabled|restricted|compromised)/i,
  /immediate(ly)?\s+(action|attention|response|verification)/i,
  /your\s+account\s+(will\s+be\s+)?suspended/i,
  /confirm\s+your\s+(identity|account|details|information)/i,
  /unusual\s+(activity|sign[- ]in|login)/i,
  /unauthorized\s+(access|activity)/i,
  /click\s+here\s+(to\s+)?(verify|confirm|restore|update)/i,
  /update\s+your\s+(billing|payment|account|card)\s+information/i,
  /limited\s+time\s+(offer|access)/i,
  /you\s+have\s+(been\s+)?(selected|won|chosen)/i,
  /expires?\s+in\s+\d+\s+(hours?|minutes?|days?)/i,
  /security\s+alert/i,
  /suspicious\s+activity/i,
  /prevent\s+(account\s+)?deletion/i,
  /re[-\s]?verify/i,
  /enter\s+your\s+(password|credentials|login)/i,
];

// ── Fear / Threat Indicators ──────────────────────────────────────────────────
const FEAR_PATTERNS = [
  /your\s+(account|data|information)\s+(has\s+been\s+|was\s+)?(hacked|breached|stolen|leaked|exposed)/i,
  /legal\s+(action|proceedings?)/i,
  /law\s+enforcement/i,
  /arrest\s+warrant/i,
  /police\s+report/i,
  /tax\s+(fraud|evasion|issue)/i,
];

// ── Credential Harvesting ─────────────────────────────────────────────────────
const CREDENTIAL_PATTERNS = [
  /sign\s+in\s+to\s+continue/i,
  /log\s+in\s+to\s+(verify|continue|confirm)/i,
  /enter\s+(your\s+)?(username|email|password|pin|otp|ssn|social\s+security)/i,
  /recovery\s+(code|key|phrase)/i,
  /two[-\s]?factor/i,
];

/**
 * Score a text string based on how many urgency/fear/credential patterns match.
 *
 * @param {string} text - Visible page text
 * @returns {{ urgencyScore: number, matchedPatterns: string[], fearDetected: boolean }}
 */
function detectPatterns(text) {
  if (!text || text.length < 10) {
    return { urgencyScore: 0, matchedPatterns: [], fearDetected: false };
  }

  const matched = [];
  let urgencyHits = 0;
  let fearHits = 0;
  let credentialHits = 0;

  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.test(text)) {
      urgencyHits++;
      matched.push(pattern.source);
    }
  }

  for (const pattern of FEAR_PATTERNS) {
    if (pattern.test(text)) {
      fearHits++;
      matched.push(pattern.source);
    }
  }

  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.test(text)) {
      credentialHits++;
      matched.push(pattern.source);
    }
  }

  // Normalize: each category maxes at 1.0 total contribution
  const urgencyScore = Math.min(
    (urgencyHits * 0.15) + (fearHits * 0.2) + (credentialHits * 0.15),
    1.0
  );

  return {
    urgencyScore: parseFloat(urgencyScore.toFixed(3)),
    matchedPatterns: matched,
    fearDetected: fearHits > 0,
    credentialDetected: credentialHits > 0,
  };
}

module.exports = { detectPatterns };
