/**
 * domainSimilarity.js
 *
 * String-distance and similarity metrics for comparing a hostname against
 * known brand domains. Used by domainMismatch.js to detect typosquatting
 * and visual similarity attacks (paypa1.com, g00gle.com, amaz0n.com).
 *
 * Algorithms implemented (zero dependencies):
 *   - Levenshtein edit distance
 *   - Jaro-Winkler similarity (prefix-weighted)
 *   - Longest common substring ratio
 *   - Combined similarity scoring against a brand's canonical domains
 *
 * @module domainSimilarity
 */

/**
 * Levenshtein edit distance between two strings.
 * O(n*m) time, O(min(n,m)) space via rolling array.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} — minimum number of single-character edits (insertions,
 *                      deletions, substitutions) to transform a into b
 */
function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;

  // Ensure a is the shorter string for space optimization
  if (a.length > b.length) [a, b] = [b, a];

  const aLen = a.length;
  const bLen = b.length;

  let prev = new Array(aLen + 1);
  let curr = new Array(aLen + 1);

  for (let i = 0; i <= aLen; i++) prev[i] = i;

  for (let j = 1; j <= bLen; j++) {
    curr[0] = j;
    for (let i = 1; i <= aLen; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[i] = Math.min(
        prev[i] + 1,       // deletion
        curr[i - 1] + 1,   // insertion
        prev[i - 1] + cost  // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[aLen];
}

/**
 * Jaro similarity between two strings.
 * Returns a score between 0 (no match) and 1 (exact match).
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function jaroSimilarity(a, b) {
  if (a === b) return 1;
  if (!a || !b) return 0;

  const aLen = a.length;
  const bLen = b.length;
  const matchWindow = Math.max(0, Math.floor(Math.max(aLen, bLen) / 2) - 1);

  const aMatches = new Array(aLen).fill(false);
  const bMatches = new Array(bLen).fill(false);

  let matches = 0;
  let transpositions = 0;

  // Count matches
  for (let i = 0; i < aLen; i++) {
    const lo = Math.max(0, i - matchWindow);
    const hi = Math.min(i + matchWindow + 1, bLen);
    for (let j = lo; j < hi; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true;
      bMatches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0;

  // Count transpositions
  let k = 0;
  for (let i = 0; i < aLen; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[k]) k++;
    if (a[i] !== b[k]) transpositions++;
    k++;
  }

  return (
    (matches / aLen +
     matches / bLen +
     (matches - transpositions / 2) / matches) / 3
  );
}

/**
 * Jaro-Winkler similarity — boosts the Jaro score for strings that
 * share a common prefix (up to 4 characters).
 * Returns a score between 0 and 1.
 *
 * @param {string} a
 * @param {string} b
 * @param {number} prefixScale — scaling factor (default 0.1)
 * @returns {number}
 */
function jaroWinkler(a, b, prefixScale = 0.1) {
  const jaro = jaroSimilarity(a, b);

  // Compute common prefix length (max 4)
  let prefixLen = 0;
  const maxPrefix = Math.min(4, a.length, b.length);
  for (let i = 0; i < maxPrefix; i++) {
    if (a[i] === b[i]) prefixLen++;
    else break;
  }

  return jaro + prefixLen * prefixScale * (1 - jaro);
}

/**
 * Longest common substring length.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function longestCommonSubstringLength(a, b) {
  if (!a || !b) return 0;

  let maxLen = 0;
  let prev = new Array(b.length + 1).fill(0);
  let curr = new Array(b.length + 1).fill(0);

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      if (a[i - 1] === b[j - 1]) {
        curr[j] = prev[j - 1] + 1;
        if (curr[j] > maxLen) maxLen = curr[j];
      } else {
        curr[j] = 0;
      }
    }
    [prev, curr] = [curr, prev];
    curr.fill(0);
  }

  return maxLen;
}

/**
 * Compute the best similarity score between a hostname and a set of
 * canonical brand domains.
 *
 * @param {string} hostname — the page's hostname (lowercase, registered domain)
 * @param {string[]} brandDomains — canonical domains for the closest matching brand
 * @param {string} brandName — the brand key for label extraction
 * @returns {{ editDistance: number, similarityScore: number, lcsRatio: number, closestBrand: string }}
 */
function computeSimilarityScore(hostname, brandDomains, brandName) {
  let bestEditDist = Infinity;
  let bestJaroWinkler = 0;
  let bestLcsRatio = 0;
  let closest = brandName;

  // Extract the primary label from the hostname (before first dot)
  const hostLabel = hostname.split('.')[0].toLowerCase();

  for (const domain of brandDomains) {
    // Compare against the full domain (without TLD) and the primary label
    const brandLabel = domain.split('.')[0].toLowerCase();
    const brandFull = domain.toLowerCase();

    // Also compare with TLD stripped for the full domain
    const candidates = [brandLabel, brandFull];

    for (const candidate of candidates) {
      // Label-only comparison (most useful for typosquatting detection)
      const labelDist = levenshteinDistance(hostLabel, candidate);
      const labelJW = jaroWinkler(hostLabel, candidate);
      const lcsLen = longestCommonSubstringLength(hostLabel, candidate);
      const lcsRatio = lcsLen / Math.max(hostLabel.length, candidate.length);

      if (labelJW > bestJaroWinkler) {
        bestEditDist = labelDist;
        bestJaroWinkler = labelJW;
        bestLcsRatio = lcsRatio;
        closest = domain;
      }
    }
  }

  // Combined similarity score: weighted blend of Jaro-Winkler and LCS ratio
  // Higher = more similar = more suspicious (if the hostname isn't the brand itself)
  const similarityScore = parseFloat((0.7 * bestJaroWinkler + 0.3 * bestLcsRatio).toFixed(4));

  return {
    editDistance: bestEditDist,
    similarityScore,
    lcsRatio: parseFloat(bestLcsRatio.toFixed(4)),
    closestBrand: closest,
  };
}

module.exports = {
  levenshteinDistance,
  jaroSimilarity,
  jaroWinkler,
  longestCommonSubstringLength,
  computeSimilarityScore,
};
