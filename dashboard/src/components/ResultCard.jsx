import React from 'react';

const VERDICT_EMOJIS  = { SAFE: '🛡️', SUSPICIOUS: '⚠️', MALICIOUS: '☠️' };
const VERDICT_LABELS  = { SAFE: 'Safe', SUSPICIOUS: 'Suspicious', MALICIOUS: 'Malicious' };
const CIRCUMFERENCE   = 2 * Math.PI * 40; // r=40

/**
 * Converts threat score (0=safe, 1=danger) → safety score (100=safe, 0=danger).
 * Whitelisted SAFE sites (score=0) get 100 exactly.
 */
function toSafetyScore(score, verdict) {
  if (verdict === 'SAFE' && (score === 0 || score === null || score === undefined)) return 100;
  const pct = Math.round((1 - (score ?? 0)) * 100);
  return Math.max(0, Math.min(100, pct));
}

export default function ResultCard({ result }) {
  if (!result) return null;

  const { url, verdict, score, confidence, level_caught, response_ms, cached } = result;
  const cls = verdict?.toLowerCase() || 'safe';
  const safetyScore = toSafetyScore(score, verdict);
  const isSafe     = verdict === 'SAFE';

  // Ring: full ring = 100% safety (green), empty ring = 0% safety (red)
  const offset = CIRCUMFERENCE - (safetyScore / 100) * CIRCUMFERENCE;

  return (
    <div className={`glass-card result-card ${cls}`}>
      {/* Safety Ring */}
      <div className="score-ring-wrapper" aria-label={`Safety score: ${safetyScore}%`}>
        <svg className="score-ring-svg" viewBox="0 0 100 100">
          <circle className="score-ring-bg" cx="50" cy="50" r="40" />
          <circle
            className={`score-ring-fill ${cls}`}
            cx="50" cy="50" r="40"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="score-ring-label">
          <span className={`score-value ${cls}`}>
            {isSafe ? '✓' : safetyScore}
          </span>
          <span className="score-tag">
            {isSafe ? 'safe' : 'safety'}
          </span>
        </div>
      </div>

      {/* Info */}
      <div className="result-info">
        <div className={`verdict-badge ${cls}`}>
          <span className="verdict-badge-dot" />
          {VERDICT_EMOJIS[verdict]}&nbsp; {VERDICT_LABELS[verdict] || verdict}
        </div>

        <div className="result-url">
          🔗 <a href={url} target="_blank" rel="noopener noreferrer">{url}</a>
        </div>

        <div className="result-meta">
          <div className="meta-item">
            <span className="meta-key">Safety Score</span>
            <span className="meta-val" style={{ color: isSafe ? 'var(--safe)' : safetyScore > 50 ? 'var(--suspicious)' : 'var(--malicious)' }}>
              {safetyScore} / 100
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-key">Confidence</span>
            <span className="meta-val">{confidence !== null ? `${Math.round((confidence || 0) * 100)}%` : '—'}</span>
          </div>
          <div className="meta-item">
            <span className="meta-key">Caught by</span>
            <span className="meta-val">{level_caught?.replace(/_/g, ' ') || '—'}</span>
          </div>
          <div className="meta-item">
            <span className="meta-key">Response</span>
            <span className="meta-val">{response_ms ? `${response_ms}ms` : '—'}</span>
          </div>
          {cached && (
            <div className="meta-item">
              <span className="meta-key">Source</span>
              <span className="meta-val">📦 Cached</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
