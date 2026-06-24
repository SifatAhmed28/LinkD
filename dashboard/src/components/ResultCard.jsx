import React from 'react';

const VERDICT_EMOJIS = { SAFE: '🛡️', SUSPICIOUS: '⚠️', MALICIOUS: '☠️' };
const VERDICT_LABELS = { SAFE: 'Safe', SUSPICIOUS: 'Suspicious', MALICIOUS: 'Malicious' };
const CIRCUMFERENCE = 2 * Math.PI * 40; // r=40

export default function ResultCard({ result }) {
  if (!result) return null;

  const { url, verdict, score, confidence, level_caught, response_ms, cached } = result;
  const cls = verdict?.toLowerCase() || 'safe';
  const scorePercent = Math.round((score ?? 0) * 100);
  const isZeroScore = (score === 0 || score === 0.0 || score === null || score === undefined);
  const isWhitelistedSafe = isZeroScore && verdict === 'SAFE';
  // For a whitelisted/clean URL (score=0, SAFE): show a full ring instead of empty ring
  const offset = isWhitelistedSafe ? 0 : CIRCUMFERENCE - (scorePercent / 100) * CIRCUMFERENCE;

  return (
    <div className={`glass-card result-card ${cls}`}>
      {/* Score Ring */}
      <div className="score-ring-wrapper" aria-label={`Threat score: ${scorePercent}%`}>
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
            {isWhitelistedSafe ? '✓' : scorePercent}
          </span>
          <span className="score-tag">
            {isWhitelistedSafe ? 'clean' : 'score'}
          </span>
        </div>
      </div>

      {/* Info */}
      <div className="result-info">
        <div className={`verdict-badge ${cls}`}>
          <span className="verdict-badge-dot" />
          {VERDICT_EMOJIS[verdict]} &nbsp; {VERDICT_LABELS[verdict] || verdict}
        </div>

        <div className="result-url">
          🔗 <a href={url} target="_blank" rel="noopener noreferrer">{url}</a>
        </div>

        <div className="result-meta">
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
