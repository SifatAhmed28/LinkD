import React from 'react';

function getScoreColor(score) {
  if (score === null || score === undefined) return 'var(--accent-blue)';
  if (score < 0.33) return 'var(--safe)';
  if (score < 0.66) return 'var(--suspicious)';
  return 'var(--malicious)';
}

export default function ScoreBreakdown({ result }) {
  if (!result?.breakdown) return null;

  const { breakdown, verdict } = result;

  // Extract numeric signal scores
  const signals = [];

  // From L2 heuristic breakdown
  const b = breakdown || {};
  const numericKeys = Object.entries(b)
    .filter(([k, v]) => typeof v === 'number' && v >= 0 && v <= 1 && !['score', 'l2_score', 'l3_score', 'final_score'].includes(k));
  for (const [key, value] of numericKeys) {
    signals.push({ name: key.replace(/_/g, ' '), score: value });
  }

  // From ML breakdown
  if (b.ml) {
    const mlFusion = b.ml?.score_fusion?.l3_components;
    if (mlFusion) {
      for (const [key, value] of Object.entries(mlFusion)) {
        signals.push({ name: `ML: ${key}`, score: value });
      }
    }
  }

  if (signals.length === 0) return null;

  return (
    <div className="breakdown-section">
      <h3 className="section-title">📊 Signal Breakdown</h3>
      <div className="breakdown-grid">
        {signals.map(({ name, score }) => {
          const pct = Math.round(score * 100);
          const color = getScoreColor(score);
          return (
            <div key={name} className="breakdown-item">
              <div className="breakdown-name">{name}</div>
              <div className="breakdown-bar-track">
                <div
                  className="breakdown-bar-fill"
                  style={{ width: `${pct}%`, background: color }}
                />
              </div>
              <div className="breakdown-score" style={{ color }}>
                {pct}%
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
