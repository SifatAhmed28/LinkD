import React, { useState } from 'react';

const LEVELS = [
  {
    key: 'L1_WHITELIST',
    label: 'Level 1 — Static Whitelist',
    desc: 'Checked against trusted domain list (in-memory Set lookup)',
  },
  {
    key: 'L1_CACHE',
    label: 'Level 1 — Cache Verification',
    desc: 'Checked Redis/LRU cache with SHA-256 content hash validation',
  },
  {
    key: 'L2_HEURISTICS',
    label: 'Level 2 — Heuristics Engine',
    desc: 'Pattern detection, domain mismatch, obfuscation, GitHub context',
  },
  {
    key: 'L3_ML',
    label: 'Level 3 — ML Inference',
    desc: 'RoBERTa sentiment, ResNet-50 visual, EasyOCR, form analysis',
  },
];

function getLevelStatus(levelKey, caughtAt, verdict) {
  const levels = ['L1_WHITELIST', 'L1_CACHE', 'L2_HEURISTICS', 'L3_ML'];
  const caughtIdx = levels.indexOf(caughtAt);
  const thisIdx = levels.indexOf(levelKey);

  if (thisIdx < caughtIdx) return 'pass';
  if (thisIdx === caughtIdx) {
    if (verdict === 'SAFE') return 'pass';
    if (verdict === 'MALICIOUS') return 'catch';
    return 'warning';
  }
  return 'skip';
}

function getStatusLabel(status) {
  return { pass: 'Passed', catch: 'Caught', warning: 'Flagged', skip: 'Skipped' }[status];
}

function getStatusIcon(status) {
  return { pass: '✓', catch: '✗', warning: '!', skip: '–' }[status];
}

export default function ThreatTimeline({ result }) {
  const [expanded, setExpanded] = useState(null);
  if (!result) return null;

  const { level_caught, verdict, breakdown } = result;
  const isCachedHit = result.cached;

  const effectiveCaught = isCachedHit ? 'L1_CACHE' : level_caught;

  // Collect flags for each level
  const l2Flags = [
    ...(breakdown?.obfuscationFlags || []),
    ...(breakdown?.githubFlags || []),
    ...(breakdown?.domainMismatches?.length > 0 ? ['domain_mismatch_detected'] : []),
  ];

  const l3Flags = [
    ...(breakdown?.ml?.sentiment?.exceeds_threshold ? ['fear_threshold_exceeded'] : []),
    ...(breakdown?.ml?.form_behavior?.flags || []),
    ...(breakdown?.ml?.ocr?.flags || []),
    ...(breakdown?.ml?.visual_similarity?.flags || []),
  ];

  const flagMap = {
    L1_WHITELIST: [],
    L1_CACHE: [],
    L2_HEURISTICS: l2Flags,
    L3_ML: l3Flags,
  };

  return (
    <div className="timeline-section">
      <h3 className="section-title">🔍 Detection Trail</h3>
      <div className="timeline">
        {LEVELS.map((level, idx) => {
          const status = getLevelStatus(level.key, effectiveCaught, verdict);
          const flags = flagMap[level.key] || [];
          const isExpanded = expanded === level.key;

          return (
            <div key={level.key} className="timeline-item">
              <div className="timeline-connector">
                <div className={`timeline-dot ${status}`}>
                  {getStatusIcon(status)}
                </div>
                {idx < LEVELS.length - 1 && <div className="timeline-line" />}
              </div>

              <div
                className="timeline-content"
                onClick={() => setExpanded(isExpanded ? null : level.key)}
                role="button"
                aria-expanded={isExpanded}
              >
                <div className="timeline-header">
                  <span className="timeline-level">{level.label}</span>
                  <span className={`timeline-badge ${status}`}>{getStatusLabel(status)}</span>
                </div>
                <p className="timeline-desc">{level.desc}</p>
                {isExpanded && flags.length > 0 && (
                  <div className="timeline-flags">
                    {flags.map((flag, i) => (
                      <span key={i} className="flag-chip">{flag.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                )}
                {isExpanded && flags.length === 0 && status !== 'skip' && (
                  <div className="timeline-flags">
                    <span className="flag-chip" style={{ background: 'rgba(16,185,129,0.1)', color: '#6ee7b7', borderColor: 'rgba(16,185,129,0.2)' }}>
                      no flags raised
                    </span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
