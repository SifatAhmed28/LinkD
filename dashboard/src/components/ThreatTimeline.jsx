import React, { useState } from 'react';

// ── Level definitions ─────────────────────────────────────────────────────────
const LEVELS = [{
        key: 'L1_WHITELIST',
        label: 'Level 1 — Static Whitelist',
        icon: '🛡️',
        desc: 'Instant trusted-domain lookup — O(1) in-memory Set check',
    },
    {
        key: 'L1_CACHE',
        label: 'Level 1 — Cache Verification',
        icon: '⚡',
        desc: 'Redis/LRU cache hit with SHA-256 content-hash validation',
    },
    {
        key: 'L2_HEURISTICS',
        label: 'Level 2 — Heuristics Engine',
        icon: '🔬',
        desc: 'URL structure, HTML fingerprints, WHOIS, Tranco rank, brand mismatch',
    },
    {
        key: 'L3_ML',
        label: 'Level 3 — ML Inference',
        icon: '🧠',
        desc: 'RoBERTa sentiment · ResNet-50 visual · EasyOCR · Form analysis',
    },
];

// ── Ordered pipeline ──────────────────────────────────────
const PIPELINE = ['L1_WHITELIST', 'L1_CACHE', 'L2_HEURISTICS', 'L3_ML'];

function getLevelStatus(levelKey, caughtAt, verdict) {
    const caughtIdx = PIPELINE.indexOf(caughtAt);
    const thisIdx = PIPELINE.indexOf(levelKey);
    if (caughtIdx === -1 || thisIdx === -1) return 'skip';
    if (thisIdx < caughtIdx) return 'pass';
    if (thisIdx === caughtIdx) {
        if (verdict === 'SAFE') return 'pass';
        if (verdict === 'MALICIOUS') return 'catch';
        return 'warning';
    }
    return 'skip';
}

const STATUS_LABEL = { pass: 'Passed', catch: 'Caught', warning: 'Flagged', skip: 'Skipped' };
const STATUS_ICON = { pass: '✓', catch: '✗', warning: '!', skip: '–' };

// ── Sub-feature builders for each level ──────────────────────────────────────
function buildL1WhitelistFeatures(result) {
    const f = result?.breakdown?.ml?.l2_features || result?.breakdown?.l2_features || {};

    return [{
            label: 'Exact domain whitelist match',
            ok: result?.level_caught === 'L1_WHITELIST' && result?.verdict === 'SAFE' && !f.whitelistPartialMatch,
            note: 'Registered domain found in trusted-domain list',
        },
        {
            label: 'Subdomain trust check',
            ok: !f.whitelistPartialMatch,
            warn: f.whitelistPartialMatch,
            note: f.whitelistPartialMatch ?
                'Multi-level subdomain of whitelisted domain — sent to L2' : 'Single-level subdomain — trusted',
        },
        {
            label: 'Trust score ≥ 1.0',
            ok: result?.level_caught === 'L1_WHITELIST',
            note: result?.level_caught === 'L1_WHITELIST' ? 'Fast-path granted' : 'Did not trigger fast-path',
        },
    ];
}

function buildL1CacheFeatures(result) {
    const cached = result?.cached;
    return [{
            label: 'Redis/LRU cache hit',
            ok: cached,
            note: cached ? 'Served from cache' : 'Cache miss — proceeded to L2',
        },
        {
            label: 'Content hash match',
            ok: cached,
            note: cached ? 'SHA-256 content hash verified — page unchanged' : 'N/A',
        },
        {
            label: 'Schema version match',
            ok: true,
            note: 'Cache entry uses current feature schema version',
        },
    ];
}

// Named labels for every L2 feature key
const L2_FEATURE_LABELS = {
    // URL structure
    url_entropy: { label: 'URL Shannon entropy', desc: 'High entropy → obfuscated/random chars' },
    url_digit_ratio: { label: 'Digit ratio in URL', desc: 'High digit density is suspicious' },
    url_letter_ratio: { label: 'Letter ratio in URL', desc: 'Very low → mostly digits/symbols' },
    url_num_dots: { label: 'Dot count in URL', desc: 'Excess dots → subdomain chains' },
    url_num_slashes: { label: 'Slash count', desc: 'Deep path nesting' },
    url_num_hyphens: { label: 'Hyphen count', desc: 'Brand-spoofing hyphens' },
    url_num_equals: { label: 'Equals signs (params)', desc: 'Many params can hide intent' },
    url_num_question: { label: 'Query strings', desc: 'Multiple "?" is unusual' },
    url_num_ampersand: { label: 'Ampersands (params)', desc: 'Long param chains' },
    url_num_percent: { label: 'Percent-encoding count', desc: 'URL-encoded obfuscation' },
    url_num_double_slash: { label: 'Double-slash count', desc: 'Unusual double slashes' },
    url_num_sensitive_words: { label: 'Sensitive keywords', desc: 'Words: login, secure, verify, update…' },
    url_has_at_symbol: { label: 'At-symbol (@) in URL', desc: 'Used to hide real hostname' },
    url_prefix_suffix_hyphen: { label: 'Brand prefix/suffix hyphen', desc: 'e.g. paypal-secure.com' },
    // HTML fingerprints
    html_num_eval_calls: { label: 'eval() calls in JS', desc: 'Obfuscated JavaScript execution' },
    html_num_unescape_calls: { label: 'unescape() calls', desc: 'Decodes hidden malicious strings' },
    html_has_right_click_disabled: { label: 'Right-click disabled', desc: 'Hides source inspection' },
    sfh_is_empty: { label: 'Form action empty', desc: 'Form submits to nothing' },
    sfh_is_about_blank: { label: 'Form action about:blank', desc: 'Form data goes nowhere visibly' },
    html_has_favicon: { label: 'Favicon present', desc: 'Legitimate sites always have one' },
    html_num_hidden_inputs: { label: 'Hidden input fields', desc: 'Harvesting data silently' },
    // Pattern signals
    fearDetected: { label: 'Fear language detected', desc: 'Urgency/threat/warning wording' },
    credentialDetected: { label: 'Credential keywords', desc: 'Password/SSN/card number requests' },
    // Domain intelligence
    inferred_brand: { label: 'Inferred brand target', desc: 'Brand the page pretends to be' },
    brand_domain_match: { label: 'Brand domain matches', desc: "Page is on brand's real domain" },
    whitelistPartialMatch: { label: 'Whitelist partial match', desc: 'Subdomain of trusted domain' },
    tranco_in_top10k: { label: 'Tranco top-10k domain', desc: 'Popular legitimate domains' },
    tranco_rank_bucket: { label: 'Tranco rank bucket', desc: 'top1k / top10k / none' },
    // WHOIS
    domain_age_days: { label: 'Domain age (days)', desc: 'Newly registered = high risk' },
    domain_expiry_days: { label: 'Domain expiry (days)', desc: 'Short registration window' },
    days_since_last_update: { label: 'Days since WHOIS update', desc: 'Recently updated = suspicious' },
    registrar_category: { label: 'Registrar category', desc: 'major / budget / unknown' },
    has_registrant_org: { label: 'Registrant org present', desc: 'Privacy-shielded = suspicious' },
    has_registrant_email: { label: 'Registrant email present', desc: 'Absent → privacy proxy' },
    has_registrant_phone: { label: 'Registrant phone present', desc: 'Absent → privacy proxy' },
    domain_name_match: { label: 'WHOIS matches brand', desc: 'Registrant org mentions brand' },
};

function featureValue(val) {
    if (val === null || val === undefined) return { display: '—', neutral: true };
    if (typeof val === 'boolean') return { display: val ? 'Yes' : 'No', ok: !val, bad: val };
    if (typeof val === 'number') return { display: val % 1 === 0 ? String(val) : val.toFixed(3), neutral: true };
    return { display: String(val), neutral: true };
}

// Risk check: flag features that look bad
const RISK_FLAGS = {
    url_entropy: (v) => v > 4.5,
    url_digit_ratio: (v) => v > 0.3,
    url_num_hyphens: (v) => v >= 2,
    url_num_percent: (v) => v > 0,
    url_num_double_slash: (v) => v > 0,
    url_num_sensitive_words: (v) => v >= 2,
    url_has_at_symbol: (v) => v === true,
    url_prefix_suffix_hyphen: (v) => v === true,
    html_num_eval_calls: (v) => v > 0,
    html_num_unescape_calls: (v) => v > 0,
    html_has_right_click_disabled: (v) => v === true,
    sfh_is_empty: (v) => v === true,
    sfh_is_about_blank: (v) => v === true,
    html_has_favicon: (v) => v === false,
    html_num_hidden_inputs: (v) => v > 2,
    fearDetected: (v) => v === true,
    credentialDetected: (v) => v === true,
    brand_domain_match: (v) => v === false,
    whitelistPartialMatch: (v) => v === true,
    tranco_in_top10k: (v) => v === false,
    domain_age_days: (v) => v !== null && v < 30,
    registrar_category: (v) => v === 'budget',
    has_registrant_org: (v) => v === false,
};

function buildL2Features(result) {
    // features are in breakdown.ml.l2_features (L3 path) or breakdown.l2_features (L2 path)
    const f = result?.breakdown?.ml?.l2_features || result?.breakdown?.l2_features;
    if (!f) return [];
    return Object.entries(L2_FEATURE_LABELS).map(([key, meta]) => {
        const val = f[key];
        const isRisky = RISK_FLAGS[key]?.(val) || false;
        const vf = featureValue(val);
        return {
            label: meta.label,
            desc: meta.desc,
            display: vf.display,
            ok: !isRisky && val !== null && val !== undefined,
            bad: isRisky,
            neutral: val === null || val === undefined,
        };
    });
}

function buildL3Features(result) {
    const ml = result?.breakdown?.ml;
    if (!ml) return [];
    const fusion = ml.score_fusion || {};
    const items = [];

    // Fear / sentiment
    items.push({
        label: 'Sentiment fear score',
        desc: 'RoBERTa model: urgency / threat language',
        display: ml.sentiment?.fear_score !== undefined ? ml.sentiment.fear_score.toFixed(3) : (ml.sentiment?.error ? 'N/A' : '—'),
        ok: !ml.sentiment?.exceeds_threshold,
        bad: ml.sentiment?.exceeds_threshold,
        neutral: !!ml.sentiment?.error,
        note: ml.sentiment?.error || undefined,
    });

    // Form behavior
    const fs = ml.form_behavior;
    items.push({
        label: 'Form behavior score',
        desc: 'Cross-origin submit, password harvesting, empty SFH',
        display: fs?.form_score !== undefined ? fs.form_score.toFixed(3) : '0.000',
        ok: (fs?.form_score?? 0) < 0.3,
        bad: (fs?.form_score?? 0) >= 0.5,
        neutral: (fs?.form_score?? 0) < 0.5 && (fs?.form_score?? 0) >= 0.3,
    });

    // OCR
    const ocr = ml.ocr;
    items.push({
        label: 'OCR text analysis',
        desc: 'EasyOCR text extracted from screenshot',
        display: result?.ocr_text?.length ? `${result.ocr_text.length} chars` : (ocr?.error ? 'N/A' : '—'),
        ok: !ocr?.flags?.length,
        bad: ocr?.flags?.length > 0,
        neutral: !ocr || !!ocr.error,
        note: ocr?.error || undefined,
    });

    // Visual similarity
    const vis = ml.visual_similarity;
    items.push({
        label: 'Visual brand similarity',
        desc: 'ResNet-50 cosine similarity vs brand screenshots',
        display: vis?.visual_score !== undefined ? vis.visual_score.toFixed(3) : (vis?.best_similarity !== undefined ? `${vis.best_similarity.toFixed(3)} (no spoof)` : '—'),
        ok: (vis?.visual_score ?? 0) < 0.82,
        bad: (vis?.visual_score ?? 0) >= 0.82,
        neutral: !vis || vis.visual_score === undefined,
        note: vis?.error || undefined,
    });

    // Final fusion scores
    items.push({
        label: 'L2 influence weight',
        desc: 'How much L2 heuristics shaped the final score',
        display: fusion.l2_influence !== undefined ? `${Math.round(fusion.l2_influence * 100)}%` : '—',
        neutral: true,
    });
    items.push({
        label: 'L3 signals fired',
        desc: 'Number of L3 detectors that returned a non-zero score',
        display: fusion.l3_signals_fired !== undefined ? String(fusion.l3_signals_fired) : '—',
        // 0 = ML analysis skipped/failed (neutral), ≥1 = ML ran (ok), high count = more evidence
        ok: (fusion.l3_signals_fired ?? 0) >= 1,
        bad: false,
        neutral: fusion.l3_signals_fired === undefined || fusion.l3_signals_fired === 0,
    });

    return items;
}

// ── Sub-feature list renderer ─────────────────────────────────────────────────
function FeatureList({ items }) {
    if (!items || items.length === 0) return null;
    return (
        <div className="feature-list">
      {items.map((item, i) => (
        <div key={i} className={`feature-row ${item.bad ? 'bad' : item.ok ? 'ok' : 'neutral'}`}>
          <span className="feature-icon">
            {item.bad ? '✗' : item.ok ? '✓' : '–'}
          </span>
          <div className="feature-body">
            <div className="feature-label-row">
              <span className="feature-label">{item.label}</span>
              <span className={`feature-value ${item.bad ? 'bad' : item.ok ? 'ok' : ''}`}>
                {item.display ?? '—'}
              </span>
            </div>
            <div className="feature-desc">{item.desc}</div>
            {item.note && <div className="feature-note">{item.note}</div>}
          </div>
        </div>
      ))}
    </div>
    );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function ThreatTimeline({ result }) {
    const [expanded, setExpanded] = useState(null);
    if (!result) return null;

    const { level_caught, verdict } = result;
    const isCachedHit = result.cached;
    const effectiveCaught = isCachedHit ?
        'L1_CACHE' :
        (level_caught || 'L3_ML');

    const featureBuilders = {
        L1_WHITELIST: () => buildL1WhitelistFeatures(result),
        L1_CACHE: () => buildL1CacheFeatures(result),
        L2_HEURISTICS: () => buildL2Features(result),
        L3_ML: () => buildL3Features(result),
    };

    return (
        <div className="timeline-section">
      <h3 className="section-title">🔍 Detection Trail</h3>
      <div className="timeline">
        {LEVELS.map((level, idx) => {
          const status    = getLevelStatus(level.key, effectiveCaught, verdict);
          const isExpanded = expanded === level.key;
          const features  = isExpanded ? featureBuilders[level.key]?.() || [] : [];
          const isActive  = status !== 'skip';

          return (
            <div key={level.key} className="timeline-item">
              {/* Connector */}
              <div className="timeline-connector">
                <div className={`timeline-dot ${status}`}>
                  {STATUS_ICON[status]}
                </div>
                {idx < LEVELS.length - 1 && <div className="timeline-line" />}
              </div>

              {/* Content */}
              <div
                className={`timeline-content ${isExpanded ? 'expanded' : ''}`}
                onClick={() => isActive && setExpanded(isExpanded ? null : level.key)}
                role={isActive ? 'button' : undefined}
                aria-expanded={isExpanded}
                style={{ cursor: isActive ? 'pointer' : 'default' }}
              >
                <div className="timeline-header">
                  <span className="timeline-level">
                    <span className="timeline-icon">{level.icon}</span>
                    {level.label}
                  </span>
                  <div className="timeline-header-right">
                    <span className={`timeline-badge ${status}`}>{STATUS_LABEL[status]}</span>
                    {isActive && (
                      <span className="timeline-chevron" aria-hidden="true">
                        {isExpanded ? '▲' : '▼'}
                      </span>
                    )}
                  </div>
                </div>
                <p className="timeline-desc">{level.desc}</p>

                {/* Expanded sub-features */}
                {isExpanded && (
                  <div className="timeline-features">
                    <FeatureList items={features} />
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