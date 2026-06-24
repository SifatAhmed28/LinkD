import React from 'react';

export default function VisualPreview({ result }) {
  if (!result) return null;

  const { screenshot_url, ocr_text, verdict, breakdown } = result;
  const mlBreakdown = breakdown?.ml;

  // Show section if screenshot was captured OR ocr text exists OR any ML visual data is present
  const hasVisualData = screenshot_url || ocr_text || mlBreakdown?.ocr || mlBreakdown?.visual_similarity;
  if (!hasVisualData) return null;

  const screenshotSrc = screenshot_url
    ? `${import.meta.env.VITE_ML_SERVICE_URL || 'http://localhost:8000'}${screenshot_url}`
    : null;

  const ocrDetail = mlBreakdown?.ocr;
  const visualSimilarity = mlBreakdown?.visual_similarity;

  return (
    <div className="preview-section">
      <h3 className="section-title">📸 Visual Analysis</h3>
      <div className="glass-card preview-card">
        <div className="preview-grid">

          {/* Screenshot */}
          <div>
            <p className="preview-label">Page Screenshot</p>
            {screenshotSrc ? (
              <div className="preview-image-wrapper">
                <img
                  className="preview-image"
                  src={screenshotSrc}
                  alt="Scanned page screenshot"
                  onError={(e) => {
                    e.target.parentElement.innerHTML =
                      '<div style="padding:40px;text-align:center;color:var(--text-muted);font-size:13px;">📷 Screenshot unavailable</div>';
                  }}
                />
                <div className="preview-image-overlay" />
              </div>
            ) : (
              <div style={{
                padding: '40px',
                textAlign: 'center',
                color: 'var(--text-muted)',
                fontSize: '13px',
                background: 'var(--bg-glass)',
                borderRadius: 'var(--radius-md)',
                border: '1px dashed var(--border)',
                minHeight: 120,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
              }}>
                <span style={{ fontSize: 28 }}>🖥️</span>
                <span>Screenshot not captured</span>
                {verdict === 'SAFE' && (
                  <span style={{ fontSize: 11, opacity: 0.6 }}>Page may have been unreachable or blocked</span>
                )}
              </div>
            )}
          </div>

          {/* OCR + Visual Similarity */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* OCR Extracted Text */}
            <div>
              <p className="preview-label">
                OCR Extracted Text
                {ocrDetail?.ocr_score !== undefined && (
                  <span style={{
                    marginLeft: 8,
                    fontSize: 11,
                    padding: '2px 8px',
                    borderRadius: 99,
                    background: 'var(--bg-glass)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    score: {Math.round((ocrDetail.ocr_score || 0) * 100)}%
                  </span>
                )}
              </p>
              {ocr_text ? (
                <div className="ocr-text-box" aria-label="OCR extracted text">
                  {ocr_text}
                </div>
              ) : (
                <div className="ocr-text-box" style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  {!screenshot_url
                    ? '📷 No screenshot — OCR skipped.'
                    : '📄 No readable text found in screenshot.'}
                </div>
              )}
            </div>

            {/* Visual Similarity */}
            <div>
              <p className="preview-label">Visual Brand Similarity</p>
              <div style={{
                background: 'var(--bg-glass)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 14px',
                fontSize: 13,
              }}>
                {visualSimilarity ? (
                  visualSimilarity.matched_brand ? (
                    <>
                      <p style={{ color: 'var(--text-primary)', marginBottom: 6, fontWeight: 600 }}>
                        Matched: <span style={{ color: 'var(--accent-cyan)' }}>{visualSimilarity.matched_brand}</span>
                      </p>
                      <p style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>
                        Similarity:{' '}
                        <strong style={{ fontFamily: 'var(--font-mono)' }}>
                          {Math.round((visualSimilarity.best_similarity || 0) * 100)}%
                        </strong>
                        {' '}/ threshold: {Math.round((visualSimilarity.similarity_threshold || 0.82) * 100)}%
                      </p>
                      {visualSimilarity.flags?.length > 0 && (
                        <p style={{ color: 'var(--malicious)', marginTop: 6, fontWeight: 500 }}>
                          ⚠️ {visualSimilarity.flags[0].replace(/_/g, ' ')}
                        </p>
                      )}
                    </>
                  ) : (
                    <p style={{ color: 'var(--text-muted)' }}>
                      {!screenshot_url
                        ? '📷 No screenshot — brand check skipped.'
                        : visualSimilarity.info || 'No brand match above similarity threshold.'}
                    </p>
                  )
                ) : (
                  <p style={{ color: 'var(--text-muted)' }}>
                    {!screenshot_url ? '📷 No screenshot — brand check skipped.' : 'Brand analysis unavailable.'}
                  </p>
                )}
              </div>
            </div>

          </div>
        </div>
      </div>
    </div>
  );
}
