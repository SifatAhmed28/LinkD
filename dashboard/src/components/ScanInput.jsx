import React, { useRef, useState } from 'react';

const PLACEHOLDER_URLS = [
  'https://github.com/suspicious-login/secure-paypal',
  'https://google-verify.github.io/account-recovery/',
  'https://bit.ly/3aBcDef',
  'https://microsoft-support.notion.site/account-verify',
];

export default function ScanInput({ onScan, isLoading }) {
  const [url, setUrl] = useState('');
  const inputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed || isLoading) return;
    onScan(trimmed);
  };

  const handleSuggestion = (suggestion) => {
    setUrl(suggestion);
    inputRef.current?.focus();
  };

  return (
    <div className="scan-section">
      <form className="scan-form" onSubmit={handleSubmit} id="scan-form">
        <div className="scan-input-wrapper">
          <span className="scan-input-icon">🔗</span>
          <input
            ref={inputRef}
            id="url-input"
            className="scan-input"
            type="text"
            placeholder="Enter a URL to analyze (e.g. github.com/user/repo or https://...)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isLoading}
            autoComplete="off"
            spellCheck="false"
            aria-label="URL to scan — https:// prefix will be added automatically if omitted"
          />
        </div>
        <button
          id="scan-btn"
          type="submit"
          className={`scan-btn ${isLoading ? 'loading' : ''}`}
          disabled={isLoading || !url.trim()}
          aria-busy={isLoading}
        >
          <span className="scan-btn-inner">
            {isLoading ? (
              <>
                <span className="spinner" aria-hidden="true" />
                Scanning…
              </>
            ) : (
              <>🔍 Analyze</>
            )}
          </span>
        </button>
      </form>

      {/* Example URLs */}
      <div style={{ marginTop: '12px', display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Try:</span>
        {PLACEHOLDER_URLS.slice(0, 3).map((suggestion) => (
          <button
            key={suggestion}
            className="suggestion-chip"
            onClick={() => handleSuggestion(suggestion)}
            title={suggestion}
          >
            {suggestion.replace('https://', '').substring(0, 30)}…
          </button>
        ))}
      </div>
    </div>
  );
}
