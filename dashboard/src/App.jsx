import React, { useState } from 'react';
import { scanUrl } from './api/scanApi';
import ScanInput from './components/ScanInput';
import ResultCard from './components/ResultCard';
import ThreatTimeline from './components/ThreatTimeline';
import VisualPreview from './components/VisualPreview';
import ScoreBreakdown from './components/ScoreBreakdown';
import StatsBanner from './components/StatsBanner';

export default function App() {
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);

  const handleScan = async (url) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await scanUrl(url);
      setResult(data);
      setScanHistory(prev => [data, ...prev].slice(0, 100));
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Scan failed. Is the gateway running?';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className="header" role="banner">
        <div className="container header-inner">
          <div className="logo">
            <div className="logo-icon" aria-hidden="true">🛡️</div>
            <div>
              <div className="logo-text">LinkD</div>
              <div className="logo-sub">Phishing Intelligence</div>
            </div>
          </div>
          <div className="header-status" aria-live="polite">
            <span className={`status-dot ${isLoading ? 'loading' : ''}`} aria-hidden="true" />
            {isLoading ? 'Scanning…' : 'Ready'}
          </div>
        </div>
      </header>

      {/* ── Main ────────────────────────────────────────────────────────── */}
      <main className="main" id="main-content">
        <div className="container">

          {/* Hero */}
          <div className="hero">
            <h1 className="hero-title">
              Detect Phishing on<br />
              <span>Trusted Platforms</span>
            </h1>
            <p className="hero-subtitle">
              3-layer ML engine: heuristics + GitHub context + deep visual analysis.
              Catch phishing attacks hidden on GitHub Pages, Notion, Google Sites & more.
            </p>
          </div>

          {/* Scan Input */}
          <ScanInput onScan={handleScan} isLoading={isLoading} />

          {/* Stats Banner */}
          <StatsBanner scanHistory={scanHistory} />

          {/* Error State */}
          {error && (
            <div className="glass-card error-card" role="alert">
              <span className="error-icon" aria-hidden="true">⚠️</span>
              <div>
                <div className="error-title">Scan Failed</div>
                <div className="error-text">{error}</div>
              </div>
            </div>
          )}

          {/* Loading State */}
          {isLoading && (
            <div className="glass-card" style={{ padding: 32, textAlign: 'center', marginBottom: 32 }}>
              <div style={{ fontSize: 32, marginBottom: 16 }}>
                <span className="spinner" style={{ width: 32, height: 32, borderWidth: 3 }} />
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: 15 }}>
                Running multi-level phishing analysis…
              </p>
              <p style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 8 }}>
                Level 1 → Level 2 → Level 3 ML inference
              </p>
            </div>
          )}

          {/* Results */}
          {result && !isLoading && (
            <>
              <div className="result-section">
                <ResultCard result={result} />
              </div>
              <ThreatTimeline result={result} />
              <ScoreBreakdown result={result} />
              <VisualPreview result={result} />
            </>
          )}

          {/* Empty State */}
          {!result && !isLoading && !error && (
            <div className="empty-state">
              <div className="empty-icon" aria-hidden="true">🔍</div>
              <div className="empty-title">Enter a URL to begin analysis</div>
              <div className="empty-desc">
                The system will check caches, run heuristics, and escalate to ML inference if needed.
              </div>
            </div>
          )}

        </div>
      </main>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <footer className="footer" role="contentinfo">
        <div className="container">
          <p>
            LinkD Phishing Intelligence ·{' '}
            <a href="https://github.com" target="_blank" rel="noopener noreferrer">View on GitHub</a>
            {' '}· 3-Level ML Detection Engine
          </p>
        </div>
      </footer>
    </div>
  );
}
