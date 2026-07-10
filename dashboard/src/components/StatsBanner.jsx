import React, { useEffect, useState, useMemo } from 'react';
import { getHealth } from '../api/scanApi';

const DEFAULT_STATS = {
  scansToday: 0,
  threatsBlocked: 0,
  avgResponseMs: 0,
  safeUrls: 0,
};

export default function StatsBanner({ scanHistory }) {
  const [health, setHealth] = useState({ gateway: 'loading', ml_service: 'loading' });

  // Derive stats from scan history
  const stats = useMemo(() => {
    if (!scanHistory?.length) return DEFAULT_STATS;
    const total = scanHistory.length;
    const threats = scanHistory.filter(r => r.verdict === 'MALICIOUS' || r.verdict === 'SUSPICIOUS').length;
    const safeCount = scanHistory.filter(r => r.verdict === 'SAFE').length;
    const avgMs = Math.round(scanHistory.reduce((s, r) => s + (r.response_ms || 0), 0) / total);
    return { 
      scansToday: total, 
      threatsBlocked: threats, 
      avgResponseMs: avgMs, 
      safeUrls: safeCount 
    };
  }, [scanHistory]);

  // One-time health check on mount (no periodic polling)
  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const h = await getHealth();
        setHealth(h);
      } catch {
        setHealth({ gateway: 'offline', ml_service: 'offline' });
      }
    };

    fetchHealth(); // Only once when component mounts
  }, []); // Empty dependency array = run once

  const gatewayOnline = health.gateway === 'ok';
  const mlOnline = health.ml_service === 'ok';
  
  return (
    <div className="stats-banner">
      <div className="glass-card stat-card">
        <span className="stat-label">Scans This Session</span>
        <span className="stat-value">{stats.scansToday}</span>
        <span className="stat-change">↑ active monitoring</span>
      </div>
      <div className="glass-card stat-card">
        <span className="stat-label">Threats Detected</span>
        <span className="stat-value" style={{
          background: stats.threatsBlocked > 0
            ? 'linear-gradient(135deg, var(--malicious), var(--suspicious))'
            : 'linear-gradient(135deg, var(--accent-blue), var(--accent-cyan))',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}>{stats.threatsBlocked}</span>
        <span className="stat-change" style={{ color: stats.threatsBlocked > 0 ? 'var(--malicious)' : 'var(--safe)' }}>
          {stats.threatsBlocked > 0 ? '⚠️ blocked' : '✓ all clear'}
        </span>
      </div>
      <div className="glass-card stat-card">
        <span className="stat-label">Avg Response</span>
        <span className="stat-value">{stats.avgResponseMs > 0 ? `${stats.avgResponseMs}` : '—'}</span>
        <span className="stat-change">{stats.avgResponseMs > 0 ? 'milliseconds' : 'no scans yet'}</span>
      </div>
      <div className="glass-card stat-card">
        <span className="stat-label">Service Status</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <span
              className={`status-dot ${health.gateway === 'loading' ? 'loading' : !gatewayOnline ? 'offline' : ''}`}
              aria-label={`Gateway: ${health.gateway}`}
            />
            <span style={{ color: 'var(--text-secondary)' }}>Gateway</span>
            <span style={{ color: gatewayOnline ? 'var(--safe)' : health.gateway === 'loading' ? 'var(--suspicious)' : 'var(--malicious)', marginLeft: 'auto', fontWeight: 600 }}>
              {health.gateway === 'loading' ? '...' : gatewayOnline ? 'Online' : 'Offline'}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <span
              className={`status-dot ${health.ml_service === 'loading' ? 'loading' : !mlOnline ? 'offline' : ''}`}
              aria-label={`ML Service: ${health.ml_service}`}
            />
            <span style={{ color: 'var(--text-secondary)' }}>ML Service</span>
            <span style={{ color: mlOnline ? 'var(--safe)' : health.ml_service === 'loading' ? 'var(--suspicious)' : 'var(--malicious)', marginLeft: 'auto', fontWeight: 600 }}>
              {health.ml_service === 'loading' ? '...' : mlOnline ? 'Online' : 'Offline'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
