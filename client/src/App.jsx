import React, { useState, useEffect, useRef } from 'react';
import './App.css';

function App() {
  const [logs, setLogs] = useState([]);
  const [history, setHistory] = useState(new Array(30).fill(0));
  const [status, setStatus] = useState({
    status: 'Disconnected',
    monitored_path: '--',
    engine: 'Sentinel Heuristic v2.0',
    threats_blocked: 0,
    ops_rate: 0,
    attack_rate: 0
  });

  const [alert, setAlert] = useState(null);
  const [isOffline, setIsOffline] = useState(true);

  // If all stats are 0, it likely means the detector isn't running
  const isDetectorDown = !isOffline && status.ops_rate === 0 && status.attack_rate === 0 && logs.length === 0;

  const fetchStatus = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/status');
      if (!response.ok) throw new Error("Offline");
      const data = await response.json();
      setStatus(data);
      setIsOffline(false);
      
      setHistory(prev => {
        const newHistory = [...prev, data.ops_rate || 0];
        return newHistory.slice(-30);
      });

      if (data.threats_blocked > status.threats_blocked) {
        const msg = `[CRITICAL] PROACTIVE BLOCK: Neutralized high-risk process at ${new Date().toLocaleTimeString()}`;
        setAlert(msg);
        setTimeout(() => setAlert(null), 8000);
      }
    } catch (error) {
      setIsOffline(true);
      setStatus(prev => ({ ...prev, status: 'Offline' }));
    }
  };

  const fetchLogs = async () => {
    if (isOffline) return;
    try {
      const response = await fetch('http://localhost:5000/api/logs');
      const data = await response.json();
      setLogs(data);
    } catch (error) {
      console.error("Error fetching logs:", error);
    }
  };

  useEffect(() => {
    const interval = setInterval(() => {
      fetchStatus();
      fetchLogs();
    }, 1000);
    return () => clearInterval(interval);
  }, [status.threats_blocked, isOffline]);

  const getLogClass = (line) => {
    if (line.includes('[CRITICAL]') || line.includes('BLOCK')) return 'critical';
    if (line.includes('[WARNING]') || line.includes('SUSPICIOUS')) return 'warning';
    return 'info';
  };

  // SVG Graph Logic for a larger graph
  // SVG Graph Logic - Smooth Bezier Curve
  const maxOps = Math.max(...history, 10);
  
  // Calculate smooth path string
  const getPath = () => {
    if (history.length < 2) return "";
    let d = `M 0,${100 - (history[0] / maxOps) * 100}`;
    for (let i = 0; i < history.length - 1; i++) {
      const x1 = (i / 29) * 100;
      const y1 = 100 - (history[i] / maxOps) * 100;
      const x2 = ((i + 1) / 29) * 100;
      const y2 = 100 - (history[i+1] / maxOps) * 100;
      const cx = (x1 + x2) / 2;
      d += ` C ${cx},${y1} ${cx},${y2} ${x2},${y2}`;
    }
    return d;
  };

  const smoothPath = getPath();

  return (
    <div className={`dashboard ${isOffline ? 'offline-mode' : ''}`}>
      {alert && (
        <div className="alert-banner-large">
          <div className="alert-icon">⚠️</div>
          <div className="alert-content">
            <div className="alert-title">THREAT NEUTRALIZED</div>
            <div className="alert-msg">{alert}</div>
          </div>
          <button className="alert-close" onClick={() => setAlert(null)}>×</button>
        </div>
      )}

      {isOffline && (
        <div className="connection-warning">
          ⚠️ BACKEND API UNREACHABLE - Ensure server/main.py is running
        </div>
      )}

      {isDetectorDown && (
        <div className="detector-warning">
          <span className="pulse-yellow"></span> DETECTOR ENGINE OFFLINE - Run: <code>python ransomware-detector/main.py</code>
        </div>
      )}

      <header className="header">
        <div className="logo-section">
          <div className="shield-icon">🛡️</div>
          <div>
            <h1>SENTINEL <span className="highlight">CORE</span></h1>
            <p className="subtitle">Real-time Ransomware Protection System</p>
          </div>
        </div>
        <div className={`status-badge ${!isOffline ? (isDetectorDown ? 'warning' : 'online') : 'offline'}`}>
          <span className="dot"></span> {!isOffline ? (isDetectorDown ? 'STANDBY' : 'SYSTEM ACTIVE') : 'SYSTEM OFFLINE'}
        </div>
      </header>

      <div className="main-layout">
        <div className="left-column">
          <div className="stats-grid-horizontal">
            <div className="stat-card-mini glass">
              <div className="label">THREATS STOPPED</div>
              <div className="value danger-text">{status.threats_blocked}</div>
            </div>
            <div className="stat-card-mini glass">
              <div className="label">ATTACK LOAD</div>
              <div className="value">{status.attack_rate}%</div>
            </div>
          </div>

          <section className="logs-container-new glass">
            <div className="section-header">
              <h2>Intelligence Feed</h2>
              <div className="scan-line"></div>
            </div>
            <div className="logs-list">
              {logs.length > 0 ? logs.map((log, index) => (
                <div key={index} className={`log-item ${getLogClass(log)}`}>
                  <span className="timestamp">[{new Date().toLocaleTimeString()}]</span> {log}
                </div>
              )) : (
                <div className="log-item info">Monitoring system kernels... (Start detector to see live feed)</div>
              )}
            </div>
          </section>

          <div className="graph-container-professional glass">
            <div className="graph-header">
              <div className="header-info">
                <div className="status-indicator">
                  <span className="pulse-cyan"></span>
                  <span className="live-text">LIVE TELEMETRY</span>
                </div>
                <h2>Protection Ops Rate</h2>
              </div>
              <div className="current-metric">
                <span className="metric-value">{status.ops_rate.toFixed(1)}</span>
                <span className="metric-unit">OPS/S</span>
              </div>
            </div>
            
            <div className="main-graph">
              <svg viewBox="0 -10 100 120" preserveAspectRatio="none" className="graph-svg">
                <defs>
                  <linearGradient id="neonGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style={{stopColor:'var(--accent)', stopOpacity:0.2}} />
                    <stop offset="100%" style={{stopColor:'var(--accent)', stopOpacity:0}} />
                  </linearGradient>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="1.5" result="coloredBlur"/>
                    <feMerge>
                        <feMergeNode in="coloredBlur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>
                </defs>
                
                {/* Grid Lines */}
                {[0, 25, 50, 75, 100].map(h => (
                  <line key={h} x1="0" y1={h} x2="100" y2={h} stroke="rgba(255,255,255,0.05)" strokeWidth="0.2" />
                ))}

                {/* Area Fill */}
                <path d={`${smoothPath} L 100 100 L 0 100 Z`} fill="url(#neonGrad)" />
                
                {/* Smooth Neon Line */}
                <path d={smoothPath} fill="none" stroke="var(--accent)" strokeWidth="1" filter="url(#glow)" />

                {/* Latest Data Point Glow */}
                {history.length > 0 && (
                  <circle 
                    cx="100" 
                    cy={100 - (history[history.length-1] / maxOps) * 100} 
                    r="1.5" 
                    fill="var(--accent)" 
                    className="latest-point"
                  />
                )}
              </svg>
              {isDetectorDown && (
                <div className="graph-placeholder">Synchronizing with Sentinel Core...</div>
              )}
            </div>
            
            <div className="graph-footer">
              <div className="time-labels">
                <span>-30s</span>
                <span>NOW</span>
              </div>
            </div>
          </div>
        </div>

        <aside className="right-column">
          <div className="threat-gauge-card glass">
            <h3>Attack Intensity</h3>
            <div className="gauge-outer">
              <div className="gauge-inner" style={{ 
                height: `${status.attack_rate}%`,
                background: `linear-gradient(to top, var(--success), ${status.attack_rate > 50 ? 'var(--danger)' : 'var(--warning)'})`
              }}></div>
              <div className="gauge-label">{status.attack_rate}%</div>
            </div>
          </div>

          <div className="defense-status-card glass">
            <h3>Active Defenses</h3>
            {['Honeypot Trap', 'Entropy Shield', 'Shadow Protector'].map((d, i) => (
              <div key={i} className="defense-row">
                <span>{d}</span>
                <span className="status-tag" style={{color: isDetectorDown ? '#666' : 'var(--success)'}}>
                  {isDetectorDown ? 'INACTIVE' : 'SECURE'}
                </span>
              </div>
            ))}
          </div>

          <div className="alert-history-card glass">
            <h3>Recent Alert Log</h3>
            <div className="alert-history-list">
              {logs.filter(l => l.includes('BLOCK') || l.includes('SUSPICIOUS')).slice(0, 5).map((l, i) => (
                <div key={i} className="alert-history-item">
                  {l}
                </div>
              ))}
              {logs.filter(l => l.includes('BLOCK') || l.includes('SUSPICIOUS')).length === 0 && (
                <div className="no-alerts">No threats detected yet.</div>
              )}
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}

export default App;
