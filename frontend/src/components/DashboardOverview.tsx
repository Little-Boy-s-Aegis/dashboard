import { useState, useEffect } from 'react';
import { Shield, Users, AlertTriangle, RefreshCw, Activity, Terminal, Play, ShieldAlert } from 'lucide-react';
import type { Agent, Alert, DashboardSummary } from '../types';

interface DashboardOverviewProps {
  summary: DashboardSummary | null;
  recentAlerts: Alert[];
  agents: Agent[];
  onNavigate: (view: string) => void;
  onSimulate: () => void;
}

export default function DashboardOverview({
  summary,
  recentAlerts,
  agents,
  onNavigate,
  onSimulate
}: DashboardOverviewProps) {
  const [simulationAgent, setSimulationAgent] = useState('');
  const [simulationType, setSimulationType] = useState('ransomware');
  const [simulating, setSimulating] = useState(false);
  const [simMessage, setSimMessage] = useState('');

  // Set default agent for simulation when list loads
  useEffect(() => {
    if (agents.length > 0 && !simulationAgent) {
      setSimulationAgent(agents[0].id);
    }
  }, [agents, simulationAgent]);

  // Calculate Top Affected Hosts (top 5 hosts with the most active alerts)
  const getTopAffectedHosts = () => {
    const counts: Record<string, { name: string; count: number; critical: number; high: number }> = {};
    
    recentAlerts.forEach(alert => {
      if (alert.status === 'resolved') return; // Only count active alerts
      
      if (!counts[alert.agentId]) {
        counts[alert.agentId] = { name: alert.agentName, count: 0, critical: 0, high: 0 };
      }
      
      counts[alert.agentId].count++;
      if (alert.severity === 'critical') {
        counts[alert.agentId].critical++;
      } else if (alert.severity === 'high') {
        counts[alert.agentId].high++;
      }
    });

    return Object.values(counts)
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  };

  const topAffectedHosts = getTopAffectedHosts();

  const handleSimulate = async () => {
    if (!simulationAgent) return;
    setSimulating(true);
    setSimMessage('Injecting payload...');
    try {
      const response = await fetch('/api/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          agentId: simulationAgent,
          type: simulationType,
        }),
      });
      if (response.ok) {
        const data = await response.json();
        setSimMessage(`Alert triggered: ${data.alert.title}`);
        onSimulate(); // Refresh data
        setTimeout(() => setSimMessage(''), 4000);
      } else {
        setSimMessage('Simulation injection failed');
        setTimeout(() => setSimMessage(''), 3000);
      }
    } catch (e) {
      setSimMessage('Error communicating with simulator');
      setTimeout(() => setSimMessage(''), 3000);
    } finally {
      setSimulating(false);
    }
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'Severe': return '#f43f5e';
      case 'Elevated': return '#f97316';
      default: return '#10b981';
    }
  };

  // Predefined key MITRE Techniques we track
  const trackedTechniques = [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1059', name: 'PowerShell / CMD' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1485', name: 'Shadow Copy Del' },
    { id: 'T1003', name: 'Lsass Dump' },
    { id: 'T1046', name: 'Port Scan' },
    { id: 'T1168', name: 'Cron Job Mod' },
    { id: 'T1071', name: 'C2 Traffic' },
  ];

  return (
    <div style={{ animation: 'flashNew 0.5s ease-out' }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">SOC Overview</h1>
          <p className="page-subtitle">Real-time enterprise threat monitoring and AI triage console</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-outline" onClick={onSimulate} style={{ gap: '6px' }}>
            <RefreshCw size={14} /> Refresh Feed
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="kpi-grid">
        <div className={`glass-panel kpi-card ${summary?.threatLevel === 'Severe' ? 'threat-severe' : summary?.threatLevel === 'Elevated' ? 'threat-elevated' : 'threat-normal'}`}>
          <div className="kpi-header">
            <span className="kpi-title">Threat Level</span>
            <Shield size={18} style={{ color: getThreatColor(summary?.threatLevel || 'Normal') }} />
          </div>
          <div className="kpi-value" style={{ color: getThreatColor(summary?.threatLevel || 'Normal') }}>
            {summary?.threatLevel || 'Normal'}
          </div>
          <div className="kpi-trend">
            <span style={{ color: '#94a3b8' }}>System status: operational</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">Monitored Hosts</span>
            <Users size={18} style={{ color: '#38bdf8' }} />
          </div>
          <div className="kpi-value">
            {summary?.activeAgents || 0}
            <span style={{ fontSize: '1rem', color: '#64748b', fontWeight: 500 }}> / {summary?.totalAgents || 0}</span>
          </div>
          <div className="kpi-trend">
            <span style={{ color: '#34d399' }}>● {summary?.activeAgents || 0} active agents</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">Incidents (24h)</span>
            <AlertTriangle size={18} style={{ color: '#fb7185' }} />
          </div>
          <div className="kpi-value" style={{ color: (summary?.criticalAlerts || 0) > 0 ? '#fb7185' : 'inherit' }}>
            {summary?.alertCount24h || 0}
          </div>
          <div className="kpi-trend">
            <span style={{ color: '#fb7185', fontWeight: 600 }}>{summary?.criticalAlerts || 0} Critical</span>
            <span style={{ color: '#94a3b8' }}> • {summary?.highAlerts || 0} High</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">MITRE Technique Hits</span>
            <Activity size={18} style={{ color: '#a78bfa' }} />
          </div>
          <div className="kpi-value">
            {summary ? Object.keys(summary.mitreCoverage).length : 0}
          </div>
          <div className="kpi-trend">
            <span style={{ color: '#c084fc' }}>Active techniques coverage</span>
          </div>
        </div>
      </div>

      {/* Main Section */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', marginBottom: '28px' }}>
        
        {/* Left Column - Chart & MITRE */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Custom SVG Chart */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={18} style={{ color: '#38bdf8' }} /> Alert Volume Trend (Last 24h)
            </h3>
            <div className="svg-chart-container">
              <svg width="100%" height="220" viewBox="0 0 500 200" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="area-gradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.4" />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
                  </linearGradient>
                  <linearGradient id="chart-gradient" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#6366f1" />
                    <stop offset="50%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#34d399" />
                  </linearGradient>
                </defs>
                
                {/* Grid Lines */}
                <line x1="0" y1="50" x2="500" y2="50" className="chart-grid-line" />
                <line x1="0" y1="100" x2="500" y2="100" className="chart-grid-line" />
                <line x1="0" y1="150" x2="500" y2="150" className="chart-grid-line" />
                
                {/* Chart Path */}
                {recentAlerts.length > 0 ? (
                  <>
                    <path
                      d={`M 0 170 Q 100 130, 200 160 T 400 80 T 500 ${180 - (summary?.criticalAlerts ? summary.criticalAlerts * 25 : 10)}`}
                      className="chart-line"
                    />
                    <path
                      d={`M 0 170 Q 100 130, 200 160 T 400 80 T 500 ${180 - (summary?.criticalAlerts ? summary.criticalAlerts * 25 : 10)} L 500 200 L 0 200 Z`}
                      className="chart-area"
                    />
                  </>
                ) : (
                  <path d="M 0 180 L 500 180" className="chart-line" />
                )}
                
                {/* X Axis labels */}
                <text x="10" y="195" className="chart-axis-text">24h ago</text>
                <text x="160" y="195" className="chart-axis-text">16h ago</text>
                <text x="320" y="195" className="chart-axis-text">8h ago</text>
                <text x="460" y="195" className="chart-axis-text">Now</text>
              </svg>
            </div>
          </div>

          {/* MITRE ATT&CK Heatmap */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={18} style={{ color: '#a78bfa' }} /> MITRE ATT&CK Technique Mapping
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '4px' }}>
              Highlights indicate mapped alarms triggering active MITRE techniques.
            </p>
            <div className="mitre-grid-container">
              {trackedTechniques.map((tech) => {
                // Find if this technique is active in summary
                const count = summary?.mitreCoverage[tech.id] || 0;
                const isActive = count > 0;
                return (
                  <div key={tech.id} className={`mitre-cell ${isActive ? 'active-coverage' : ''}`}>
                    <span className="mitre-cell-tech" style={{ color: isActive ? '#38bdf8' : '' }}>
                      {tech.id}
                    </span>
                    <div className="mitre-cell-title" title={tech.name}>{tech.name}</div>
                    {isActive && <div className="mitre-cell-count">{count} {count === 1 ? 'alert' : 'alerts'}</div>}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column - Simulator & Feed */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Top Affected Hosts Widget */}
          <div className="glass-panel" style={{ padding: '24px', border: '1px solid rgba(244, 63, 94, 0.25)', boxShadow: '0 0 15px rgba(244, 63, 94, 0.05)' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#fb7185' }}>
              <ShieldAlert size={18} /> Top Affected Hosts
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '4px', marginBottom: '16px' }}>
              Endpoints with active anomalies requiring triage.
            </p>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {topAffectedHosts.map((host) => {
                const maxAlerts = Math.max(...topAffectedHosts.map(h => h.count), 1);
                const percent = (host.count / maxAlerts) * 100;
                const hasCritical = host.critical > 0;
                
                return (
                  <div key={host.name} style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem' }}>
                      <span style={{ fontWeight: 600, color: '#f1f5f9' }}>{host.name}</span>
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                        {host.critical > 0 && (
                          <span className="badge badge-critical" style={{ fontSize: '0.65rem', padding: '1px 6px' }}>
                            {host.critical} Critical
                          </span>
                        )}
                        <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 'bold' }}>
                          {host.count} {host.count === 1 ? 'Alert' : 'Alerts'}
                        </span>
                      </div>
                    </div>
                    <div style={{ width: '100%', height: '5px', background: 'rgba(255,255,255,0.06)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${percent}%`,
                        height: '100%',
                        background: hasCritical ? 'linear-gradient(90deg, #f43f5e, #fb7185)' : 'linear-gradient(90deg, #f97316, #ff983f)',
                        boxShadow: hasCritical ? '0 0 8px rgba(244, 63, 94, 0.4)' : 'none',
                        borderRadius: '3px',
                        transition: 'all 0.5s ease'
                      }} />
                    </div>
                  </div>
                );
              })}

              {topAffectedHosts.length === 0 && (
                <div style={{ color: '#64748b', fontSize: '0.8rem', textAlign: 'center', padding: '12px 0' }}>
                  No active incidents detected.
                </div>
              )}
            </div>
          </div>

          {/* Attack Simulator Panel */}
          <div className="glass-panel" style={{ padding: '24px', border: '1px solid rgba(56, 189, 248, 0.15)' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#38bdf8' }}>
              <Play size={18} /> Cyberattack Simulator
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '4px', marginBottom: '16px' }}>
              Trigger mock security incidents to inspect SIEM response and AI analysis.
            </p>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>TARGET HOST</label>
                <select 
                  className="select-input" 
                  value={simulationAgent}
                  onChange={(e) => setSimulationAgent(e.target.value)}
                  style={{ width: '100%', background: '#1c1c24' }}
                >
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>{agent.name} ({agent.ip})</option>
                  ))}
                </select>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>ATTACK VECTOR</label>
                <select 
                  className="select-input" 
                  value={simulationType}
                  onChange={(e) => setSimulationType(e.target.value)}
                  style={{ width: '100%', background: '#1c1c24' }}
                >
                  <option value="ransomware">Ransomware (VSS Wiping & Encryption)</option>
                  <option value="bruteforce">SSH Brute Force (T1110)</option>
                  <option value="malware">Credentials Dumping (Lsass Mimikatz)</option>
                </select>
              </div>

              <button 
                className="btn btn-primary" 
                onClick={handleSimulate} 
                disabled={simulating || !simulationAgent}
                style={{ width: '100%', marginTop: '8px', gap: '8px' }}
              >
                <Terminal size={16} /> {simulating ? 'Injecting Payload...' : 'Launch Simulation'}
              </button>

              {simMessage && (
                <div style={{
                  padding: '10px',
                  borderRadius: '6px',
                  background: 'rgba(56, 189, 248, 0.08)',
                  border: '1px solid rgba(56, 189, 248, 0.2)',
                  fontSize: '0.75rem',
                  color: '#38bdf8',
                  fontFamily: 'JetBrains Mono, monospace',
                  animation: 'flashNew 0.5s ease-out'
                }}>
                  {simMessage}
                </div>
              )}
            </div>
          </div>

          {/* Live Security Alarms Feed */}
          <div className="glass-panel" style={{ padding: '24px', flex: 1, display: 'flex', flexDirection: 'column' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
              <AlertTriangle size={18} style={{ color: '#fb7185' }} /> Recent Security Alarms
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
              {recentAlerts.slice(0, 5).map((alert) => (
                <div 
                  key={alert.id} 
                  onClick={() => onNavigate('alerts')}
                  style={{
                    padding: '12px',
                    borderRadius: '8px',
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid rgba(255,255,255,0.04)',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    position: 'relative'
                  }}
                  className="hover-card"
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span className={`badge badge-${alert.severity}`} style={{ fontSize: '0.65rem', padding: '2px 8px' }}>
                      {alert.severity}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: '#64748b' }}>
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ fontWeight: 600, fontSize: '0.85rem', color: '#f1f5f9' }}>{alert.title}</div>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '2px' }}>Host: {alert.agentName}</div>
                </div>
              ))}

              {recentAlerts.length === 0 && (
                <div style={{ color: '#64748b', fontSize: '0.85rem', textAlign: 'center', padding: '40px 0', flex: 1 }}>
                  No security incidents recorded in the last 24h.
                </div>
              )}
            </div>

            <button 
              className="btn btn-outline" 
              onClick={() => onNavigate('alerts')}
              style={{ width: '100%', marginTop: '16px', fontSize: '0.8rem' }}
            >
              Open Alerts Incident Manager
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}
