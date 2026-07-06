import { useState, useEffect } from 'react';
import { Shield, Monitor, AlertTriangle, RefreshCw, Activity, Play, TrendingUp, Cpu } from 'lucide-react';
import type { Agent, Alert, DashboardSummary, ActionLog } from '../types';

interface Props {
  summary: DashboardSummary | null;
  recentAlerts: Alert[];
  agents: Agent[];
  actions: ActionLog[];
  timeRange: string;
  setTimeRange: (val: string) => void;
  onNavigate: (view: string, mitreId?: string) => void;
  onSimulate: () => void;
}

export default function DashboardOverview({ summary, recentAlerts, agents, actions, timeRange, setTimeRange, onNavigate, onSimulate }: Props) {
  const [simAgent, setSimAgent] = useState('');
  const [simType, setSimType] = useState('ransomware');
  const [simulating, setSimulating] = useState(false);
  const [simMsg, setSimMsg] = useState('');

  useEffect(() => { if (agents.length > 0 && !simAgent) setSimAgent(agents[0].id); }, [agents, simAgent]);

  // Filter alerts by time window
  const filterByTimeRange = (alertTimestamp: string) => {
    const alertTime = new Date(alertTimestamp).getTime();
    const now = new Date().getTime();
    const diffMinutes = (now - alertTime) / (1000 * 60);
    switch (timeRange) {
      case '15m': return diffMinutes <= 15;
      case '1h': return diffMinutes <= 60;
      case '4h': return diffMinutes <= 240;
      case '12h': return diffMinutes <= 720;
      case '24h':
      default: return diffMinutes <= 1440;
    }
  };

  const filteredAlerts = recentAlerts.filter(a => filterByTimeRange(a.timestamp));

  const getHighestSeverityForAgent = (agentId: string) => {
    const agentAlerts = filteredAlerts.filter(a => a.agentId === agentId && a.status !== 'resolved');
    if (agentAlerts.length === 0) return 'SAFE';
    const severities = agentAlerts.map(a => a.severity);
    if (severities.includes('critical')) return 'CRITICAL';
    if (severities.includes('high')) return 'HIGH';
    if (severities.includes('medium')) return 'MEDIUM';
    return 'LOW';
  };

  const getSeverityBadgeColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-low';
    }
  };

  const topHosts = (() => {
    const m: Record<string, { name: string; count: number; critical: number }> = {};
    filteredAlerts.filter(a => a.status !== 'resolved').forEach(a => {
      if (!m[a.agentId]) m[a.agentId] = { name: a.agentName, count: 0, critical: 0 };
      m[a.agentId].count++;
      if (a.severity === 'critical') m[a.agentId].critical++;
    });
    return Object.values(m).sort((a, b) => b.count - a.count).slice(0, 5);
  })();

  const handleSimulate = async () => {
    if (!simAgent) return;
    setSimulating(true);
    setSimMsg('Injecting...');
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: simAgent, type: simType })
      });
      if (res.ok) { const d = await res.json(); setSimMsg(`✓ ${d.alert.title}`); onSimulate(); }
      else setSimMsg('✗ Failed');
    } catch { setSimMsg('✗ Error'); }
    finally { setSimulating(false); setTimeout(() => setSimMsg(''), 4000); }
  };

  const techniqueNames: Record<string, string> = {
    'T1110': 'Brute Force',
    'T1059': 'Command & Script',
    'T1078': 'Valid Accounts',
    'T1485': 'Data Destruction',
    'T1003': 'Credential Dump',
    'T1046': 'Network Scan',
    'T1168': 'Scheduled Task',
    'T1071': 'App Layer Proto',
    'T1190': 'Exploit Pub-Facing App',
    'T1189': 'Drive-by Compromise',
    'T1068': 'Exploitation for Priv Esc',
    'T1565.002': 'Data Invalidation',
  };

  const techniques = (() => {
    const list = [
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1059', name: 'Command & Script' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1485', name: 'Data Destruction' },
      { id: 'T1003', name: 'Credential Dump' },
      { id: 'T1046', name: 'Network Scan' },
      { id: 'T1168', name: 'Scheduled Task' },
      { id: 'T1071', name: 'App Layer Proto' },
    ];
    
    if (summary?.mitreCoverage) {
      Object.keys(summary.mitreCoverage).forEach(techId => {
        if (!list.some(t => t.id === techId)) {
          list.push({
            id: techId,
            name: techniqueNames[techId] || 'Other Technique'
          });
        }
      });
    }
    return list;
  })();

  const chartPoints = (() => {
    const numBins = 8;
    const bins = Array(numBins).fill(0);
    
    let durationMs = 24 * 60 * 60 * 1000;
    switch (timeRange) {
      case '15m': durationMs = 15 * 60 * 1000; break;
      case '1h': durationMs = 60 * 60 * 1000; break;
      case '4h': durationMs = 4 * 60 * 60 * 1000; break;
      case '12h': durationMs = 12 * 60 * 60 * 1000; break;
    }
    
    const now = Date.now();
    const startTime = now - durationMs;
    const binSize = durationMs / numBins;
    
    filteredAlerts.forEach(a => {
      const t = new Date(a.timestamp).getTime();
      const offset = t - startTime;
      if (offset >= 0 && offset < durationMs) {
        const binIndex = Math.floor(offset / binSize);
        if (binIndex >= 0 && binIndex < numBins) {
          bins[binIndex]++;
        }
      }
    });
    
    const maxAlertsInBin = Math.max(...bins, 1);
    const points = bins.map((count, index) => {
      const x = 10 + (index * (480 / (numBins - 1)));
      const y = 145 - (count / maxAlertsInBin) * 110;
      return { x, y };
    });
    
    return points;
  })();

  const chartPath = (() => {
    if (chartPoints.length === 0) return 'M 10 145 L 490 145';
    let path = `M ${chartPoints[0].x} ${chartPoints[0].y}`;
    for (let i = 1; i < chartPoints.length; i++) {
      path += ` L ${chartPoints[i].x} ${chartPoints[i].y}`;
    }
    return path;
  })();

  const chartAreaPath = (() => {
    if (chartPoints.length === 0) return 'M 10 145 L 490 145 Z';
    let path = `M ${chartPoints[0].x} ${chartPoints[0].y}`;
    for (let i = 1; i < chartPoints.length; i++) {
      path += ` L ${chartPoints[i].x} ${chartPoints[i].y}`;
    }
    path += ` L ${chartPoints[chartPoints.length - 1].x} 145 L ${chartPoints[0].x} 145 Z`;
    return path;
  })();

  const axisLabels = (() => {
    switch (timeRange) {
      case '15m': return ['15m ago', '10m', '5m', 'Now'];
      case '1h': return ['1h ago', '40m', '20m', 'Now'];
      case '4h': return ['4h ago', '3h', '2h', '1h', 'Now'];
      case '12h': return ['12h ago', '8h', '4h', 'Now'];
      default: return ['24h ago', '16h', '8h', 'Now'];
    }
  })();

  const Bar = ({ value, max, color }: { value: number; max: number; color: string }) => (
    <div style={{ width: '100%', height: 3, background: 'var(--border-0)', borderRadius: 1 }}>
      <div style={{ width: `${(value / max) * 100}%`, height: '100%', background: color, borderRadius: 1, transition: 'width 0.3s' }} />
    </div>
  );

  const highestSeverity = (() => {
    const activeAlerts = filteredAlerts.filter(a => a.status !== 'resolved');
    if (activeAlerts.length === 0) return 'Safe';
    const severities = activeAlerts.map(a => a.severity);
    if (severities.includes('critical')) return 'Crit';
    if (severities.includes('high')) return 'High';
    if (severities.includes('medium')) return 'Medium';
    return 'Low';
  })();

  const systemStatus = highestSeverity === 'Safe' ? 'Operational' : 'Being Attacked';
  const systemStatusColor = systemStatus === 'Operational' ? 'var(--low)' : 'var(--critical)';

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case 'Crit':
        return {
          background: 'rgba(217, 63, 60, 0.18)',
          color: 'var(--critical)',
          border: '1px solid rgba(217, 63, 60, 0.3)',
          padding: '1px 5px',
          borderRadius: '3px',
          fontWeight: 600,
          marginLeft: '4px',
          fontSize: '0.68rem',
          textTransform: 'uppercase' as const
        };
      case 'High':
        return {
          background: 'rgba(242, 124, 54, 0.18)',
          color: 'var(--high)',
          border: '1px solid rgba(242, 124, 54, 0.3)',
          padding: '1px 5px',
          borderRadius: '3px',
          fontWeight: 600,
          marginLeft: '4px',
          fontSize: '0.68rem',
          textTransform: 'uppercase' as const
        };
      case 'Medium':
        return {
          background: 'rgba(230, 180, 50, 0.18)',
          color: 'var(--medium)',
          border: '1px solid rgba(230, 180, 50, 0.3)',
          padding: '1px 5px',
          borderRadius: '3px',
          fontWeight: 600,
          marginLeft: '4px',
          fontSize: '0.68rem',
          textTransform: 'uppercase' as const
        };
      case 'Low':
        return {
          background: 'rgba(60, 180, 114, 0.18)',
          color: 'var(--low)',
          border: '1px solid rgba(60, 180, 114, 0.3)',
          padding: '1px 5px',
          borderRadius: '3px',
          fontWeight: 600,
          marginLeft: '4px',
          fontSize: '0.68rem',
          textTransform: 'uppercase' as const
        };
      default:
        return {
          background: 'rgba(255, 255, 255, 0.05)',
          color: 'var(--text-3)',
          border: '1px solid var(--border-1)',
          padding: '1px 5px',
          borderRadius: '3px',
          fontWeight: 600,
          marginLeft: '4px',
          fontSize: '0.68rem',
          textTransform: 'uppercase' as const
        };
    }
  };

  return (
    <div style={{ animation: 'fadeInUp 0.25s ease-out' }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">SOC Overview</h1>
          <p className="page-subtitle">Real-time threat monitoring and triage console</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <select
            className="select-input"
            value={timeRange}
            onChange={e => setTimeRange(e.target.value)}
            style={{ minWidth: 80, padding: '4px 8px', fontSize: '0.78rem', height: 28 }}
          >
            <option value="15m">15m</option>
            <option value="1h">1h</option>
            <option value="4h">4h</option>
            <option value="12h">12h</option>
            <option value="24h">24h</option>
          </select>
          <button className="btn btn-outline" onClick={onSimulate} style={{ height: 28 }}><RefreshCw size={12} /> Refresh</button>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="kpi-grid">
        <div className="glass-panel kpi-card">
          <div className="kpi-header"><span className="kpi-title">System Status</span><Shield size={14} style={{ color: systemStatusColor, opacity: 0.6 }} /></div>
          <div className="kpi-value" style={{ color: systemStatusColor }}>{systemStatus}</div>
          <div className="kpi-trend" style={{ display: 'flex', alignItems: 'center', marginTop: 4 }}>
            Highest Threat Level: <span style={getSeverityStyle(highestSeverity)}>{highestSeverity}</span>
          </div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-header"><span className="kpi-title">Monitored Hosts</span><Monitor size={14} style={{ color: 'var(--accent)', opacity: 0.6 }} /></div>
          <div className="kpi-value">{summary?.activeAgents || 0}<span style={{ fontSize: '0.85rem', color: 'var(--text-3)', fontWeight: 400 }}>/{summary?.totalAgents || 0}</span></div>
          <div className="kpi-trend" style={{ color: 'var(--low)' }}>● {summary?.activeAgents || 0} reporting</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-header"><span className="kpi-title">Incidents (24h)</span><AlertTriangle size={14} style={{ color: (summary?.criticalAlerts || 0) > 0 ? 'var(--critical)' : 'var(--text-3)', opacity: 0.6 }} /></div>
          <div className="kpi-value" style={{ color: (summary?.criticalAlerts || 0) > 0 ? 'var(--critical)' : undefined }}>{summary?.alertCount24h || 0}</div>
          <div className="kpi-trend"><span style={{ color: 'var(--critical-dim)' }}>{summary?.criticalAlerts || 0} crit</span> · {summary?.highAlerts || 0} high</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-header"><span className="kpi-title">MITRE Coverage</span><TrendingUp size={14} style={{ color: 'var(--purple)', opacity: 0.6 }} /></div>
          <div className="kpi-value">{summary ? Object.keys(summary.mitreCoverage).length : 0}</div>
          <div className="kpi-trend">Active techniques</div>
        </div>
      </div>

      {/* Abnormality & Orchestrator Panels */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: 12, marginBottom: 14 }}>
        {/* Left: Abnormality Status */}
        <div className="glass-panel" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <h3 style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-0)' }}>
            <TrendingUp size={13} style={{ color: 'var(--accent)' }} /> Agent Abnormality Status
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flex: 1, justifyContent: 'center' }}>
            {[...agents]
              .sort((a, b) => b.threatScore - a.threatScore)
              .slice(0, 3)
              .map((agent, idx) => {
              const highestSev = getHighestSeverityForAgent(agent.id);
              const totalEvents = filteredAlerts.filter(a => a.agentId === agent.id && ['low', 'medium', 'high', 'critical'].includes(a.severity)).length;
              return (
                <div key={agent.id} style={{
                  padding: '10px 14px', background: 'var(--bg-surface)', border: '1px solid var(--border-1)',
                  borderRadius: 'var(--r-xs)', display: 'flex', flexDirection: 'column', gap: 6
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-0)', fontSize: '0.82rem' }}>
                      A{idx + 1}: {agent.name}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>{agent.ip}</span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, borderTop: '1px solid rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.03)', padding: '5px 0' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <span style={{ fontSize: '0.62rem', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>Highest Event</span>
                      <div>
                        <span className={`badge ${getSeverityBadgeColor(highestSev)}`} style={{ fontSize: '0.58rem', padding: '1px 4px' }}>
                          {highestSev}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <span style={{ fontSize: '0.62rem', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.03em' }}>Total Events</span>
                      <strong style={{ fontSize: '0.78rem', color: totalEvents > 0 ? 'var(--accent)' : 'var(--text-2)' }}>{totalEvents}</strong>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Security Orchestrator Table */}
        <div className="glass-panel" style={{ padding: 14, display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-0)', marginBottom: 8 }}>
            <Cpu size={13} style={{ color: 'var(--info)' }} /> Security Orchestrator status
          </h3>
          <div className="table-container" style={{ flex: 1, overflowY: 'auto', maxHeight: 240 }}>
            <table className="sec-table" style={{ width: '100%', fontSize: '0.78rem' }}>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th style={{ textAlign: 'center' }}>Critical</th>
                  <th style={{ textAlign: 'center' }}>High</th>
                  <th style={{ textAlign: 'center' }}>Medium</th>
                  <th style={{ textAlign: 'center' }}>Low</th>
                  <th style={{ textAlign: 'center' }}>Highest Level</th>
                  <th>Mitigation</th>
                </tr>
              </thead>
              <tbody>
                {agents.map(a => {
                  const cCount = filteredAlerts.filter(x => x.agentId === a.id && x.severity === 'critical' && x.status !== 'resolved').length;
                  const hCount = filteredAlerts.filter(x => x.agentId === a.id && x.severity === 'high' && x.status !== 'resolved').length;
                  const mCount = filteredAlerts.filter(x => x.agentId === a.id && x.severity === 'medium' && x.status !== 'resolved').length;
                  const lCount = filteredAlerts.filter(x => x.agentId === a.id && x.severity === 'low' && x.status !== 'resolved').length;
                  const highestSev = getHighestSeverityForAgent(a.id);

                  let statusColor = 'var(--low)';
                  let statusLabel = 'SECURED';
                  if (a.status === 'disconnected') {
                    statusColor = 'var(--text-3)';
                    statusLabel = 'ISOLATED';
                  } else if (cCount > 0) {
                    statusColor = 'var(--critical)';
                    statusLabel = 'CONTAINING';
                  } else if (hCount > 0) {
                    statusColor = 'var(--high)';
                    statusLabel = 'ATTACKED';
                  } else if (mCount > 0 || lCount > 0) {
                    statusColor = 'var(--medium)';
                    statusLabel = 'MONITOR';
                  }

                  return (
                    <tr key={a.id}>
                      <td style={{ fontWeight: 600, padding: '4px 8px' }}>{a.name}</td>
                      <td style={{ textAlign: 'center', color: cCount > 0 ? 'var(--critical)' : 'var(--text-3)', fontWeight: cCount > 0 ? 600 : 400, padding: '4px 8px' }}>{cCount}</td>
                      <td style={{ textAlign: 'center', color: hCount > 0 ? 'var(--high)' : 'var(--text-3)', fontWeight: hCount > 0 ? 600 : 400, padding: '4px 8px' }}>{hCount}</td>
                      <td style={{ textAlign: 'center', color: mCount > 0 ? 'var(--medium)' : 'var(--text-3)', fontWeight: mCount > 0 ? 600 : 400, padding: '4px 8px' }}>{mCount}</td>
                      <td style={{ textAlign: 'center', color: lCount > 0 ? 'var(--low)' : 'var(--text-3)', fontWeight: lCount > 0 ? 600 : 400, padding: '4px 8px' }}>{lCount}</td>
                      <td style={{ textAlign: 'center', padding: '4px 8px' }}>
                        <span className={`badge ${getSeverityBadgeColor(highestSev)}`} style={{ fontSize: '0.58rem', padding: '1px 4px' }}>
                          {highestSev}
                        </span>
                      </td>
                      <td style={{ padding: '4px 8px' }}>
                        <span style={{ fontSize: '0.68rem', fontWeight: 600, color: statusColor, display: 'flex', alignItems: 'center', gap: 3 }}>
                          <span style={{ width: 4, height: 4, background: statusColor, borderRadius: '50%' }} />
                          {statusLabel}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.7fr 1fr', gap: 12 }}>
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Chart */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.85rem' }}>
                <Activity size={13} style={{ color: 'var(--info)' }} /> Alert Volume
              </h3>
              <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>{timeRange}</span>
            </div>
            <div className="svg-chart-container" style={{ position: 'relative' }}>
              <svg width="100%" height="180" viewBox="0 0 500 180" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="area-gradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.15" />
                    <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <line x1="0" y1="45" x2="500" y2="45" className="chart-grid-line" />
                <line x1="0" y1="90" x2="500" y2="90" className="chart-grid-line" />
                <line x1="0" y1="135" x2="500" y2="135" className="chart-grid-line" />
                {filteredAlerts.length > 0 ? (
                  <>
                    <path d={chartPath} className="chart-line" />
                    <path d={chartAreaPath} className="chart-area" fill="url(#area-gradient)" />
                    {chartPoints.map((p, idx) => (
                      <circle key={idx} cx={p.x} cy={p.y} r="3.5" fill="var(--accent)" style={{ filter: 'drop-shadow(0 0 2px var(--accent))' }} />
                    ))}
                  </>
                ) : <path d="M 10 145 L 490 145" className="chart-line" />}
                <text x="10" y="175" className="chart-axis-text">{axisLabels[0]}</text>
                <text x="160" y="175" className="chart-axis-text" textAnchor="middle">{axisLabels[1]}</text>
                <text x="310" y="175" className="chart-axis-text" textAnchor="middle">{axisLabels[2]}</text>
                <text x="490" y="175" className="chart-axis-text" textAnchor="end">{axisLabels[axisLabels.length - 1]}</text>
              </svg>
            </div>
          </div>

          {/* MITRE Grid */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <h3 style={{ fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Shield size={13} style={{ color: 'var(--purple)' }} /> MITRE ATT&CK
            </h3>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-3)', margin: '3px 0 0' }}>Click active techniques to filter alerts.</p>
            <div className="mitre-grid-container">
              {techniques.map(t => {
                const c = summary?.mitreCoverage[t.id] || 0;
                const active = c > 0;
                return (
                  <div key={t.id} className={`mitre-cell ${active ? 'active-coverage' : ''}`}
                    onClick={() => { if (active) onNavigate('alerts', t.id); }}
                    style={{ cursor: active ? 'pointer' : 'default' }}>
                    <span className="mitre-cell-tech" style={{ color: active ? 'var(--info)' : undefined }}>{t.id}</span>
                    <div className="mitre-cell-title" title={t.name}>{t.name}</div>
                    {active && <div className="mitre-cell-count">{c}</div>}
                  </div>
                );
              })}
            </div>
          </div>

          {/* AI Autonomous Defense Log */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <h3 style={{ fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent)' }}>
              <Cpu size={13} /> AI Autonomous Defense Log
            </h3>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-3)', margin: '3px 0 8px' }}>Active automated containment and response logs</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {actions.filter(act => act.actor.includes('SOAR') || act.actor.includes('AI') || act.actor === 'AI Agent').slice(0, 4).map(act => (
                <div key={act.id} style={{
                  padding: '8px 10px', background: 'var(--bg-surface)', border: '1px solid var(--border-0)',
                  borderRadius: 'var(--r-xs)', fontSize: '0.76rem', display: 'flex', flexDirection: 'column', gap: 2
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-3)' }}>
                    <span style={{ color: 'var(--accent-dim)', fontWeight: 600 }}>{act.actionType}</span>
                    <span>{new Date(act.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                  </div>
                  <div style={{ color: 'var(--text-1)' }}>Target: <code style={{ fontSize: '0.72rem', color: 'var(--text-0)' }}>{act.target}</code></div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-2)', marginTop: 2, borderLeft: '2px solid var(--accent)', paddingLeft: 6, fontStyle: 'italic' }}>
                    {act.message}
                  </div>
                </div>
              ))}
              {actions.filter(act => act.actor.includes('SOAR') || act.actor.includes('AI') || act.actor === 'AI Agent').length === 0 && (
                <p style={{ textAlign: 'center', padding: '12px 0', color: 'var(--text-3)', fontSize: '0.78rem' }}>No AI mitigations triggered yet.</p>
              )}
            </div>
          </div>
        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Top Affected */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <h3 style={{ fontSize: '0.85rem', color: 'var(--critical-dim)', marginBottom: 10 }}>Top Affected Hosts</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {topHosts.map(h => {
                const maxC = Math.max(...topHosts.map(x => x.count), 1);
                return (
                  <div key={h.name}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: 3 }}>
                      <span style={{ color: 'var(--text-0)', fontWeight: 600 }}>{h.name}</span>
                      <span style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.78rem' }}>
                        {h.critical > 0 && <span style={{ color: 'var(--critical-dim)', marginRight: 6 }}>{h.critical} crit</span>}
                        {h.count}
                      </span>
                    </div>
                    <Bar value={h.count} max={maxC} color={h.critical > 0 ? 'var(--critical)' : 'var(--high)'} />
                  </div>
                );
              })}
              {topHosts.length === 0 && <p style={{ textAlign: 'center', padding: '16px 0', color: 'var(--text-3)', fontSize: '0.82rem' }}>No active incidents</p>}
            </div>
          </div>

          {/* Simulator */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <h3 style={{ fontSize: '0.85rem', color: 'var(--accent-dim)', marginBottom: 10 }}>Attack Simulator</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <label style={{ fontSize: '0.65rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>Target</label>
              <select className="select-input" value={simAgent} onChange={e => setSimAgent(e.target.value)} style={{ width: '100%' }}>
                {agents.map(a => <option key={a.id} value={a.id}>{a.name} ({a.ip})</option>)}
              </select>
              <label style={{ fontSize: '0.65rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>Vector</label>
              <select className="select-input" value={simType} onChange={e => setSimType(e.target.value)} style={{ width: '100%' }}>
                <option value="ransomware">Ransomware (VSS Delete)</option>
                <option value="bruteforce">SSH Brute Force (T1110)</option>
                <option value="malware">Credential Dump (Mimikatz)</option>
              </select>
              <button className="btn btn-primary" onClick={handleSimulate} disabled={simulating || !simAgent} style={{ width: '100%', marginTop: 4 }}>
                <Play size={12} /> {simulating ? 'Injecting...' : 'Launch'}
              </button>
              {simMsg && <div style={{ padding: '8px 10px', background: 'var(--accent-bg)', border: '1px solid rgba(59,130,246,0.2)', fontSize: '0.78rem', color: 'var(--accent-dim)', fontFamily: "'IBM Plex Mono', monospace", borderRadius: 'var(--r-xs)', animation: 'fadeInUp 0.2s' }}>{simMsg}</div>}
            </div>
          </div>

          {/* Recent Alerts */}
          <div className="glass-panel" style={{ padding: 16, flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
              <h3 style={{ fontSize: '0.85rem' }}>Recent Alerts</h3>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>LIVE</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
              {filteredAlerts.slice(0, 6).map(a => (
                <div key={a.id} onClick={() => onNavigate('alerts')} className="hover-card" style={{
                  padding: '8px 10px', borderRadius: 'var(--r-xs)', cursor: 'pointer',
                  border: '1px solid var(--border-0)', transition: 'all 0.1s'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', marginBottom: 2 }}>
                    <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                    <span style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>{new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                  </div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-0)' }}>{a.title}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-3)' }}>{a.agentName}</div>
                </div>
              ))}
              {filteredAlerts.length === 0 && <p style={{ textAlign: 'center', padding: '24px 0', color: 'var(--text-3)' }}>No incidents</p>}
            </div>
            <button className="btn btn-outline" onClick={() => onNavigate('alerts')} style={{ width: '100%', marginTop: 8, fontSize: '0.78rem' }}>
              Open Incident Manager →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
