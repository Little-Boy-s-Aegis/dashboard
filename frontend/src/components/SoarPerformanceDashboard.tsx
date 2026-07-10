import { useState, useEffect } from 'react';
import { Cpu, CheckCircle2, XCircle, Clock, RotateCw, Play, ShieldCheck, Zap } from 'lucide-react';
import type { ActionLog, Alert } from '../types';

interface SoarMetrics {
  totalPlaybooks: number;
  successCount: number;
  failedCount: number;
  successRate: number;
  avgResponseTimeSeconds: number;
}

interface Props {
  actions: ActionLog[];
  alerts: Alert[];
}

export default function SoarPerformanceDashboard({ actions, alerts }: Props) {
  const [metrics, setMetrics] = useState<SoarMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [autopilotEnabled, setAutopilotEnabled] = useState(false);
  const [bannedIPs, setBannedIPs] = useState<any[]>([]);

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/soar/metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch (e) {
      console.error('Failed to fetch SOAR metrics:', e);
    } finally {
      setLoading(false);
    }
  };

  const fetchSettings = async () => {
    try {
      const res = await fetch('/api/settings');
      if (res.ok) {
        const data = await res.json();
        setAutopilotEnabled(data.soc_autopilot_enabled);
      }
    } catch (e) {
      console.error('Failed to fetch settings:', e);
    }
  };

  const toggleAutopilot = async () => {
    const newValue = !autopilotEnabled;
    setAutopilotEnabled(newValue);
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ soc_autopilot_enabled: newValue })
      });
    } catch (e) {
      console.error('Failed to toggle autopilot:', e);
    }
  };

  const fetchBannedIPs = async () => {
    try {
      const res = await fetch('/api/banned-ips');
      if (res.ok) {
        const data = await res.json();
        setBannedIPs(data);
      }
    } catch (e) {
      console.error('Failed to fetch banned IPs:', e);
    }
  };

  const unblockIP = async (ip: string) => {
    try {
      const res = await fetch('/api/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: 'SOC Operator',
          actionType: 'Unblock IP',
          target: ip,
          message: 'Manual unblock requested from SOC Dashboard'
        })
      });
      if (res.ok) {
        fetchBannedIPs();
      }
    } catch (e) {
      console.error('Failed to unblock IP:', e);
    }
  };

  useEffect(() => {
    fetchMetrics();
    fetchSettings();
    fetchBannedIPs();
    const interval = setInterval(() => {
      fetchMetrics();
      fetchBannedIPs();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading || !metrics) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '300px', gap: 8 }}>
        <RotateCw size={18} className="spin" style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: '0.78rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>CALCULATING PERFORMANCE METRICS...</span>
      </div>
    );
  }

  // Filter actions handled by the SOAR engine
  const soarActions = actions.filter(act => 
    act.actor.includes('SOAR') || act.actor.includes('AI')
  );

  const slaStats = (() => {
    let under15 = 0;
    let under30 = 0;
    let over30 = 0;
    let total = 0;

    soarActions.forEach(act => {
      const matchingAlert = alerts.find(a => 
        a.agentName && act.target.includes(a.agentName)
      );

      if (matchingAlert) {
        const duration = (new Date(act.timestamp).getTime() - new Date(matchingAlert.timestamp).getTime()) / 1000;
        if (duration > 0 && duration <= 300) {
          total++;
          if (duration < 15) {
            under15++;
            under30++;
          } else if (duration <= 30) {
            under30++;
          } else {
            over30++;
          }
        }
      }
    });

    if (total === 0) {
      return { under15Pct: 0.0, under30Pct: 100.0, over30Pct: 0.0, total: 0 };
    }

    return {
      under15Pct: Math.round((under15 / total) * 1000) / 10,
      under30Pct: Math.round((under30 / total) * 1000) / 10,
      over30Pct: Math.round((over30 / total) * 1000) / 10,
      total
    };
  })();

  return (
    <div style={{ animation: 'fadeInUp 0.25s ease-out', display: 'flex', flexDirection: 'column', gap: 16 }}>
      
      {/* Page Header */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Cpu style={{ color: 'var(--accent)' }} size={22} />
            SOAR Performance Monitoring
          </h1>
          <p className="page-subtitle">Real-time statistics, automation response times, and containment success rates</p>
        </div>
        <button className="btn btn-outline" onClick={fetchMetrics} style={{ height: 28 }}>
          <RotateCw size={12} /> Refresh
        </button>
      </div>

      {/* KPI Cards */}
      <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        
        {/* Total Playbooks Run */}
        <div className="glass-panel kpi-card" style={{ padding: '16px 20px', borderLeft: '3px solid var(--accent)' }}>
          <div className="kpi-header">
            <span className="kpi-title" style={{ letterSpacing: '0.05em' }}>TOTAL PLAYBOOKS RUN</span>
            <Play size={14} style={{ color: 'var(--accent)', opacity: 0.6 }} />
          </div>
          <div className="kpi-value" style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: '2rem', fontWeight: 700, margin: '8px 0 4px' }}>
            {metrics.totalPlaybooks}
          </div>
          <div className="kpi-trend" style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>
            Automated playbook flows triggered
          </div>
        </div>

        {/* Action Success Rate */}
        <div className="glass-panel kpi-card" style={{ padding: '16px 20px', borderLeft: '3px solid var(--low)' }}>
          <div className="kpi-header">
            <span className="kpi-title" style={{ letterSpacing: '0.05em' }}>SUCCESS RATE</span>
            <CheckCircle2 size={14} style={{ color: 'var(--low)', opacity: 0.6 }} />
          </div>
          <div className="kpi-value" style={{ color: 'var(--low)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '2rem', fontWeight: 700, margin: '8px 0 4px' }}>
            {metrics.successRate.toFixed(1)}%
          </div>
          <div className="kpi-trend" style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>
            {metrics.successCount} success / {metrics.failedCount} failed
          </div>
        </div>

        {/* Avg Response Time */}
        <div className="glass-panel kpi-card" style={{ padding: '16px 20px', borderLeft: '3px solid var(--info)' }}>
          <div className="kpi-header">
            <span className="kpi-title" style={{ letterSpacing: '0.05em' }}>AVG RESPONSE TIME</span>
            <Clock size={14} style={{ color: 'var(--info)', opacity: 0.6 }} />
          </div>
          <div className="kpi-value" style={{ color: 'var(--info)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '2rem', fontWeight: 700, margin: '8px 0 4px' }}>
            {metrics.avgResponseTimeSeconds.toFixed(1)}s
          </div>
          <div className="kpi-trend" style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>
            From ingestion to API mitigation
          </div>
        </div>

        {/* Target SLA */}
        <div className="glass-panel kpi-card" style={{ padding: '16px 20px', borderLeft: '3px solid var(--purple)' }}>
          <div className="kpi-header">
            <span className="kpi-title" style={{ letterSpacing: '0.05em' }}>SLA COMPLIANCE</span>
            <ShieldCheck size={14} style={{ color: 'var(--purple)', opacity: 0.6 }} />
          </div>
          <div className="kpi-value" style={{ color: 'var(--purple)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '2rem', fontWeight: 700, margin: '8px 0 4px' }}>
            {slaStats.under30Pct.toFixed(1)}%
          </div>
          <div className="kpi-trend" style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>
            Within target 30s response SLA
          </div>
        </div>

      </div>

      {/* Autopilot Automation Control Toggle */}
      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderLeft: autopilotEnabled ? '4px solid var(--low)' : '4px solid var(--accent)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ 
            padding: 8, 
            borderRadius: '50%', 
            background: autopilotEnabled ? 'rgba(76, 175, 80, 0.15)' : 'rgba(255, 152, 0, 0.15)',
            color: autopilotEnabled ? 'var(--low)' : 'var(--accent)'
          }}>
            <Zap size={20} />
          </div>
          <div>
            <h3 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-0)', margin: 0 }}>
              SOC Playbook Automation Control (Autopilot Mode)
            </h3>
            <p style={{ fontSize: '0.74rem', color: 'var(--text-3)', margin: '2px 0 0' }}>
              {autopilotEnabled 
                ? "ON: AI has Full Control to execute automated playbooks immediately (Block IP, Quarantine Host, Force Logout)." 
                : "OFF: AI operates in Suggest-Only Mode. Recommended remediation actions require manual approval."}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ 
            fontSize: '0.72rem', 
            fontWeight: 700, 
            padding: '4px 8px', 
            borderRadius: 4, 
            fontFamily: "'IBM Plex Mono', monospace",
            background: autopilotEnabled ? 'rgba(76, 175, 80, 0.1)' : 'rgba(255, 152, 0, 0.1)',
            color: autopilotEnabled ? 'var(--low)' : 'var(--accent)'
          }}>
            {autopilotEnabled ? "AI AUTOPILOT ON" : "SUGGEST ONLY (DEFAULT)"}
          </span>
          <button 
            className="btn btn-outline"
            style={{ 
              height: 32, 
              padding: '0 16px', 
              fontSize: '0.78rem',
              fontWeight: 600,
              borderColor: autopilotEnabled ? 'var(--low)' : 'var(--border-2)',
              color: autopilotEnabled ? 'var(--low)' : 'var(--text-1)',
              borderRadius: 6,
              cursor: 'pointer'
            }}
            onClick={toggleAutopilot}
          >
            {autopilotEnabled ? "Switch to Suggest Only" : "Enable Playbook Automation"}
          </button>
        </div>
      </div>

      {/* Main Grid: Details and Chart */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 16 }}>
        
        {/* Left Column: Log history of automated actions */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ background: 'var(--bg-surface)', padding: '10px 16px', borderBottom: '1px solid var(--border-1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-0)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Zap size={14} style={{ color: 'var(--accent)' }} />
              Automated Containment Actions History
            </span>
            <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>{soarActions.length} Executed</span>
          </div>

          <div style={{ padding: '12px', maxHeight: 'calc(100vh - 360px)', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
            {soarActions.map(act => {
              const isSuccess = act.status === 'success';
              return (
                <div key={act.id} style={{
                  padding: '10px 14px', background: 'var(--bg-surface)', border: '1px solid var(--border-0)',
                  borderRadius: 'var(--r-xs)', display: 'flex', flexDirection: 'column', gap: 4
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.7rem' }}>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <span className="badge badge-brand" style={{ background: 'var(--accent-dim)', color: '#fff' }}>{act.actor}</span>
                      <span className="badge badge-neutral" style={{ fontSize: '0.58rem', padding: '1px 3px' }}>{act.actionType}</span>
                    </div>
                    <span style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.65rem' }}>
                      {new Date(act.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 1 }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-1)' }}>
                      Target Resource: <code style={{ fontSize: '0.72rem', color: 'var(--text-0)' }}>{act.target}</code>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.7rem', fontWeight: 600, color: isSuccess ? 'var(--low-dim)' : 'var(--critical-dim)' }}>
                      {isSuccess ? <CheckCircle2 size={12} style={{ color: 'var(--low)' }} /> : <XCircle size={12} style={{ color: 'var(--critical)' }} />}
                      {act.status.toUpperCase()}
                    </div>
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-2)', background: 'rgba(0,0,0,0.15)', padding: '5px 8px', borderRadius: 'var(--r-xs)', border: '1px solid var(--border-0)', marginTop: 2, fontStyle: 'italic' }}>
                    {act.message}
                  </div>
                </div>
              );
            })}
            {soarActions.length === 0 && (
              <p style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-3)', fontSize: '0.8rem' }}>No automated actions logged yet.</p>
            )}
          </div>
        </div>

        {/* Right Column: SLA Details & Response metrics */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          
          {/* SLA Distribution */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <h3 style={{ fontSize: '0.85rem', color: 'var(--text-0)', marginBottom: 12 }}>SLA Compliance Distribution</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              
              {/* Under 15s Card */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 4 }}>
                  <span>Fast Containment (&lt; 15s)</span>
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, color: 'var(--low)' }}>{slaStats.under15Pct.toFixed(1)}%</span>
                </div>
                <div style={{ width: '100%', height: 4, background: 'var(--border-0)', borderRadius: 2 }}>
                  <div style={{ width: `${slaStats.under15Pct}%`, height: '100%', background: 'var(--low)', borderRadius: 2 }} />
                </div>
              </div>

              {/* Target SLA 30s Card */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 4 }}>
                  <span>SLA Threshold (30s)</span>
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, color: 'var(--info)' }}>{slaStats.under30Pct.toFixed(1)}%</span>
                </div>
                <div style={{ width: '100%', height: 4, background: 'var(--border-0)', borderRadius: 2 }}>
                  <div style={{ width: `${slaStats.under30Pct}%`, height: '100%', background: 'var(--info)', borderRadius: 2 }} />
                </div>
              </div>

              {/* Missed SLA Card */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 4 }}>
                  <span>SLA Violations (&gt; 30s)</span>
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, color: 'var(--text-3)' }}>{slaStats.over30Pct.toFixed(1)}%</span>
                </div>
                <div style={{ width: '100%', height: 4, background: 'var(--border-0)', borderRadius: 2 }}>
                  <div style={{ width: `${slaStats.over30Pct}%`, height: '100%', background: 'var(--critical)', borderRadius: 2 }} />
                </div>
              </div>

            </div>
          </div>

          {/* Performance Audit Guidelines */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <h3 style={{ fontSize: '0.85rem', color: 'var(--text-0)', marginBottom: 8 }}>SOAR Audit Info</h3>
            <p style={{ fontSize: '0.76rem', color: 'var(--text-2)', lineHeight: '1.4' }}>
              All metrics are dynamically calculated from logs generated by the Aegis L2 Orchestrator. 
              The response time is tracked from the initial finding ingestion timestamp to the corresponding action worker completion callback.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 12, padding: '8px 10px', background: 'rgba(0,0,0,0.15)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-xs)', fontSize: '0.72rem', color: 'var(--text-3)' }}>
              <Clock size={12} />
              Centralized Audit DB Storage active in PostgreSQL
            </div>
          </div>

        </div>

      </div>

      {/* WAF IP Block & Ban Registry Table */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', marginTop: 8 }}>
        <div style={{ background: 'var(--bg-surface)', padding: '12px 16px', borderBottom: '1px solid var(--border-1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-0)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={16} style={{ color: 'var(--accent)' }} />
            PostgreSQL Centralized WAF IP Block & Ban Registry
          </span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>
            {bannedIPs.filter(ip => ip.status === 'active').length} Active Bans
          </span>
        </div>

        <div style={{ padding: '8px 12px', overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.76rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-1)', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.68rem' }}>
                <th style={{ padding: '8px 12px' }}>IP ADDRESS</th>
                <th style={{ padding: '8px 12px' }}>BANNED AT</th>
                <th style={{ padding: '8px 12px' }}>BANNED BY</th>
                <th style={{ padding: '8px 12px' }}>REASON / RATIONALE</th>
                <th style={{ padding: '8px 12px' }}>STATUS</th>
                <th style={{ padding: '8px 12px', textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {bannedIPs.map(b => (
                <tr key={b.ipAddress} style={{ borderBottom: '1px solid var(--border-0)', color: 'var(--text-1)' }}>
                  <td style={{ padding: '10px 12px', fontWeight: 600, fontFamily: "'IBM Plex Mono', monospace" }}>{b.ipAddress}</td>
                  <td style={{ padding: '10px 12px', color: 'var(--text-3)' }}>
                    {new Date(b.bannedAt).toLocaleString()}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <span className="badge badge-neutral" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>{b.bannedBy}</span>
                  </td>
                  <td style={{ padding: '10px 12px', color: 'var(--text-2)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {b.reason}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{ 
                      fontSize: '0.65rem', 
                      fontWeight: 700, 
                      padding: '2px 6px', 
                      borderRadius: 4,
                      background: b.status === 'active' ? 'rgba(244, 67, 54, 0.15)' : 'rgba(76, 175, 80, 0.15)',
                      color: b.status === 'active' ? 'var(--critical)' : 'var(--low)'
                    }}>
                      {b.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                    {b.status === 'active' ? (
                      <button 
                        className="btn btn-outline" 
                        style={{ 
                          height: 24, 
                          padding: '0 10px', 
                          fontSize: '0.68rem',
                          borderColor: 'var(--low)',
                          color: 'var(--low)',
                          cursor: 'pointer'
                        }}
                        onClick={() => unblockIP(b.ipAddress)}
                      >
                        Unban IP
                      </button>
                    ) : (
                      <span style={{ color: 'var(--text-3)', fontSize: '0.68rem', fontStyle: 'italic' }}>Unlocked</span>
                    )}
                  </td>
                </tr>
              ))}
              {bannedIPs.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '30px 0', color: 'var(--text-3)' }}>
                    No IP bans registered in PostgreSQL.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
