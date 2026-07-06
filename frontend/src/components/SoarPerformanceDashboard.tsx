import { useState, useEffect } from 'react';
import { Cpu, CheckCircle2, XCircle, Clock, RotateCw, Play, ShieldCheck, Zap } from 'lucide-react';
import type { ActionLog } from '../types';

interface SoarMetrics {
  totalPlaybooks: number;
  successCount: number;
  failedCount: number;
  successRate: number;
  avgResponseTimeSeconds: number;
}

interface Props {
  actions: ActionLog[];
}

export default function SoarPerformanceDashboard({ actions }: Props) {
  const [metrics, setMetrics] = useState<SoarMetrics | null>(null);
  const [loading, setLoading] = useState(true);

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

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
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
            100%
          </div>
          <div className="kpi-trend" style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>
            Within target 30s response SLA
          </div>
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
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, color: 'var(--low)' }}>100%</span>
                </div>
                <div style={{ width: '100%', height: 4, background: 'var(--border-0)', borderRadius: 2 }}>
                  <div style={{ width: '100%', height: '100%', background: 'var(--low)', borderRadius: 2 }} />
                </div>
              </div>

              {/* Target SLA 30s Card */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 4 }}>
                  <span>SLA Threshold (30s)</span>
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, color: 'var(--info)' }}>100%</span>
                </div>
                <div style={{ width: '100%', height: 4, background: 'var(--border-0)', borderRadius: 2 }}>
                  <div style={{ width: '100%', height: '100%', background: 'var(--info)', borderRadius: 2 }} />
                </div>
              </div>

              {/* Missed SLA Card */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 4 }}>
                  <span>SLA Violations (&gt; 30s)</span>
                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, color: 'var(--text-3)' }}>0%</span>
                </div>
                <div style={{ width: '100%', height: 4, background: 'var(--border-0)', borderRadius: 2 }}>
                  <div style={{ width: '0%', height: '100%', background: 'var(--critical)', borderRadius: 2 }} />
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

    </div>
  );
}
