import { useState, useEffect } from 'react';
import { Send, ShieldAlert, Cpu, CheckCircle, XCircle, RefreshCw, Zap } from 'lucide-react';
import type { Agent, ActionLog, Alert } from '../types';

interface Props {
  agents: Agent[];
  alerts: Alert[];
  actions: ActionLog[];
  timeRange: string;
  setTimeRange: (val: string) => void;
  onRefresh: () => void;
  currentUser?: string;
}

const ACTION_TYPES = ['Isolate Host', 'Block IP', 'Unblock IP', 'Terminate Process', 'Revoke Credentials'];

export default function ResponseCenter({ agents, alerts, actions, timeRange, setTimeRange, onRefresh, currentUser }: Props) {
  const [actor, setActor] = useState(currentUser ? `SOC (${currentUser})` : 'SOC (Sarah Connor)');
  const [actionType, setActionType] = useState(ACTION_TYPES[0]);
  const [target, setTarget] = useState('');
  const [message, setMessage] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  useEffect(() => {
    if (currentUser) {
      setActor(`SOC (${currentUser})`);
    }
  }, [currentUser]);

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

  const filteredAlerts = alerts.filter(a => filterByTimeRange(a.timestamp));

  // Get Top 3 Agents (A1, A2, A3) details
  const a1 = agents.find(a => a.id === 'agent-01') || agents[0];
  const a2 = agents.find(a => a.id === 'agent-02') || agents[1];
  const a3 = agents.find(a => a.id === 'agent-03') || agents[2];
  const targetAgents = [a1, a2, a3].filter(Boolean);

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

  const handleTrigger = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) {
      setErrorMsg('Target value is required.');
      return;
    }
    setErrorMsg('');
    setSuccessMsg('');
    setSubmitting(true);

    try {
      const res = await fetch('/api/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actor, actionType, target, message })
      });
      if (res.ok) {
        setSuccessMsg(`✓ Triggered ${actionType} on ${target} successfully.`);
        setTarget('');
        setMessage('');
        onRefresh();
      } else {
        const err = await res.json();
        setErrorMsg(err.error || 'Action failed');
      }
    } catch {
      setErrorMsg('Network error triggered.');
    } finally {
      setSubmitting(false);
      setTimeout(() => { setSuccessMsg(''); setErrorMsg(''); }, 4000);
    }
  };

  const statusIcon = (s: string) => {
    if (s === 'success') return <CheckCircle size={12} style={{ color: 'var(--low)' }} />;
    if (s === 'failed') return <XCircle size={12} style={{ color: 'var(--critical)' }} />;
    return <RefreshCw size={12} style={{ color: 'var(--medium)', animation: 'spin 2s linear infinite' }} />;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, animation: 'fadeInUp 0.25s ease-out' }}>

      {/* Page Header */}
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div>
          <h1 className="page-title">Response Center</h1>
          <p className="page-subtitle">Perform manual mitigation controls and orchestration</p>
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
          <button className="btn btn-outline" onClick={onRefresh} style={{ height: 28 }}><RefreshCw size={12} /> Refresh</button>
        </div>
      </div>

      {/* 1. TOP PANEL: Agent Abnormality Status (A1, A2, A3) */}
      <div className="glass-panel" style={{ padding: 14 }}>
        <h3 style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-0)', marginBottom: 10 }}>
          <Zap size={14} style={{ color: 'var(--accent)' }} /> Agent Abnormality Status (Primary Hosts)
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          {targetAgents.map((agent, i) => {
            if (!agent) return null;
            const highestSev = getHighestSeverityForAgent(agent.id);
            const totalEvents = filteredAlerts.filter(a => a.agentId === agent.id && ['low', 'medium', 'high', 'critical'].includes(a.severity)).length;
            return (
              <div key={agent.id} style={{
                padding: '10px 14px', background: 'var(--bg-surface)', border: '1px solid var(--border-1)',
                borderRadius: 'var(--r-xs)', display: 'flex', flexDirection: 'column', gap: 6
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-0)', fontSize: '0.82rem' }}>
                    A{i + 1}: {agent.name}
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

      {/* 2. BOTTOM SECTION: Forms, Logs, and Orchestrator */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 16 }}>

        {/* Left Column: Form & Orchestrator */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Remediation Form */}
          <form className="glass-panel" onSubmit={handleTrigger} style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <h3 style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-0)', borderBottom: '1px solid var(--border-1)', paddingBottom: 8, marginBottom: 2 }}>
              <ShieldAlert size={14} style={{ color: 'var(--high)' }} /> Trigger Manual Remediation
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: '0.66rem', color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase' }}>Operator (Analyst)</label>
                <div className="search-input" style={{
                  display: 'flex', alignItems: 'center', height: 36, fontSize: '0.82rem',
                  color: 'var(--accent)', fontWeight: 600, background: 'rgba(0,0,0,0.15)',
                  paddingLeft: 10, cursor: 'not-allowed', borderRadius: 'var(--r-xs)',
                  border: '1px solid var(--border-1)', userSelect: 'none'
                }}>
                  {actor}
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: '0.66rem', color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase' }}>Action Type</label>
                <select className="select-input" value={actionType} onChange={e => setActionType(e.target.value)}>
                  {ACTION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: '0.66rem', color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase' }}>Target Selection</label>
                {actionType === 'Isolate Host' ? (
                  <select className="select-input" value={target} onChange={e => setTarget(e.target.value)}>
                    <option value="">— Select Host —</option>
                    {agents.map(a => <option key={a.id} value={a.name}>{a.name}</option>)}
                  </select>
                ) : (
                  <input type="text" className="search-input" value={target}
                    onChange={e => {
                      const val = e.target.value;
                      if (actionType === 'Block IP') {
                        setTarget(val.replace(/[^0-9.]/g, '').slice(0, 15));
                      } else {
                        setTarget(val.replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 50));
                      }
                    }}
                    placeholder={
                      actionType === 'Block IP' ? 'e.g. 198.51.100.222' :
                        actionType === 'Terminate Process' ? 'e.g. svchost_cipher.exe' : 'e.g. Administrator'
                    }
                  />
                )}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: '0.66rem', color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase' }}>Mitigation Message</label>
                <input type="text" className="search-input" value={message}
                  onChange={e => setMessage(e.target.value.replace(/[<>&"']/g, '').slice(0, 100))}
                  placeholder="Optional comment/reason..." />
              </div>
            </div>

            <button className="btn btn-primary" type="submit" disabled={submitting} style={{ marginTop: 4, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 6 }}>
              <Send size={12} /> {submitting ? 'Executing...' : 'Deploy Mitigation'}
            </button>

            {successMsg && <div style={{ padding: '6px 10px', background: 'var(--low-bg)', border: '1px solid rgba(16,185,129,0.2)', fontSize: '0.76rem', color: 'var(--low-dim)', borderRadius: 'var(--r-xs)' }}>{successMsg}</div>}
            {errorMsg && <div style={{ padding: '6px 10px', background: 'var(--critical-bg)', border: '1px solid rgba(217,63,60,0.2)', fontSize: '0.76rem', color: 'var(--critical-dim)', borderRadius: 'var(--r-xs)' }}>{errorMsg}</div>}
          </form>

          {/* Orchestrator Table */}
          <div className="glass-panel" style={{ padding: 14 }}>
            <h3 style={{ fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-0)', marginBottom: 8 }}>
              <Cpu size={14} style={{ color: 'var(--info)' }} /> Security Orchestrator status
            </h3>
            <div className="table-container" style={{ overflowX: 'auto' }}>
              <table className="sec-table" style={{ width: '100%' }}>
                <thead>
                  <tr>
                    <th>Target Agent</th>
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
                        <td style={{ fontWeight: 600 }}>{a.name}</td>
                        <td style={{ textAlign: 'center', color: cCount > 0 ? 'var(--critical)' : 'var(--text-3)', fontWeight: cCount > 0 ? 600 : 400 }}>{cCount}</td>
                        <td style={{ textAlign: 'center', color: hCount > 0 ? 'var(--high)' : 'var(--text-3)', fontWeight: hCount > 0 ? 600 : 400 }}>{hCount}</td>
                        <td style={{ textAlign: 'center', color: mCount > 0 ? 'var(--medium)' : 'var(--text-3)', fontWeight: mCount > 0 ? 600 : 400 }}>{mCount}</td>
                        <td style={{ textAlign: 'center', color: lCount > 0 ? 'var(--low)' : 'var(--text-3)', fontWeight: lCount > 0 ? 600 : 400 }}>{lCount}</td>
                        <td style={{ textAlign: 'center' }}>
                          <span className={`badge ${getSeverityBadgeColor(highestSev)}`} style={{ fontSize: '0.58rem', padding: '1px 4px' }}>
                            {highestSev}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.7rem', fontWeight: 600, color: statusColor, display: 'flex', alignItems: 'center', gap: 4 }}>
                            <span style={{ width: 5, height: 5, background: statusColor, borderRadius: '50%' }} />
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

        {/* Right Column: Combined Audit Log */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <div style={{ background: 'var(--bg-surface)', padding: '8px 14px', borderBottom: '1px solid var(--border-1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-0)', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Cpu size={12} style={{ color: 'var(--accent)' }} /> Combined Audit Action Log (AI & SOC)
            </span>
            <span style={{ fontSize: '0.68rem', color: 'var(--text-3)' }}>{actions.length} Total</span>
          </div>

          <div style={{ padding: '8px 12px', maxHeight: 'calc(100vh - 180px)', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
            {actions.map(act => {
              const isAI = act.actor === 'AI Agent';
              return (
                <div key={act.id} style={{
                  padding: '8px 10px', background: 'var(--bg-surface)', border: '1px solid var(--border-0)',
                  borderRadius: 'var(--r-xs)', display: 'flex', flexDirection: 'column', gap: 3
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.68rem' }}>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <span className={`badge ${isAI ? 'badge-brand' : 'badge-high'}`}>{act.actor}</span>
                      <span className="badge badge-neutral" style={{ fontSize: '0.58rem', padding: '1px 3px' }}>{act.actionType}</span>
                    </div>
                    <span style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.62rem' }}>
                      {new Date(act.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 1 }}>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-1)' }}>
                      Target: <strong style={{ color: 'var(--text-0)', fontFamily: "'IBM Plex Mono', monospace', fontSize: '0.74rem'" }}>{act.target}</strong>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.68rem', fontWeight: 600, color: act.status === 'success' ? 'var(--low-dim)' : 'var(--critical-dim)' }}>
                      {statusIcon(act.status)} {act.status.toUpperCase()}
                    </div>
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-2)', background: 'rgba(0,0,0,0.15)', padding: '4px 6px', borderRadius: 'var(--r-xs)', border: '1px solid var(--border-0)', marginTop: 1 }}>
                    {act.message}
                  </div>
                </div>
              );
            })}
            {actions.length === 0 && <p style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-3)', fontSize: '0.8rem' }}>No containment actions logged.</p>}
          </div>
        </div>

      </div>
    </div>
  );
}
