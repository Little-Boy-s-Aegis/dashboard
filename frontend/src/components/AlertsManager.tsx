import { useState, useEffect } from 'react';
import { Search, Eye, CheckCircle, Sparkles, Copy, RefreshCw, Terminal, ShieldAlert, ShieldOff } from 'lucide-react';
import type { Alert, AIAnalysis } from '../types';

const getAttackerIp = (rawLog?: string): string => {
  if (!rawLog) return 'N/A';
  try {
    const parsed = JSON.parse(rawLog);
    return parsed.clientIp || parsed.client_ip || parsed.sourceIp || parsed.source_ip || parsed.srcIp || parsed.ip || 'N/A';
  } catch {
    return 'N/A';
  }
};

interface Props {
  alerts: Alert[];
  onRefresh: () => void;
  initialMitreFilter?: string | null;
  onClearMitreFilter?: () => void;
}

const ANALYSTS = ['Alex Miller', 'Sarah Connor', 'John Doe', 'AI Copilot'];

export default function AlertsManager({ alerts, onRefresh, initialMitreFilter, onClearMitreFilter }: Props) {
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [aiAnalysis, setAiAnalysis] = useState<Record<string, AIAnalysis>>({});
  const [loadingAI, setLoadingAI] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bannedIps, setBannedIps] = useState<string[]>([]);
  const [banningIp, setBanningIp] = useState<string | null>(null);

  const fetchBannedIps = async () => {
    try {
      const res = await fetch('/api/banned-ips');
      if (res.ok) {
        const data = await res.json();
        const active = data.filter((item: any) => item.status === 'active').map((item: any) => item.ipAddress || item.ip_address);
        setBannedIps(active);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchBannedIps();
  }, []);

  const handleBanIp = async (alert: Alert, e: React.MouseEvent) => {
    e.stopPropagation();
    const ip = getAttackerIp(alert.rawLog);
    if (ip === 'N/A') return;
    if (banningIp) return;
    setBanningIp(ip);
    try {
      const res = await fetch(`/api/alerts/${alert.id}/orchestrated-ban`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: ip
        })
      });
      if (res.ok) {
        setBannedIps(prev => [...prev, ip]);
        onRefresh();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setBanningIp(null);
    }
  };

  const handleUnbanIp = async (ip: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (banningIp) return;
    setBanningIp(ip);
    try {
      const res = await fetch('/api/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: 'SOC (admin)',
          actionType: 'Unblock IP',
          target: ip,
          message: 'Quick unban from Alerts & Incidents table'
        })
      });
      if (res.ok) {
        setBannedIps(prev => prev.filter(x => x !== ip));
        onRefresh();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setBanningIp(null);
    }
  };

  useEffect(() => {
    if (initialMitreFilter) { setSearchQuery(initialMitreFilter); onClearMitreFilter?.(); }
  }, [initialMitreFilter, onClearMitreFilter]);

  useEffect(() => {
    if (selectedAlertId && !aiAnalysis[selectedAlertId]) {
      handleAI(selectedAlertId);
    }
  }, [selectedAlertId]);

  const filtered = alerts.filter(a => {
    if (severityFilter && a.severity !== severityFilter) return false;
    if (categoryFilter && a.category !== categoryFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return a.title.toLowerCase().includes(q) || a.description.toLowerCase().includes(q) ||
        a.agentName.toLowerCase().includes(q) || a.mitreTechnique.toLowerCase().includes(q);
    }
    return true;
  });

  const selected = alerts.find(a => a.id === selectedAlertId);
  const allSelected = filtered.length > 0 && filtered.every(a => selectedIds.has(a.id));

  const toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIds(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  };

  const toggleAll = () => {
    if (allSelected) setSelectedIds(p => { const n = new Set(p); filtered.forEach(a => n.delete(a.id)); return n; });
    else setSelectedIds(p => { const n = new Set(p); filtered.forEach(a => n.add(a.id)); return n; });
  };

  const handleAI = async (id: string) => {
    setLoadingAI(id);
    try {
      const r = await fetch(`/api/alerts/${id}/analyze`, { method: 'POST' });
      if (r.ok) { const d: AIAnalysis = await r.json(); setAiAnalysis(p => ({ ...p, [id]: d })); onRefresh(); }
    } catch (e) { console.error(e); } finally { setLoadingAI(null); }
  };



  const handleResolveAndUnban = async (id: string, ip: string) => {
    try {
      await fetch(`/api/alerts/${id}/resolve`, { method: 'POST' });
      if (ip !== 'N/A' && bannedIps.includes(ip)) {
        await fetch('/api/actions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            actor: 'SOC (admin)',
            actionType: 'Unblock IP',
            target: ip,
            message: 'Auto unban on resolving alert'
          })
        });
        setBannedIps(prev => prev.filter(x => x !== ip));
      }
      onRefresh();
    } catch {}
  };

  const handleAssign = async (id: string, assignee: string) => {
    try { await fetch(`/api/alerts/${id}/assign`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ assignee }) }); onRefresh(); } catch {}
  };

  const bulkResolve = async () => {
    if (selectedIds.size === 0) return;
    try { await fetch('/api/alerts/bulk-resolve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: [...selectedIds] }) }); setSelectedIds(new Set()); onRefresh(); } catch {}
  };

  const bulkAssign = async (assignee: string) => {
    if (!assignee || selectedIds.size === 0) return;
    try { await fetch('/api/alerts/bulk-assign', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: [...selectedIds], assignee }) }); setSelectedIds(new Set()); onRefresh(); } catch {}
  };

  const clip = (text: string, id: string) => { navigator.clipboard.writeText(text); setCopiedId(id); setTimeout(() => setCopiedId(null), 2000); };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selected ? '1.2fr 1fr' : '1fr', gap: 16, animation: 'fadeInUp 0.25s ease-out' }}>
      {/* List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0, height: 'calc(100vh - 56px)' }}>
        <div className="page-header" style={{ marginBottom: 6 }}>
          <div>
            <h1 className="page-title">Alarms & Incidents</h1>
            <p className="page-subtitle">Triage alerts and run AI analysis</p>
          </div>
        </div>

        {/* Filters */}
        <div className="glass-panel filter-bar" style={{ padding: '8px 10px' }}>
          <Search size={14} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
          <input type="text" placeholder="Search host, technique, description..." className="search-input"
            value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
            style={{ border: 'none', background: 'transparent', padding: '4px 0', width: '100%' }} />
          <select className="select-input" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} style={{ minWidth: 110 }}>
            <option value="">All Severity</option>
            <option value="critical">Critical</option><option value="high">High</option>
            <option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <select className="select-input" value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)} style={{ minWidth: 120 }}>
            <option value="">All Categories</option>
            <option value="malware">Malware</option><option value="auth">Auth</option>
            <option value="network">Network</option><option value="fim">FIM</option><option value="audit">Audit</option>
          </select>
        </div>

        {/* Bulk */}
        {selectedIds.size > 0 && (
          <div className="glass-panel" style={{ padding: '6px 10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--accent-bg)' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-1)' }}>Selected <strong>{selectedIds.size}</strong></span>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <select onChange={e => { if (e.target.value) { bulkAssign(e.target.value); e.target.value = ''; } }} className="select-input" style={{ padding: '3px 6px', fontSize: '0.72rem' }}>
                <option value="">Assign...</option>
                {ANALYSTS.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
              <button className="btn btn-primary" onClick={bulkResolve} style={{ padding: '3px 10px', fontSize: '0.72rem' }}><CheckCircle size={11} /> Resolve</button>
              <button className="btn btn-outline" onClick={() => setSelectedIds(new Set())} style={{ padding: '3px 8px', fontSize: '0.72rem' }}>Cancel</button>
            </div>
          </div>
        )}

        {/* Table */}
        <div className="glass-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
          <div className="table-container" style={{ flex: 1, overflowY: 'auto' }}>
            <table className="sec-table">
              <colgroup>
                <col style={{ width: 36 }} />
                <col style={{ width: 72 }} />
                <col style={{ width: 70 }} />
                <col style={{ width: 120 }} />
                <col />
                <col style={{ width: 60 }} />
                <col style={{ width: 110 }} />
                <col style={{ width: 68 }} />
                <col style={{ width: 120 }} />
              </colgroup>
              <thead>
                <tr>
                  <th style={{ textAlign: 'center' }}><input type="checkbox" checked={allSelected} onChange={toggleAll} style={{ cursor: 'pointer', accentColor: 'var(--accent)' }} /></th>
                  <th>Severity</th><th>Time</th><th>Host</th><th>Title</th><th>MITRE</th><th>Assignee</th><th>Status</th><th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(a => (
                  <tr key={a.id} onClick={() => setSelectedAlertId(a.id)} style={{ cursor: 'pointer', background: selectedAlertId === a.id ? 'var(--bg-hover)' : undefined }}
                    className={a.status !== 'resolved' && (a.severity === 'critical' || a.severity === 'high') ? 'row-alerting' : ''}>
                    <td style={{ textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                      <input type="checkbox" checked={selectedIds.has(a.id)} onChange={e => toggleSelect(a.id, e as any)} style={{ cursor: 'pointer', accentColor: 'var(--accent)' }} />
                    </td>
                    <td><span className={`badge badge-${a.severity}`}>{a.severity}</span></td>
                    <td style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.76rem' }}>{new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false })}</td>
                    <td style={{ fontWeight: 500 }} title={a.agentName}>{a.agentName}</td>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-0)' }} title={a.title}>{a.title}</div>
                      {(() => {
                        const attackerIp = getAttackerIp(a.rawLog);
                        return attackerIp !== 'N/A' && (
                          <div style={{ fontSize: '0.72rem', color: 'var(--critical)', marginTop: 2, display: 'flex', gap: 4, alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-3)' }}>Attacker:</span> {attackerIp}
                          </div>
                        );
                      })()}
                    </td>
                    <td><code style={{ color: 'var(--info)', fontSize: '0.76rem' }}>{a.mitreTechnique}</code></td>
                    <td onClick={e => e.stopPropagation()}>
                      <select value={a.assignee || ''} onChange={e => handleAssign(a.id, e.target.value)} className="select-input"
                        style={{ background: 'transparent', border: '1px solid var(--border-0)', color: a.assignee ? 'var(--accent-dim)' : 'var(--text-3)', fontWeight: a.assignee ? 600 : 400, padding: '2px 4px', fontSize: '0.7rem', width: '100%' }}>
                        <option value="">—</option>
                        {ANALYSTS.map(n => <option key={n} value={n}>{n}</option>)}
                      </select>
                    </td>
                    <td><span className={`badge ${a.status === 'resolved' ? 'badge-info' : a.status === 'investigating' ? 'badge-medium' : 'badge-neutral'}`}>{a.status}</span></td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <button className="btn btn-outline" onClick={e => { e.stopPropagation(); setSelectedAlertId(a.id); }} style={{ padding: '2px 6px', fontSize: '0.68rem' }} title="View Details"><Eye size={10} /></button>
                        {(() => {
                          const ip = getAttackerIp(a.rawLog);
                          if (ip === 'N/A') return null;
                          const isBanned = bannedIps.includes(ip);
                          return isBanned ? (
                            <button
                              onClick={e => handleUnbanIp(ip, e)}
                              disabled={banningIp === ip}
                              style={{
                                background: 'rgba(16, 185, 129, 0.15)',
                                border: '1px solid rgba(16, 185, 129, 0.4)',
                                color: '#34d399',
                                padding: '2px 6px',
                                fontSize: '0.66rem',
                                borderRadius: 'var(--r-xs)',
                                cursor: 'pointer',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '3px',
                                fontWeight: 600,
                                outline: 'none'
                              }}
                              title="IP is currently banned. Click to unban."
                            >
                              <ShieldOff size={10} />
                              Unban
                            </button>
                          ) : (
                            <button
                              onClick={e => handleBanIp(a, e)}
                              disabled={banningIp === ip}
                              style={{
                                background: 'rgba(239, 68, 68, 0.15)',
                                border: '1px solid rgba(239, 68, 68, 0.4)',
                                color: '#f87171',
                                padding: '2px 6px',
                                fontSize: '0.66rem',
                                borderRadius: 'var(--r-xs)',
                                cursor: 'pointer',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '3px',
                                fontWeight: 600,
                                outline: 'none'
                              }}
                              title="Ban Attacker IP"
                            >
                              <ShieldAlert size={10} />
                              Ban IP
                            </button>
                          );
                        })()}
                      </div>
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-3)', padding: '32px 0' }}>No alerts match filters.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Detail Panel */}
      {selected && (
        <div className="glass-panel" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14, height: 'fit-content', maxHeight: 'calc(100vh - 60px)', overflowY: 'auto', animation: 'fadeInUp 0.2s', position: 'sticky', top: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <div>
              <code style={{ fontSize: '0.68rem', color: 'var(--text-3)' }}>{selected.id}</code>
              <h2 style={{ fontSize: '1.05rem', marginTop: 3 }}>{selected.title}</h2>
            </div>
            <button className="btn btn-outline" onClick={() => setSelectedAlertId(null)} style={{ padding: '2px 8px', fontSize: '0.8rem', height: 'fit-content' }}>✕</button>
          </div>

          <div style={{ padding: 12, background: 'var(--bg-surface)', borderRadius: 'var(--r-xs)', fontSize: '0.84rem', border: '1px solid var(--border-0)' }}>
            <p style={{ margin: 0, lineHeight: 1.5 }}>{selected.description}</p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 10, fontSize: '0.8rem' }}>
              <div style={{ color: 'var(--text-3)' }}>Host (Target): <span style={{ color: 'var(--text-1)' }}>{selected.agentName}</span></div>
              <div style={{ color: 'var(--text-3)' }}>Attacker IP: <span style={{ color: 'var(--critical)', fontWeight: 600 }}>{getAttackerIp(selected.rawLog)}</span></div>
              <div style={{ color: 'var(--text-3)' }}>MITRE: <code style={{ color: 'var(--info)' }}>{selected.mitreTechnique}</code></div>
              <div style={{ color: 'var(--text-3)' }}>Category: <span style={{ color: 'var(--text-1)' }}>{selected.category}</span></div>
              <div style={{ color: 'var(--text-3)' }}>Assignee:
                <select value={selected.assignee || ''} onChange={e => handleAssign(selected.id, e.target.value)} className="select-input"
                  style={{ marginLeft: 4, padding: '2px 6px', fontSize: '0.78rem', color: selected.assignee ? 'var(--accent-dim)' : 'var(--text-2)' }}>
                  <option value="">—</option>
                  {ANALYSTS.map(n => <option key={n} value={n}>{n}</option>)}
                </select>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 6 }}>
            {selected.status !== 'resolved' && (
              <button className="btn btn-primary" onClick={() => handleResolveAndUnban(selected.id, getAttackerIp(selected.rawLog))} style={{ flex: 1 }}>
                <CheckCircle size={12} /> Resolve & Unban
              </button>
            )}
            {(() => {
              const ip = getAttackerIp(selected.rawLog);
              if (ip === 'N/A') return null;
              const isBanned = bannedIps.includes(ip);
              return isBanned ? (
                <button
                  className="btn"
                  onClick={e => handleUnbanIp(ip, e)}
                  disabled={banningIp === ip}
                  style={{
                    background: 'rgba(16, 185, 129, 0.15)',
                    border: '1px solid rgba(16, 185, 129, 0.4)',
                    color: '#34d399',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '4px',
                    fontWeight: 600,
                    flex: 1
                  }}
                >
                  <ShieldOff size={12} /> Unban IP
                </button>
              ) : (
                <button
                  className="btn"
                  onClick={e => handleBanIp(selected, e)}
                  disabled={banningIp === ip}
                  style={{
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    color: '#f87171',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '4px',
                    fontWeight: 600,
                    flex: 1
                  }}
                >
                  <ShieldAlert size={12} /> Ban IP
                </button>
              );
            })()}
            <button className="btn btn-outline" onClick={() => clip(selected.rawLog, 'raw')} style={{ flex: 0.5 }}><Copy size={12} /> {copiedId === 'raw' ? 'Copied' : 'Copy'}</button>
          </div>

          {/* AI */}
          <div style={{ border: '1px solid rgba(167,139,250,0.15)', borderRadius: 'var(--r-xs)', background: 'var(--purple-bg)', padding: 14 }}>
            <h3 style={{ fontSize: '0.85rem', color: 'var(--purple)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
              <Sparkles size={13} /> AI Copilot
            </h3>
            {loadingAI === selected.id ? (
              <div style={{ padding: '14px 0', textAlign: 'center', color: 'var(--purple)' }}>
                <RefreshCw size={18} style={{ animation: 'spin 1.5s linear infinite', display: 'block', margin: '0 auto 6px' }} />
                <span style={{ fontSize: '0.75rem', fontFamily: "'IBM Plex Mono', monospace" }}>Querying threat intel...</span>
              </div>
            ) : aiAnalysis[selected.id] ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: '0.84rem' }}>
                <div><span style={{ color: 'var(--purple)', fontWeight: 600, fontSize: '0.75rem' }}>Assessment</span><p style={{ margin: '3px 0 0', color: 'var(--text-0)' }}>{aiAnalysis[selected.id].summary}</p></div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  <div><span style={{ color: 'var(--text-3)', fontSize: '0.68rem' }}>Actor</span><div style={{ fontWeight: 600, color: 'var(--critical-dim)' }}>{aiAnalysis[selected.id].threatActor}</div></div>
                  <div><span style={{ color: 'var(--text-3)', fontSize: '0.68rem' }}>Confidence</span><div style={{ fontWeight: 600, color: 'var(--low)' }}>{aiAnalysis[selected.id].confidence}%</div></div>
                </div>
                <div><span style={{ color: 'var(--purple)', fontWeight: 600, fontSize: '0.75rem' }}>Details</span><p style={{ margin: '3px 0 0', color: 'var(--text-2)', fontSize: '0.8rem' }}>{aiAnalysis[selected.id].technicalDetail}</p></div>
                <div>
                  <span style={{ color: 'var(--purple)', fontWeight: 600, fontSize: '0.75rem' }}>Playbook</span>
                  <ul style={{ paddingLeft: 14, marginTop: 4, display: 'flex', flexDirection: 'column', gap: 3, fontSize: '0.82rem' }}>
                    {aiAnalysis[selected.id].remediationSteps?.map((s, i) => <li key={i}>{s}</li>)}
                  </ul>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center' }}>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-3)', margin: '0 0 10px' }}>Run AI triage for threat attribution and playbook generation.</p>
                <button className="btn btn-primary" onClick={() => handleAI(selected.id)} style={{ width: '100%', background: 'var(--purple)', borderColor: 'var(--purple)' }}>
                  <Sparkles size={12} /> Analyze
                </button>
              </div>
            )}
          </div>

          {/* Raw */}
          <div>
            <span style={{ fontSize: '0.65rem', color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', display: 'flex', alignItems: 'center', gap: 4, marginBottom: 6 }}>
              <Terminal size={11} /> Raw Event
            </span>
            <pre style={{ background: 'var(--bg-body)', padding: 10, borderRadius: 'var(--r-xs)', border: '1px solid var(--border-1)', overflowX: 'auto', color: 'var(--low)', fontSize: '0.72rem', margin: 0, fontFamily: "'IBM Plex Mono', monospace" }}>
              {JSON.stringify(JSON.parse(selected.rawLog || '{}'), null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
