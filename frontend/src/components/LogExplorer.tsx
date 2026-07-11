import { useState, useEffect } from 'react';
import { Search, RefreshCw, Terminal, BarChart3, ChevronDown, ChevronRight } from 'lucide-react';
import type { LogEntry } from '../types';

interface Props { onRefresh: () => void; }
interface Bucket { time: string; count: number; }

export default function LogExplorer({ onRefresh }: Props) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [hist, setHist] = useState<Bucket[]>([]);
  const [query, setQuery] = useState('');
  const [facility, setFacility] = useState('');
  const [actor, setActor] = useState('');
  const [dq, setDq] = useState('');
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggle = (id: string) => setExpanded(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });

  useEffect(() => { const t = setTimeout(() => setDq(query), 300); return () => clearTimeout(t); }, [query]);

  const fetchLogs = () => {
    setLoading(true);
    const p = new URLSearchParams();
    if (dq) p.append('q', dq);
    if (facility) p.append('facility', facility);
    if (actor) p.append('actor', actor);
    fetch(`/api/logs?${p.toString()}`).then(r => r.json()).then(d => {
      setLogs(d.logs || []); setHist(d.histogram || []); setLoading(false); onRefresh();
    }).catch(() => setLoading(false));
  };

  useEffect(() => { fetchLogs(); }, [dq, facility, actor]);

  const sevStyle = (s: string) => {
    if (s === 'alert') return { color: 'var(--critical-dim)', background: 'var(--critical-bg)' };
    if (s === 'error') return { color: 'var(--high-dim)', background: 'var(--high-bg)' };
    if (s === 'warning') return { color: 'var(--medium-dim)', background: 'var(--medium-bg)' };
    return { color: 'var(--info-dim)', background: 'var(--info-bg)' };
  };

  const maxC = Math.max(...hist.map(h => h.count), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, animation: 'fadeInUp 0.25s ease-out' }}>
      <div className="page-header" style={{ marginBottom: 4 }}>
        <div>
          <h1 className="page-title">Log Explorer</h1>
          <p className="page-subtitle">Search and analyze raw events in real time</p>
        </div>
        <button className="btn btn-outline" onClick={fetchLogs} disabled={loading}>
          <RefreshCw size={12} style={loading ? { animation: 'spin 1s linear infinite' } : {}} /> Refresh
        </button>
      </div>

      {/* Query bar */}
      <div className="glass-panel" style={{ padding: '8px 10px', display: 'flex', gap: 8, alignItems: 'center' }}>
        <div style={{ display: 'flex', flex: 1, gap: 6, background: 'var(--bg-surface)', border: '1px solid var(--border-2)', borderRadius: 'var(--r-xs)', padding: '3px 10px', alignItems: 'center' }}>
          <Search size={13} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
          <input type="text" placeholder="Search logs... (root, failed, 404, db-replica)"
            className="search-input" value={query} onChange={e => setQuery(e.target.value)}
            style={{ border: 'none', background: 'transparent', padding: '4px 0', width: '100%' }} />
        </div>
        <select className="select-input" value={facility} onChange={e => setFacility(e.target.value)} style={{ minWidth: 120 }}>
          <option value="">All Services</option>
          <option value="auth">auth/pam</option>
          <option value="web">web/http</option>
          <option value="daemon">daemon</option>
          <option value="syslog">syslog</option>
          <option value="soc_audit">SOC Audit</option>
        </select>
        <select className="select-input" value={actor} onChange={e => setActor(e.target.value)} style={{ minWidth: 140 }}>
          <option value="">All Originators</option>
          <option value="system">🖥️ System Agents</option>
          <option value="soc">👤 SOC Operators</option>
          <option value="ai">🤖 AI Orchestrator</option>
        </select>
      </div>

      {/* Histogram */}
      {hist.length > 0 && (
        <div className="glass-panel" style={{ padding: '12px 16px' }}>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 4 }}>
            <BarChart3 size={11} /> Frequency (2h)
          </div>
          <div style={{ height: 60, width: '100%' }}>
            <svg width="100%" height="60" style={{ overflow: 'visible' }}>
              {hist.map((b, i) => {
                const w = 6;
                const h = (b.count / maxC) * 40;
                const x = `${(i / (hist.length - 1)) * 94 + 3}%`;
                return (
                  <g key={i}>
                    <rect x={x} y={45 - h} width={w} height={h} rx="1"
                      fill={b.count > 0 ? 'var(--accent)' : 'rgba(255,255,255,0.02)'}
                      opacity={b.count > 0 ? 0.65 : 0.2} />
                    {b.count > 0 && <text x={x} y={42 - h} fill="var(--text-2)" fontSize="7" textAnchor="middle" dx="3" fontFamily="'IBM Plex Mono', monospace">{b.count}</text>}
                    <text x={x} y="58" fill="var(--text-3)" fontSize="7" textAnchor="middle" dx="3" fontFamily="'IBM Plex Mono', monospace">{b.time}</text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>
      )}

      {/* Log console */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div style={{ background: 'var(--bg-row-alt)', padding: '7px 14px', borderBottom: '1px solid var(--border-1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: 5, fontWeight: 600 }}>
            <Terminal size={12} style={{ color: 'var(--accent)' }} /> SYSLOG
          </span>
          <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>{logs.length} entries</span>
        </div>

        <div style={{ padding: '4px 10px', maxHeight: 420, overflowY: 'auto', background: 'var(--bg-body)', display: 'flex', flexDirection: 'column' }}>
          {logs.map(log => (
            <div key={log.id} style={{ borderBottom: '1px solid var(--border-0)' }}>
              <div onClick={() => toggle(log.id)} className="log-row-click" style={{
                display: 'flex', gap: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.76rem',
                lineHeight: 1.5, padding: '4px 4px', cursor: 'pointer', borderRadius: 'var(--r-xs)',
                transition: 'background 0.08s', background: expanded.has(log.id) ? 'rgba(59,130,246,0.03)' : 'transparent',
                userSelect: 'none', alignItems: 'flex-start'
              }}>
                <span style={{ color: 'var(--text-4)', flexShrink: 0, marginTop: 2 }}>
                  {expanded.has(log.id) ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                </span>
                <span style={{ color: 'var(--text-3)', whiteSpace: 'nowrap', fontSize: '0.72rem' }}>
                  {new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                </span>
                <span style={{ color: 'var(--accent)', fontWeight: 600, whiteSpace: 'nowrap' }}>[{log.agentName}]</span>
                <span style={{ color: 'var(--purple)', whiteSpace: 'nowrap', fontSize: '0.72rem' }}>{log.facility}</span>
                <span style={{ ...sevStyle(log.severity), padding: '0 4px', borderRadius: 'var(--r-xs)', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600, lineHeight: '16px', whiteSpace: 'nowrap', flexShrink: 0 }}>
                  {log.severity}
                </span>
                <span style={{ color: 'var(--text-0)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', flex: 1 }}>
                  {log.message}
                  {log.statusCode ? <span style={{ marginLeft: 6, color: log.statusCode >= 400 ? 'var(--critical)' : 'var(--low)', fontWeight: 600 }}>({log.statusCode})</span> : null}
                </span>
              </div>

              {expanded.has(log.id) && (
                <div style={{ padding: '6px 10px 8px', margin: '2px 4px 6px 20px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-xs)', animation: 'fadeInUp 0.15s' }}>
                  <div style={{ color: 'var(--text-3)', fontSize: '0.62rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 4, paddingBottom: 3, borderBottom: '1px solid var(--border-0)' }}>
                    Structured Data
                  </div>
                  <pre style={{ margin: 0, color: 'var(--info-dim)', fontSize: '0.7rem', lineHeight: 1.4, whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: "'IBM Plex Mono', monospace" }}>
                    {JSON.stringify(log, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ))}
          {logs.length === 0 && <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--text-3)' }}>No logs match query.</div>}
        </div>
      </div>
    </div>
  );
}
