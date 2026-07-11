import { useState } from 'react';
import { Eye, FileText, User, RefreshCw, GitBranch } from 'lucide-react';
import type { FIMEvent } from '../types';

interface Props { fimEvents: FIMEvent[]; onRefresh: () => void; }

export default function FimDashboard({ fimEvents, onRefresh }: Props) {
  const [selId, setSelId] = useState<string | null>(null);
  const sel = fimEvents.find(e => e.id === selId);

  const total = fimEvents.length;
  const mods = fimEvents.filter(e => e.eventType === 'modify').length;
  const creates = fimEvents.filter(e => e.eventType === 'create').length;
  const deletes = fimEvents.filter(e => e.eventType === 'delete').length;

  const typeColor = (t: string) => t === 'create' ? 'var(--low)' : t === 'delete' ? 'var(--critical)' : 'var(--medium)';
  const typeBadge = (t: string) => {
    if (t === 'create') return { background: 'var(--low-bg)', color: 'var(--low-dim)' };
    if (t === 'delete') return { background: 'var(--critical-bg)', color: 'var(--critical-dim)' };
    return { background: 'var(--medium-bg)', color: 'var(--medium-dim)' };
  };

  const getDiff = (event: FIMEvent) => {
    const p = event.filePath;
    const filename = p.split(/[\\/]/).pop() || p;
    const eventType = event.eventType;
    
    const isDoc = filename.endsWith('.docx') || filename.endsWith('.xlsx') || filename.endsWith('.pdf') || filename.endsWith('.png') || filename.endsWith('.jpg') || filename.endsWith('.zip') || filename.endsWith('.exe') || filename.endsWith('.dll');

    if (isDoc) {
      if (eventType === 'create') {
        return {
          f: p,
          d: [
            `+ [Binary Data - Created File: ${filename}]`,
            `+ Size: ${event.size ? `${(event.size / 1024).toFixed(1)} KB` : 'Unknown'}`,
            `+ Format: application/octet-stream`,
            `+ MD5: ${event.md5 || 'N/A'}`
          ]
        };
      } else if (eventType === 'delete') {
        return {
          f: p,
          d: [
            `- [Binary Data - Deleted File: ${filename}]`,
            `- Size: ${event.size ? `${(event.size / 1024).toFixed(1)} KB` : 'Unknown'}`,
            `- Previous Checksum: ${event.md5 || 'N/A'}`
          ]
        };
      } else {
        return {
          f: p,
          d: [
            `  [Binary Data - Modified File: ${filename}]`,
            `- Previous Checksum (MD5): ${event.md5 || 'N/A'}`,
            `+ New Checksum (MD5): ${event.sha256 ? event.sha256.substring(0, 32) : 'N/A'}`,
            `  Modified by: ${event.user || 'unknown'} via ${event.process || 'unknown'}`
          ]
        };
      }
    }

    // Text file diffs generated from event metadata
    if (eventType === 'create') {
      return {
        f: p,
        d: [
          `+ [New File Created: ${filename}]`,
          `+ User: ${event.user || 'unknown'}`,
          `+ Process: ${event.process || 'unknown'}`,
          `+ Size: ${event.size ? `${event.size} bytes` : 'Unknown'}`,
          `+ MD5: ${event.md5 || 'N/A'}`,
          `+ SHA-256: ${event.sha256 ? `${event.sha256.substring(0, 24)}...` : 'N/A'}`
        ]
      };
    } else if (eventType === 'delete') {
      return {
        f: p,
        d: [
          `- [File Deleted: ${filename}]`,
          `- User: ${event.user || 'unknown'}`,
          `- Process: ${event.process || 'unknown'}`,
          `- Previous MD5: ${event.md5 || 'N/A'}`,
          `- Previous SHA-256: ${event.sha256 ? `${event.sha256.substring(0, 24)}...` : 'N/A'}`
        ]
      };
    } else {
      return {
        f: p,
        d: [
          `  [File Modified: ${filename}]`,
          `  Modified by: ${event.user || 'unknown'}`,
          `  Process: ${event.process || 'unknown'}`,
          `- Previous state (pre-modification)`,
          `+ Current MD5: ${event.md5 || 'N/A'}`,
          `+ Current SHA-256: ${event.sha256 ? `${event.sha256.substring(0, 24)}...` : 'N/A'}`,
          `+ Size: ${event.size ? `${event.size} bytes` : 'Unknown'}`
        ]
      };
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: sel ? '1.2fr 1fr' : '1fr', gap: 16, animation: 'fadeInUp 0.25s ease-out' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }}>
        <div className="page-header" style={{ marginBottom: 6 }}>
          <div>
            <h1 className="page-title">File Integrity Monitoring</h1>
            <p className="page-subtitle">Audit file changes across hosts</p>
          </div>
          <button className="btn btn-outline" onClick={onRefresh}><RefreshCw size={12} /> Refresh</button>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1, background: 'var(--border-1)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-xs)', overflow: 'hidden' }}>
          {[
            { label: 'TOTAL', val: total, color: 'var(--text-0)' },
            { label: 'MODIFY', val: mods, color: 'var(--medium)' },
            { label: 'CREATE', val: creates, color: 'var(--low)' },
            { label: 'DELETE', val: deletes, color: 'var(--critical)' },
          ].map((s, i) => (
            <div key={i} style={{ padding: '10px 14px', background: 'var(--bg-canvas)' }}>
              <span style={{ fontSize: '0.62rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.06em' }}>{s.label}</span>
              <div style={{ fontSize: '1.3rem', fontWeight: 700, color: s.color, fontFamily: "'IBM Plex Mono', monospace" }}>{s.val}</div>
            </div>
          ))}
        </div>

        <div className="glass-panel table-container" style={{ maxHeight: 'calc(100vh - 220px)', overflowY: 'auto' }}>
          <table className="sec-table">
            <thead><tr><th>Type</th><th>Time</th><th>Host</th><th>Path</th><th>User</th><th>Process</th><th></th></tr></thead>
            <tbody>
              {fimEvents.map(e => (
                <tr key={e.id} onClick={() => setSelId(e.id)} style={{ cursor: 'pointer', background: selId === e.id ? 'var(--bg-hover)' : undefined }}>
                  <td><span className="badge" style={typeBadge(e.eventType)}>{e.eventType}</span></td>
                  <td style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.78rem' }}>{new Date(e.timestamp).toLocaleTimeString('en-US', { hour12: false })}</td>
                  <td style={{ fontWeight: 500 }}>{e.agentName}</td>
                  <td style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.78rem', color: 'var(--text-1)' }}>{e.filePath}</td>
                  <td><span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><User size={10} style={{ color: 'var(--text-3)' }} />{e.user}</span></td>
                  <td><code style={{ color: 'var(--purple)', fontSize: '0.78rem' }}>{e.process}</code></td>
                  <td><button className="btn btn-outline" style={{ padding: '2px 6px', fontSize: '0.68rem' }}><Eye size={10} /> Diff</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {sel && (
        <div className="glass-panel" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14, height: 'fit-content', animation: 'fadeInUp 0.2s', position: 'sticky', top: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <div>
              <span className="badge badge-neutral" style={{ fontSize: '0.58rem' }}>FIM Inspector</span>
              <h2 style={{ fontSize: '1.05rem', marginTop: 4 }}>Diff Viewer</h2>
              <p style={{ margin: '2px 0 0', fontSize: '0.76rem', color: 'var(--text-3)' }}>{sel.agentName}</p>
            </div>
            <button className="btn btn-outline" onClick={() => setSelId(null)} style={{ padding: '2px 8px', height: 'fit-content' }}>✕</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, background: 'var(--bg-surface)', padding: 12, borderRadius: 'var(--r-xs)', fontSize: '0.8rem', border: '1px solid var(--border-0)' }}>
            <div><span style={{ color: 'var(--text-3)', fontSize: '0.68rem' }}>File</span><div style={{ fontWeight: 600, color: 'var(--text-0)', fontFamily: "'IBM Plex Mono', monospace", fontSize: '0.78rem', wordBreak: 'break-all', marginTop: 2 }}>{sel.filePath}</div></div>
            <div><span style={{ color: 'var(--text-3)', fontSize: '0.68rem' }}>Operation</span><div style={{ fontWeight: 600, color: typeColor(sel.eventType), textTransform: 'capitalize', marginTop: 2 }}>{sel.eventType}</div></div>
            <div><span style={{ color: 'var(--text-3)', fontSize: '0.68rem' }}>User</span><div style={{ fontWeight: 600, color: 'var(--text-0)', marginTop: 2 }}>{sel.user}</div></div>
            <div><span style={{ color: 'var(--text-3)', fontSize: '0.68rem' }}>Process</span><div style={{ fontWeight: 600, color: 'var(--purple)', fontFamily: "'IBM Plex Mono', monospace", marginTop: 2 }}>{sel.process}</div></div>
          </div>

          {sel.eventType !== 'delete' && (
            <div style={{ fontSize: '0.72rem', background: 'var(--bg-body)', padding: '8px 12px', borderRadius: 'var(--r-xs)', border: '1px solid var(--border-1)', display: 'flex', flexDirection: 'column', gap: 3 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: 'var(--text-3)' }}>MD5:</span><code style={{ color: 'var(--accent)' }}>{sel.md5}</code></div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}><span style={{ color: 'var(--text-3)' }}>SHA-256:</span><code style={{ color: 'var(--accent)' }} title={sel.sha256}>{sel.sha256 ? `${sel.sha256.substring(0, 16)}...${sel.sha256.slice(-8)}` : ''}</code></div>
            </div>
          )}

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.65rem', color: 'var(--text-3)', marginBottom: 6, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              <GitBranch size={11} /> Diff
            </div>
            <div style={{ background: 'var(--bg-body)', borderRadius: 'var(--r-xs)', border: '1px solid var(--border-1)', overflow: 'hidden' }}>
              <div style={{ background: 'var(--bg-row-alt)', padding: '6px 12px', borderBottom: '1px solid var(--border-1)', fontSize: '0.7rem', fontFamily: "'IBM Plex Mono', monospace", color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: 4 }}>
                <FileText size={10} /> {getDiff(sel).f}
              </div>
              <pre style={{ padding: '10px 12px', margin: 0, overflowX: 'auto', fontSize: '0.72rem', fontFamily: "'IBM Plex Mono', monospace", lineHeight: 1.6 }}>
                {getDiff(sel).d.map((line, i) => {
                  const add = line.startsWith('+');
                  const rem = line.startsWith('-');
                  return <div key={i} style={{ color: add ? 'var(--low-dim)' : rem ? 'var(--critical-dim)' : 'var(--text-3)', background: add ? 'rgba(16,185,129,0.06)' : rem ? 'rgba(239,68,68,0.06)' : 'transparent', padding: '0 3px', borderRadius: 1 }}>{line}</div>;
                })}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
