import { useState } from 'react';
import { Eye, FileText, User, Terminal, RefreshCw } from 'lucide-react';
import type { FIMEvent } from '../types';

interface FimDashboardProps {
  fimEvents: FIMEvent[];
  onRefresh: () => void;
}

export default function FimDashboard({ fimEvents, onRefresh }: FimDashboardProps) {
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const selectedEvent = fimEvents.find(e => e.id === selectedEventId);

  // Compute metrics
  const total = fimEvents.length;
  const modifies = fimEvents.filter(e => e.eventType === 'modify').length;
  const creates = fimEvents.filter(e => e.eventType === 'create').length;
  const deletes = fimEvents.filter(e => e.eventType === 'delete').length;

  const getEventColor = (type: string) => {
    switch (type) {
      case 'create': return '#10b981'; // Green
      case 'delete': return '#f43f5e'; // Red
      default: return '#eab308'; // Yellow/Amber
    }
  };

  // Get simulated file diffs based on path
  const getFileDiff = (filePath: string) => {
    if (filePath.includes('passwd')) {
      return {
        filename: '/etc/passwd',
        diff: [
          '  syslog:x:104:104::/home/syslog:/usr/sbin/nologin',
          '  uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin',
          '- user1:x:1001:1001:,,,:/home/user1:/bin/bash',
          '+ user1:x:1001:1001:,,,:/home/user1:/bin/bash',
          '+ dev_backdoor:x:0:0:Backdoor Admin Account:/root:/bin/bash'
        ]
      };
    } else if (filePath.includes('limits.conf')) {
      return {
        filename: '/etc/security/limits.conf',
        diff: [
          '  # /etc/security/limits.conf',
          '  #',
          '  #Each line describes a limit for a user/group',
          '- *               soft    core            0',
          '+ *               soft    core            unlimited',
          '+ *               hard    nofile          65536',
          '+ root            soft    nofile          65536',
          '+ root            hard    nofile          65536'
        ]
      };
    } else if (filePath.includes('sshd_config')) {
      return {
        filename: '/etc/ssh/sshd_config',
        diff: [
          '  # Logging',
          '  SyslogFacility AUTH',
          '- PermitRootLogin no',
          '+ PermitRootLogin yes',
          '- PasswordAuthentication no',
          '+ PasswordAuthentication yes',
          '  ChallengeResponseAuthentication no'
        ]
      };
    } else if (filePath.includes('hosts')) {
      return {
        filename: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
        diff: [
          '  127.0.0.1       localhost',
          '  ::1             localhost',
          '+ 198.51.100.222  internal-router.local',
          '+ 203.0.113.88    malicious-c2.net',
          '+ 10.0.12.100     kubernetes.default'
        ]
      };
    } else if (filePath.includes('shadow')) {
      return {
        filename: '/etc/shadow',
        diff: [
          '  systemd-timesync:*:19022:0:99999:7:::',
          '  systemd-network:*:19022:0:99999:7:::',
          '- root:$6$f82k30s9$482...:19022:0:99999:7:::',
          '+ root:$6$f82k30s9$482...:19022:0:99999:7:::',
          '+ dev_backdoor:$6$compromisedhash...:19500:0:99999:7:::'
        ]
      };
    } else if (filePath.endsWith('.locked')) {
      return {
        filename: filePath,
        diff: [
          '  [File Encrypted by Ransomware Payload]',
          '+ -----BEGIN AES ENCRYPTED DATA-----',
          '+ K8s9Xw1mP02sL9mK1s0Dns9Kl2sLd89Km2sLns93ksLkd9sK2',
          '+ dks0sKd8sK2ns9KlsKd9sK2lsKd8sK2ls90dsk1sLd92kdLs91s',
          '+ -----END AES ENCRYPTED DATA-----'
        ]
      };
    }

    return {
      filename: filePath,
      diff: [
        '  [New or Deleted binary file detected]',
        '  Unable to compute character diff on binary payloads.',
        '  Refer to MD5 and SHA-256 hashes to verify checksum changes.'
      ]
    };
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedEvent ? '1.2fr 1fr' : '1fr', gap: '24px', transition: 'all 0.3s ease' }}>
      
      {/* List Column */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 }}>
        <div className="page-header" style={{ marginBottom: '16px' }}>
          <div>
            <h1 className="page-title">File Integrity Monitoring (FIM)</h1>
            <p className="page-subtitle">Audit file creation, modifications, and access details across hosts</p>
          </div>
          <button className="btn btn-outline" onClick={onRefresh} style={{ gap: '6px' }}>
            <RefreshCw size={14} /> Refresh Events
          </button>
        </div>

        {/* FIM Stats Summary */}
        <div className="glass-panel" style={{ padding: '16px 24px', display: 'flex', gap: '40px' }}>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 600 }}>AUDITED CHANGES</span>
            <span style={{ fontSize: '1.5rem', fontWeight: 800 }}>{total}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 600 }}>MODIFICATIONS</span>
            <span style={{ fontSize: '1.5rem', fontWeight: 800, color: '#eab308' }}>{modifies}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 600 }}>CREATIONS</span>
            <span style={{ fontSize: '1.5rem', fontWeight: 800, color: '#10b981' }}>{creates}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 600 }}>DELETIONS</span>
            <span style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f43f5e' }}>{deletes}</span>
          </div>
        </div>

        {/* Event Logs Table */}
        <div className="glass-panel table-container">
          <table className="sec-table">
            <thead>
              <tr>
                <th>Event Type</th>
                <th>Timestamp</th>
                <th>Host</th>
                <th>File Path</th>
                <th>User</th>
                <th>Process</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {fimEvents.map((event) => (
                <tr 
                  key={event.id}
                  onClick={() => setSelectedEventId(event.id)}
                  style={{ cursor: 'pointer', background: selectedEventId === event.id ? 'rgba(56, 189, 248, 0.05)' : '' }}
                >
                  <td>
                    <span 
                      className="badge" 
                      style={{ 
                        background: `${getEventColor(event.eventType)}1a`, 
                        color: getEventColor(event.eventType),
                        borderColor: `${getEventColor(event.eventType)}33`
                      }}
                    >
                      {event.eventType}
                    </span>
                  </td>
                  <td style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </td>
                  <td>{event.agentName}</td>
                  <td style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem', color: '#cbd5e1' }}>
                    {event.filePath}
                  </td>
                  <td style={{ display: 'flex', alignItems: 'center', gap: '4px', borderBottom: 'none', padding: '14px 0' }}>
                    <User size={12} style={{ color: '#64748b' }} /> {event.user}
                  </td>
                  <td>
                    <code style={{ color: '#a78bfa' }}>{event.process}</code>
                  </td>
                  <td>
                    <button className="btn btn-outline" style={{ padding: '4px 8px', fontSize: '0.75rem' }}>
                      <Eye size={12} /> View Diff
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Diff Inspector Column */}
      {selectedEvent && (
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px', height: 'fit-content', border: '1px solid rgba(255,255,255,0.08)' }}>
          
          {/* Inspector Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>FIM Details</span>
              <h2 style={{ fontSize: '1.25rem', marginTop: '6px' }}>Integrity Diff Inspector</h2>
              <p style={{ margin: '4px 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>Host: {selectedEvent.agentName}</p>
            </div>
            <button className="btn btn-outline" onClick={() => setSelectedEventId(null)} style={{ padding: '4px 10px' }}>
              ✕ Close
            </button>
          </div>

          {/* Metadata */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '14px', borderRadius: '8px', fontSize: '0.8rem' }}>
            <div>
              <span style={{ color: '#64748b' }}>Modified File:</span>
              <div style={{ fontWeight: 600, color: '#f1f5f9', fontFamily: 'JetBrains Mono', marginTop: '2px', wordBreak: 'break-all' }}>{selectedEvent.filePath}</div>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Operation Type:</span>
              <div style={{ fontWeight: 600, color: getEventColor(selectedEvent.eventType), textTransform: 'capitalize', marginTop: '2px' }}>{selectedEvent.eventType}</div>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Responsible User:</span>
              <div style={{ fontWeight: 600, color: '#f1f5f9', marginTop: '2px' }}>{selectedEvent.user}</div>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Responsible Process:</span>
              <div style={{ fontWeight: 600, color: '#a78bfa', fontFamily: 'JetBrains Mono', marginTop: '2px' }}>{selectedEvent.process}</div>
            </div>
          </div>

          {/* File Hash Values */}
          {selectedEvent.eventType !== 'delete' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.75rem', background: '#09090b', padding: '10px 14px', borderRadius: '6px', border: '1px solid hsl(var(--border-muted))' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#64748b' }}>MD5:</span>
                <code style={{ color: '#38bdf8' }}>{selectedEvent.md5}</code>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#64748b' }}>SHA-256:</span>
                <code style={{ color: '#38bdf8' }} title={selectedEvent.sha256}>
                  {selectedEvent.sha256 ? `${selectedEvent.sha256.substring(0, 16)}...${selectedEvent.sha256.slice(-8)}` : ''}
                </code>
              </div>
            </div>
          )}

          {/* Code Diff Display */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '8px' }}>
              <Terminal size={14} /> FILE INTEGRITY DIFF ANALYZER
            </div>
            
            <div style={{
              background: '#09090b',
              borderRadius: '8px',
              border: '1px solid hsl(var(--border-muted))',
              overflow: 'hidden'
            }}>
              {/* File Title Bar */}
              <div style={{
                background: 'rgba(255,255,255,0.03)',
                padding: '8px 14px',
                borderBottom: '1px solid hsl(var(--border-muted))',
                fontSize: '0.75rem',
                fontFamily: 'JetBrains Mono',
                color: '#94a3b8',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <FileText size={12} /> {getFileDiff(selectedEvent.filePath).filename}
              </div>

              {/* Line Diffs */}
              <pre style={{
                padding: '14px',
                margin: 0,
                overflowX: 'auto',
                fontSize: '0.75rem',
                fontFamily: 'JetBrains Mono',
                lineHeight: 1.6
              }}>
                {getFileDiff(selectedEvent.filePath).diff.map((line, idx) => {
                  const isAdded = line.startsWith('+');
                  const isRemoved = line.startsWith('-');
                  const color = isAdded ? '#34d399' : isRemoved ? '#fb7185' : '#64748b';
                  const bg = isAdded ? 'rgba(52, 211, 153, 0.05)' : isRemoved ? 'rgba(251, 113, 133, 0.05)' : 'transparent';
                  return (
                    <div key={idx} style={{ color, background: bg, padding: '0 4px', borderRadius: '2px' }}>
                      {line}
                    </div>
                  );
                })}
              </pre>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
