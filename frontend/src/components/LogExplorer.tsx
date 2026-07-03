import { useState, useEffect } from 'react';
import { Search, RefreshCw, Terminal, AlertCircle } from 'lucide-react';
import type { LogEntry } from '../types';

interface LogExplorerProps {
  onRefresh: () => void;
}

interface HistogramBucket {
  time: string;
  count: number;
}

export default function LogExplorer({ onRefresh }: LogExplorerProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [histogram, setHistogram] = useState<HistogramBucket[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [facilityFilter, setFacilityFilter] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [loading, setLoading] = useState(false);

  // Debounce search query to avoid spamming requests
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(searchQuery);
    }, 3000); // 300ms debounce
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Fetch logs and histogram
  const fetchLogsData = () => {
    setLoading(true);
    const queryParams = new URLSearchParams();
    if (debouncedQuery) queryParams.append('q', debouncedQuery);
    if (facilityFilter) queryParams.append('facility', facilityFilter);

    fetch(`/api/logs?${queryParams.toString()}`)
      .then(res => res.json())
      .then(data => {
        setLogs(data.logs || []);
        setHistogram(data.histogram || []);
        setLoading(false);
        onRefresh();
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchLogsData();
  }, [debouncedQuery, facilityFilter]);

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case 'alert': return { color: '#fb7185', background: 'rgba(244, 63, 94, 0.12)', border: '1px solid rgba(244, 63, 94, 0.2)' };
      case 'error': return { color: '#f97316', background: 'rgba(249, 115, 22, 0.12)', border: '1px solid rgba(249, 115, 22, 0.2)' };
      case 'warning': return { color: '#fef08a', background: 'rgba(234, 179, 8, 0.12)', border: '1px solid rgba(234, 179, 8, 0.2)' };
      default: return { color: '#93c5fd', background: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.15)' };
    }
  };

  // Find max count in histogram for scaling
  const maxCount = Math.max(...histogram.map(h => h.count), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', animation: 'flashNew 0.5s ease-out' }}>
      <div className="page-header" style={{ marginBottom: '10px' }}>
        <div>
          <h1 className="page-title">Elastic Log Explorer</h1>
          <p className="page-subtitle">Search, parse, and analyze raw log events across nodes in real time</p>
        </div>
        <button className="btn btn-outline" onClick={fetchLogsData} style={{ gap: '6px' }} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'pulse-alerting' : ''} style={{ animation: loading ? 'spin 1s linear infinite' : '' }} /> Refresh logs
        </button>
      </div>

      {/* Query Bar */}
      <div className="glass-panel" style={{ padding: '16px', display: 'flex', gap: '12px' }}>
        <div style={{ display: 'flex', flex: 1, gap: '10px', background: 'rgba(0,0,0,0.15)', border: '1px solid hsl(var(--border-muted))', borderRadius: '8px', padding: '4px 12px' }}>
          <Search size={18} style={{ color: '#64748b', alignSelf: 'center' }} />
          <input
            type="text"
            placeholder="Enter search terms... (e.g. 'root', 'failed', 'status 200', 'db-replica')"
            className="search-input"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ border: 'none', background: 'transparent', padding: '6px 0', width: '100%' }}
          />
        </div>
        
        <select
          className="select-input"
          value={facilityFilter}
          onChange={(e) => setFacilityFilter(e.target.value)}
          style={{ width: '150px' }}
        >
          <option value="">All Services</option>
          <option value="auth">ssh / pam_auth</option>
          <option value="web">apache / web_server</option>
          <option value="daemon">system_daemons</option>
          <option value="syslog">syslogd_kernel</option>
        </select>
      </div>

      {/* Log Histogram */}
      {histogram.length > 0 && (
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '0.85rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertCircle size={14} /> Log Frequency Histogram (Hits over 2 hours)
          </h3>
          <div style={{ height: '80px', width: '100%', position: 'relative' }}>
            <svg width="100%" height="80" style={{ overflow: 'visible' }}>
              {histogram.map((bucket, idx) => {
                const rectWidth = 8;
                const rectHeight = (bucket.count / maxCount) * 55;
                const xPos = `${(idx / (histogram.length - 1)) * 94 + 3}%`;
                const yPos = 60 - rectHeight;

                return (
                  <g key={idx}>
                    {/* Bar */}
                    <rect
                      x={xPos}
                      y={yPos}
                      width={rectWidth}
                      height={rectHeight}
                      rx="2"
                      fill={bucket.count > 0 ? '#38bdf8' : '#27272a'}
                      opacity={bucket.count > 0 ? 0.8 : 0.3}
                      style={{ transition: 'all 0.5s ease' }}
                    />
                    {/* Count Indicator */}
                    {bucket.count > 0 && (
                      <text
                        x={xPos}
                        y={yPos - 6}
                        fill="#e2e8f0"
                        fontSize="9"
                        textAnchor="middle"
                        dx="4"
                      >
                        {bucket.count}
                      </text>
                    )}
                    {/* Time Label */}
                    <text
                      x={xPos}
                      y="78"
                      fill="#64748b"
                      fontSize="9"
                      textAnchor="middle"
                      dx="4"
                    >
                      {bucket.time}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>
      )}

      {/* Log Console Output */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        {/* Terminal Header */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          padding: '10px 18px',
          borderBottom: '1px solid hsl(var(--border-muted))',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span style={{ fontSize: '0.8rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600 }}>
            <Terminal size={14} style={{ color: '#38bdf8' }} /> SYSLOG STREAM OUTPUT
          </span>
          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
            Showing latest {logs.length} entries
          </span>
        </div>

        {/* Scrollable logs area */}
        <div style={{
          padding: '12px 18px',
          maxHeight: '450px',
          overflowY: 'auto',
          background: '#09090b',
          display: 'flex',
          flexDirection: 'column',
          gap: '6px'
        }}>
          {logs.map((log) => (
            <div key={log.id} style={{
              display: 'flex',
              gap: '12px',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '0.8rem',
              lineHeight: 1.6,
              padding: '4px 0',
              borderBottom: '1px solid rgba(255, 255, 255, 0.02)'
            }}>
              {/* Timestamp */}
              <span style={{ color: '#64748b', whiteSpace: 'nowrap' }}>
                {new Date(log.timestamp).toISOString()}
              </span>

              {/* Host */}
              <span style={{ color: '#3b82f6', fontWeight: 600, whiteSpace: 'nowrap' }}>
                [{log.agentName}]
              </span>

              {/* Facility */}
              <span style={{ color: '#a78bfa', whiteSpace: 'nowrap' }}>
                {log.facility}
              </span>

              {/* Severity Badge */}
              <span style={{
                ...getSeverityStyle(log.severity),
                padding: '0 6px',
                borderRadius: '4px',
                fontSize: '0.7rem',
                textTransform: 'uppercase',
                fontWeight: 600,
                display: 'inline-block',
                height: 'fit-content'
              }}>
                {log.severity}
              </span>

              {/* Message */}
              <span style={{ color: '#e2e8f0', wordBreak: 'break-all' }}>
                {log.message}
                {log.statusCode ? (
                  <span style={{
                    marginLeft: '8px',
                    color: log.statusCode >= 400 ? '#f43f5e' : '#10b981',
                    fontWeight: 600
                  }}>
                    (Code: {log.statusCode})
                  </span>
                ) : null}
              </span>
            </div>
          ))}

          {logs.length === 0 && (
            <div style={{ padding: '60px 0', textAlign: 'center', color: '#64748b' }}>
              No log messages matching search query found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
