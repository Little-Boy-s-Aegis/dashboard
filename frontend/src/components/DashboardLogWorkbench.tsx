import { useEffect, useMemo, useState } from 'react';
import { BarChart3, Database, Grip, PieChart, RefreshCw, Search, Table2, Terminal } from 'lucide-react';
import type { ActionLog, Agent, Alert, LogEntry } from '../types';

type SourceKey = 'syslog' | 'alerts' | 'actions' | 'hosts';
type VisualKey = 'table' | 'bar' | 'donut';

interface Props {
  alerts: Alert[];
  agents: Agent[];
  actions: ActionLog[];
}

interface FieldOption {
  key: string;
  label: string;
}

interface LensEvent {
  id: string;
  timestamp: string;
  source: SourceKey;
  title: string;
  actor: string;
  severity: string;
  status: string;
  message: string;
  fields: Record<string, string | number | boolean | undefined>;
}

const SOURCE_OPTIONS: Array<{ key: SourceKey; label: string; eyebrow: string }> = [
  { key: 'syslog', label: 'Raw Events', eyebrow: 'Ingest' },
  { key: 'alerts', label: 'Detections', eyebrow: 'SOC' },
  { key: 'actions', label: 'Response', eyebrow: 'SOAR' },
  { key: 'hosts', label: 'Host State', eyebrow: 'EDR' },
];

const FIELD_OPTIONS: Record<SourceKey, FieldOption[]> = {
  syslog: [
    { key: 'facility', label: 'Service' },
    { key: 'severity', label: 'Severity' },
    { key: 'agentName', label: 'Host' },
    { key: 'sourceIp', label: 'Source IP' },
    { key: 'statusCode', label: 'HTTP Status' },
    { key: 'threatType', label: 'Threat Type' },
  ],
  alerts: [
    { key: 'severity', label: 'Severity' },
    { key: 'category', label: 'Category' },
    { key: 'status', label: 'Status' },
    { key: 'agentName', label: 'Host' },
    { key: 'mitreTechnique', label: 'MITRE' },
    { key: 'ruleId', label: 'Rule' },
  ],
  actions: [
    { key: 'actionType', label: 'Action' },
    { key: 'status', label: 'Status' },
    { key: 'actor', label: 'Actor' },
    { key: 'target', label: 'Target' },
  ],
  hosts: [
    { key: 'status', label: 'Status' },
    { key: 'os', label: 'OS' },
    { key: 'threatBand', label: 'Threat Band' },
    { key: 'cpuBand', label: 'CPU Band' },
    { key: 'ramBand', label: 'RAM Band' },
  ],
};

const CHART_COLORS = [
  'var(--critical)',
  'var(--high)',
  'var(--info)',
  'var(--low)',
  'var(--medium)',
  'var(--accent)',
  'var(--text-2)',
  'var(--purple)',
];

const toBand = (value: number, warning: number, critical: number) => {
  if (value >= critical) return 'critical';
  if (value >= warning) return 'warning';
  return 'normal';
};

const threatBand = (score: number) => {
  if (score >= 70) return 'severe';
  if (score >= 40) return 'elevated';
  return 'normal';
};

const textValue = (value: string | number | boolean | undefined) => {
  if (value === undefined || value === null || value === '') return 'unknown';
  return String(value);
};

const formatTime = (timestamp: string) => {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return 'n/a';
  return date.toLocaleTimeString('en-US', { hour12: false });
};

const readAlertSourceIp = (rawLog: string) => {
  try {
    const parsed = JSON.parse(rawLog) as Record<string, unknown>;
    return String(parsed.clientIp || parsed.client_ip || parsed.sourceIp || parsed.source_ip || parsed.srcIp || parsed.ip || '');
  } catch {
    return '';
  }
};

export default function DashboardLogWorkbench({ alerts, agents, actions }: Props) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [selectedSource, setSelectedSource] = useState<SourceKey>('syslog');
  const [selectedField, setSelectedField] = useState('facility');
  const [selectedValue, setSelectedValue] = useState('all');
  const [visual, setVisual] = useState<VisualKey>('table');
  const [query, setQuery] = useState('');

  const fetchSyslog = async () => {
    setLogsLoading(true);
    try {
      const response = await fetch('/api/logs?limit=250');
      if (response.ok) {
        const payload = await response.json();
        setLogs(Array.isArray(payload.logs) ? payload.logs : []);
      }
    } catch (error) {
      console.error('Failed to fetch dashboard logs:', error);
    } finally {
      setLogsLoading(false);
    }
  };

  useEffect(() => {
    void fetchSyslog();
  }, []);

  useEffect(() => {
    const available = FIELD_OPTIONS[selectedSource];
    if (!available.some(option => option.key === selectedField)) {
      setSelectedField(available[0].key);
    }
    setSelectedValue('all');
  }, [selectedSource, selectedField]);

  useEffect(() => {
    setSelectedValue('all');
  }, [selectedField]);

  const events = useMemo<LensEvent[]>(() => {
    if (selectedSource === 'syslog') {
      return logs.map(log => ({
        id: log.id,
        timestamp: log.timestamp,
        source: 'syslog',
        title: `${log.facility}/${log.severity}`,
        actor: log.agentName,
        severity: log.severity,
        status: log.threatFlagged ? 'flagged' : 'observed',
        message: log.message,
        fields: {
          facility: log.facility,
          severity: log.severity,
          agentName: log.agentName,
          sourceIp: log.sourceIp,
          statusCode: log.statusCode || undefined,
          threatType: log.threatType,
        },
      }));
    }

    if (selectedSource === 'alerts') {
      return alerts.map(alert => ({
        id: alert.id,
        timestamp: alert.timestamp,
        source: 'alerts',
        title: alert.title,
        actor: alert.agentName,
        severity: alert.severity,
        status: alert.status,
        message: alert.description,
        fields: {
          severity: alert.severity,
          category: alert.category,
          status: alert.status,
          agentName: alert.agentName,
          mitreTechnique: alert.mitreTechnique,
          ruleId: alert.ruleId,
          sourceIp: readAlertSourceIp(alert.rawLog),
        },
      }));
    }

    if (selectedSource === 'actions') {
      return actions.map(action => ({
        id: action.id,
        timestamp: action.timestamp,
        source: 'actions',
        title: action.actionType,
        actor: action.actor,
        severity: action.status === 'failed' ? 'error' : 'info',
        status: action.status,
        message: action.message,
        fields: {
          actionType: action.actionType,
          status: action.status,
          actor: action.actor,
          target: action.target,
        },
      }));
    }

    return agents.map(agent => ({
      id: agent.id,
      timestamp: agent.lastSeen,
      source: 'hosts',
      title: agent.name,
      actor: agent.ip,
      severity: threatBand(agent.threatScore),
      status: agent.status,
      message: `${agent.os} | CPU ${agent.cpuUsage.toFixed(0)}% | RAM ${agent.ramUsage.toFixed(0)}% | Threat ${agent.threatScore}/100`,
      fields: {
        status: agent.status,
        os: agent.os,
        threatBand: threatBand(agent.threatScore),
        cpuBand: toBand(agent.cpuUsage, 65, 85),
        ramBand: toBand(agent.ramUsage, 70, 88),
      },
    }));
  }, [actions, agents, alerts, logs, selectedSource]);

  const fieldValues = useMemo(() => {
    const counts = new Map<string, number>();
    events.forEach(event => {
      const value = textValue(event.fields[selectedField]);
      counts.set(value, (counts.get(value) || 0) + 1);
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 18);
  }, [events, selectedField]);

  const filteredEvents = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return events.filter(event => {
      const fieldValue = textValue(event.fields[selectedField]);
      if (selectedValue !== 'all' && fieldValue !== selectedValue) return false;
      if (!normalizedQuery) return true;
      const haystack = [
        event.title,
        event.actor,
        event.severity,
        event.status,
        event.message,
        ...Object.values(event.fields).map(textValue),
      ].join(' ').toLowerCase();
      return haystack.includes(normalizedQuery);
    });
  }, [events, query, selectedField, selectedValue]);

  const chartRows = useMemo(() => {
    const counts = new Map<string, number>();
    filteredEvents.forEach(event => {
      const value = textValue(event.fields[selectedField]);
      counts.set(value, (counts.get(value) || 0) + 1);
    });
    return [...counts.entries()]
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [filteredEvents, selectedField]);

  const selectedFieldLabel = FIELD_OPTIONS[selectedSource].find(option => option.key === selectedField)?.label || 'Data';
  const maxCount = Math.max(...chartRows.map(row => row.count), 1);
  const totalCount = chartRows.reduce((sum, row) => sum + row.count, 0);

  let cursor = 0;
  const donutGradient = chartRows.length
    ? `conic-gradient(${chartRows.map((row, index) => {
      const start = cursor;
      const end = cursor + (row.count / Math.max(totalCount, 1)) * 360;
      cursor = end;
      return `${CHART_COLORS[index % CHART_COLORS.length]} ${start}deg ${end}deg`;
    }).join(', ')})`
    : 'conic-gradient(var(--border-2) 0deg 360deg)';

  return (
    <section className="event-workbench glass-panel">
      <div className="event-workbench-header">
        <div>
          <span className="section-kicker"><Database size={12} /> Event Lens</span>
          <h2>Audit timeline</h2>
        </div>
        <button className="btn btn-outline" onClick={fetchSyslog} disabled={logsLoading} title="Refresh raw events">
          <RefreshCw size={12} className={logsLoading ? 'spin' : ''} />
          Sync
        </button>
      </div>

      <div className="event-controls">
        <label>
          <span>Log</span>
          <select className="select-input" value={selectedSource} onChange={event => setSelectedSource(event.target.value as SourceKey)}>
            {SOURCE_OPTIONS.map(source => (
              <option key={source.key} value={source.key}>{source.eyebrow} · {source.label}</option>
            ))}
          </select>
        </label>

        <label>
          <span>Data</span>
          <select className="select-input" value={selectedField} onChange={event => setSelectedField(event.target.value)}>
            {FIELD_OPTIONS[selectedSource].map(field => (
              <option key={field.key} value={field.key}>{field.label}</option>
            ))}
          </select>
        </label>

        <label>
          <span>Value</span>
          <select className="select-input" value={selectedValue} onChange={event => setSelectedValue(event.target.value)}>
            <option value="all">All values</option>
            {fieldValues.map(([value, count]) => (
              <option key={value} value={value}>{value} ({count})</option>
            ))}
          </select>
        </label>

        <label className="event-search">
          <span>Search</span>
          <div>
            <Search size={13} />
            <input value={query} onChange={event => setQuery(event.target.value)} placeholder="event, host, IP, MITRE..." />
          </div>
        </label>

        <div className="event-view-toggle" aria-label="Visualization">
          <button className={visual === 'table' ? 'active' : ''} onClick={() => setVisual('table')} title="Table view">
            <Table2 size={14} /> Table
          </button>
          <button className={visual === 'bar' ? 'active' : ''} onClick={() => setVisual('bar')} title="Chart view">
            <BarChart3 size={14} /> Chart
          </button>
          <button className={visual === 'donut' ? 'active' : ''} onClick={() => setVisual('donut')} title="Circle view">
            <PieChart size={14} /> Circle
          </button>
        </div>
      </div>

      <div className="event-workbench-canvas">
        <div className="event-canvas-bar">
          <span><Terminal size={12} /> {filteredEvents.length} events</span>
          <span>{selectedFieldLabel}</span>
          <Grip size={14} />
        </div>

        {visual === 'table' && (
          <div className="table-container event-table-wrap">
            <table className="sec-table event-table">
              <colgroup>
                <col style={{ width: 92 }} />
                <col style={{ width: 112 }} />
                <col style={{ width: 130 }} />
                <col style={{ width: 110 }} />
                <col />
              </colgroup>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>{selectedFieldLabel}</th>
                  <th>Status</th>
                  <th>Event</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.slice(0, 80).map(event => (
                  <tr key={`${event.source}-${event.id}`}>
                    <td style={{ fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-3)' }}>{formatTime(event.timestamp)}</td>
                    <td>
                      <span className={`event-source-pill source-${event.source}`}>{SOURCE_OPTIONS.find(source => source.key === event.source)?.label}</span>
                    </td>
                    <td title={textValue(event.fields[selectedField])}>{textValue(event.fields[selectedField])}</td>
                    <td><span className={`badge badge-${event.status === 'failed' ? 'critical' : event.severity}`}>{event.status}</span></td>
                    <td>
                      <strong>{event.title}</strong>
                      <span>{event.actor}</span>
                      <p>{event.message}</p>
                    </td>
                  </tr>
                ))}
                {filteredEvents.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-3)', padding: '32px 0' }}>No events match the current lens.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {visual === 'bar' && (
          <div className="event-chart-bars">
            {chartRows.map((row, index) => (
              <div className="event-bar-row" key={row.label}>
                <span title={row.label}>{row.label}</span>
                <div>
                  <i style={{ width: `${(row.count / maxCount) * 100}%`, background: CHART_COLORS[index % CHART_COLORS.length] }} />
                </div>
                <strong>{row.count}</strong>
              </div>
            ))}
            {chartRows.length === 0 && <div className="event-empty-state">No chart data</div>}
          </div>
        )}

        {visual === 'donut' && (
          <div className="event-donut-view">
            <div className="event-donut" style={{ background: donutGradient }}>
              <div>
                <strong>{totalCount}</strong>
                <span>events</span>
              </div>
            </div>
            <div className="event-donut-legend">
              {chartRows.map((row, index) => (
                <div key={row.label}>
                  <i style={{ background: CHART_COLORS[index % CHART_COLORS.length] }} />
                  <span title={row.label}>{row.label}</span>
                  <strong>{totalCount > 0 ? Math.round((row.count / totalCount) * 100) : 0}%</strong>
                </div>
              ))}
              {chartRows.length === 0 && <div className="event-empty-state">No circle data</div>}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
