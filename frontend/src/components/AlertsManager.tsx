import { useState } from 'react';
import { Search, Eye, CheckCircle, Sparkles, Copy, RefreshCw, Terminal } from 'lucide-react';
import type { Alert, AIAnalysis } from '../types';

interface AlertsManagerProps {
  alerts: Alert[];
  onRefresh: () => void;
}

const ANALYSTS = ['Alex Miller', 'Sarah Connor', 'John Doe', 'AI Copilot'];

export default function AlertsManager({ alerts, onRefresh }: AlertsManagerProps) {
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  
  const [aiAnalysis, setAiAnalysis] = useState<Record<string, AIAnalysis>>({});
  const [loadingAI, setLoadingAI] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Selection state for checkboxes
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Filter alerts locally
  const filteredAlerts = alerts.filter(alert => {
    if (severityFilter && alert.severity !== severityFilter) return false;
    if (categoryFilter && alert.category !== categoryFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        alert.title.toLowerCase().includes(q) ||
        alert.description.toLowerCase().includes(q) ||
        alert.agentName.toLowerCase().includes(q) ||
        alert.mitreTechnique.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const selectedAlert = alerts.find(a => a.id === selectedAlertId);

  // Toggle selection for an alert ID
  const toggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent opening detail panel
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Toggle select all filtered alerts
  const isAllSelected = filteredAlerts.length > 0 && filteredAlerts.every(a => selectedIds.has(a.id));
  const toggleSelectAll = () => {
    if (isAllSelected) {
      setSelectedIds(prev => {
        const next = new Set(prev);
        filteredAlerts.forEach(a => next.delete(a.id));
        return next;
      });
    } else {
      setSelectedIds(prev => {
        const next = new Set(prev);
        filteredAlerts.forEach(a => next.add(a.id));
        return next;
      });
    }
  };

  // Fetch AI analysis from backend
  const handleAIAnalyze = async (alertId: string) => {
    setLoadingAI(alertId);
    try {
      const response = await fetch(`/api/alerts/${alertId}/analyze`, {
        method: 'POST'
      });
      if (response.ok) {
        const data: AIAnalysis = await response.json();
        setAiAnalysis(prev => ({ ...prev, [alertId]: data }));
        onRefresh(); // Refresh alerts to update status to "investigating"
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAI(null);
    }
  };

  // Resolve single alert
  const handleResolve = async (alertId: string) => {
    try {
      const response = await fetch(`/api/alerts/${alertId}/resolve`, {
        method: 'POST'
      });
      if (response.ok) {
        onRefresh(); // Refresh dashboard data
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Assign single alert
  const handleAssign = async (alertId: string, assignee: string) => {
    try {
      const response = await fetch(`/api/alerts/${alertId}/assign`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assignee })
      });
      if (response.ok) {
        onRefresh();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Bulk Resolve alerts
  const handleBulkResolve = async () => {
    if (selectedIds.size === 0) return;
    try {
      const response = await fetch('/api/alerts/bulk-resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: Array.from(selectedIds) })
      });
      if (response.ok) {
        setSelectedIds(new Set());
        onRefresh();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Bulk Assign alerts
  const handleBulkAssign = async (assignee: string) => {
    if (selectedIds.size === 0) return;
    try {
      const response = await fetch('/api/alerts/bulk-assign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: Array.from(selectedIds), assignee })
      });
      if (response.ok) {
        setSelectedIds(new Set());
        onRefresh();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedAlert ? '1.2fr 1fr' : '1fr', gap: '24px', transition: 'all 0.3s ease' }}>
      
      {/* List Column */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 }}>
        <div className="page-header" style={{ marginBottom: '16px' }}>
          <div>
            <h1 className="page-title">Alarms & Incidents</h1>
            <p className="page-subtitle">Triage security incidents and consult AI assistant for playbooks</p>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="glass-panel filter-bar" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', flex: 1, gap: '10px' }}>
            <Search size={18} style={{ color: '#64748b', alignSelf: 'center', marginLeft: '6px' }} />
            <input
              type="text"
              placeholder="Search by host, technique, description..."
              className="search-input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ border: 'none', background: 'transparent', padding: '6px 0', width: '100%' }}
            />
          </div>
          <select
            className="select-input"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            className="select-input"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
          >
            <option value="">All Categories</option>
            <option value="malware">Malware</option>
            <option value="auth">Authentication</option>
            <option value="network">Network Activity</option>
            <option value="fim">File Integrity</option>
            <option value="audit">System Audit</option>
          </select>
        </div>

        {/* Bulk Action Panel */}
        {selectedIds.size > 0 && (
          <div className="glass-panel" style={{
            padding: '12px 18px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'rgba(167, 139, 250, 0.05)',
            border: '1px solid rgba(167, 139, 250, 0.25)',
            borderRadius: '8px',
            animation: 'flashNew 0.3s ease-out'
          }}>
            <div style={{ fontSize: '0.85rem', color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Sparkles size={16} style={{ color: '#a78bfa' }} />
              <span>Selected <strong>{selectedIds.size}</strong> {selectedIds.size === 1 ? 'alert' : 'alerts'}</span>
            </div>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Assign to:</span>
                <select
                  onChange={(e) => {
                    if (e.target.value) {
                      handleBulkAssign(e.target.value);
                      e.target.value = ''; // Reset select
                    }
                  }}
                  style={{
                    background: '#1c1c24',
                    border: '1px solid rgba(255,255,255,0.08)',
                    color: '#cbd5e1',
                    borderRadius: '6px',
                    padding: '4px 8px',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    outline: 'none'
                  }}
                  className="select-input"
                >
                  <option value="">Select Analyst...</option>
                  {ANALYSTS.map(name => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
              </div>

              <button className="btn btn-primary" onClick={handleBulkResolve} style={{ padding: '6px 12px', fontSize: '0.75rem', gap: '6px' }}>
                <CheckCircle size={14} /> Bulk Resolve
              </button>

              <button className="btn btn-outline" onClick={() => setSelectedIds(new Set())} style={{ padding: '6px 12px', fontSize: '0.75rem' }}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Alerts Table */}
        <div className="glass-panel table-container">
          <table className="sec-table">
            <thead>
              <tr>
                <th style={{ width: '40px', textAlign: 'center' }}>
                  <input 
                    type="checkbox" 
                    checked={isAllSelected} 
                    onChange={toggleSelectAll} 
                    style={{ cursor: 'pointer', width: '15px', height: '15px' }} 
                  />
                </th>
                <th>Severity</th>
                <th>Time</th>
                <th>Host</th>
                <th>Alert Title</th>
                <th>MITRE ID</th>
                <th>Assignee</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert) => (
                <tr 
                  key={alert.id}
                  onClick={() => setSelectedAlertId(alert.id)}
                  style={{ cursor: 'pointer', background: selectedAlertId === alert.id ? 'rgba(56, 189, 248, 0.05)' : '' }}
                  className={alert.status !== 'resolved' && (alert.severity === 'critical' || alert.severity === 'high') ? 'row-alerting' : ''}
                >
                  <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                    <input 
                      type="checkbox" 
                      checked={selectedIds.has(alert.id)} 
                      onChange={(e) => toggleSelect(alert.id, e as any)} 
                      style={{ cursor: 'pointer', width: '14px', height: '14px' }} 
                    />
                  </td>
                  <td>
                    <span className={`badge badge-${alert.severity}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </td>
                  <td>{alert.agentName}</td>
                  <td style={{ fontWeight: 600, color: '#f1f5f9' }}>{alert.title}</td>
                  <td>
                    <code style={{ color: '#38bdf8' }}>{alert.mitreTechnique}</code>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <select
                      value={alert.assignee || ''}
                      onChange={(e) => handleAssign(alert.id, e.target.value)}
                      style={{
                        background: 'rgba(255,255,255,0.03)',
                        border: '1px solid rgba(255,255,255,0.08)',
                        color: alert.assignee ? '#a78bfa' : '#64748b',
                        fontWeight: alert.assignee ? 600 : 'normal',
                        borderRadius: '6px',
                        padding: '4px 6px',
                        fontSize: '0.75rem',
                        outline: 'none',
                        cursor: 'pointer'
                      }}
                      className="select-input"
                    >
                      <option value="" style={{ color: '#64748b' }}>Unassigned</option>
                      {ANALYSTS.map(name => (
                        <option key={name} value={name} style={{ color: '#f1f5f9' }}>{name}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <span className={`badge ${alert.status === 'resolved' ? 'badge-info' : alert.status === 'investigating' ? 'badge-medium' : 'badge-neutral'}`}>
                      {alert.status}
                    </span>
                  </td>
                  <td>
                    <button 
                      className="btn btn-outline" 
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedAlertId(alert.id);
                      }}
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                    >
                      <Eye size={12} /> Inspect
                    </button>
                  </td>
                </tr>
              ))}

              {filteredAlerts.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: '#64748b', padding: '40px 0' }}>
                    No matching alerts found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Expanded Details Side Panel */}
      {selectedAlert && (
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px', height: 'fit-content', border: '1px solid rgba(255,255,255,0.08)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'JetBrains Mono' }}>{selectedAlert.id}</span>
              <h2 style={{ fontSize: '1.25rem', marginTop: '4px' }}>{selectedAlert.title}</h2>
            </div>
            <button className="btn btn-outline" onClick={() => setSelectedAlertId(null)} style={{ padding: '4px 10px' }}>
              ✕ Close
            </button>
          </div>

          {/* Description & Host */}
          <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', fontSize: '0.85rem' }}>
            <p style={{ margin: 0 }}>{selectedAlert.description}</p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '12px', color: '#94a3b8' }}>
              <div><strong>Agent Name:</strong> {selectedAlert.agentName}</div>
              <div><strong>Agent ID:</strong> {selectedAlert.agentId}</div>
              <div><strong>MITRE Tech:</strong> <code style={{ color: '#38bdf8' }}>{selectedAlert.mitreTechnique}</code></div>
              <div><strong>Category:</strong> {selectedAlert.category}</div>
              <div style={{ gridColumn: 'span 2', display: 'flex', alignItems: 'center' }}>
                <strong>Assignee:</strong>
                <select
                  value={selectedAlert.assignee || ''}
                  onChange={(e) => handleAssign(selectedAlert.id, e.target.value)}
                  style={{
                    background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    color: selectedAlert.assignee ? '#a78bfa' : '#cbd5e1',
                    fontWeight: selectedAlert.assignee ? 600 : 'normal',
                    borderRadius: '6px',
                    padding: '4px 8px',
                    fontSize: '0.8rem',
                    marginLeft: '8px',
                    outline: 'none',
                    cursor: 'pointer'
                  }}
                  className="select-input"
                >
                  <option value="">Unassigned</option>
                  {ANALYSTS.map(name => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', gap: '10px' }}>
            {selectedAlert.status !== 'resolved' && (
              <button className="btn btn-primary" onClick={() => handleResolve(selectedAlert.id)} style={{ flex: 1, gap: '6px' }}>
                <CheckCircle size={16} /> Mark Resolved
              </button>
            )}
            <button 
              className="btn btn-outline"
              onClick={() => copyToClipboard(selectedAlert.rawLog, 'raw')}
              style={{ gap: '6px' }}
            >
              <Copy size={14} /> {copiedId === 'raw' ? 'Copied!' : 'Copy Event'}
            </button>
          </div>

          {/* AI Security Copilot Analyst */}
          <div style={{
            border: '1px solid rgba(167, 139, 250, 0.25)',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, rgba(167, 139, 250, 0.04) 0%, rgba(139, 92, 246, 0.02) 100%)',
            padding: '20px',
            position: 'relative',
            overflow: 'hidden'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Sparkles size={16} style={{ color: '#c084fc' }} />
              <h3 style={{ fontSize: '0.95rem', background: 'linear-gradient(135deg, #c084fc 0%, #818cf8 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                AI Security Copilot
              </h3>
            </div>

            {loadingAI === selectedAlert.id ? (
              <div style={{ padding: '20px 0', textAlign: 'center', color: '#a78bfa', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                <RefreshCw size={24} className="pulse-alerting" style={{ animation: 'spin 1.5s linear infinite' }} />
                <span style={{ fontSize: '0.8rem', fontFamily: 'JetBrains Mono' }}>Querying threat databases & crafting playbook...</span>
              </div>
            ) : aiAnalysis[selectedAlert.id] ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.85rem' }} className="flash-on-load">
                <div>
                  <div style={{ color: '#c084fc', fontWeight: 600 }}>Triage Assessment</div>
                  <p style={{ margin: '4px 0 0 0', color: '#e2e8f0' }}>{aiAnalysis[selectedAlert.id].summary}</p>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div>
                    <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>Threat Actor Group</span>
                    <div style={{ fontWeight: 600, color: '#fb7185' }}>{aiAnalysis[selectedAlert.id].threatActor}</div>
                  </div>
                  <div>
                    <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>Analyst Confidence</span>
                    <div style={{ fontWeight: 600, color: '#34d399' }}>{aiAnalysis[selectedAlert.id].confidence}%</div>
                  </div>
                </div>

                <div>
                  <div style={{ color: '#c084fc', fontWeight: 600 }}>Technical Details</div>
                  <p style={{ margin: '4px 0 0 0', color: '#94a3b8', fontSize: '0.8rem', lineHeight: 1.5 }}>
                    {aiAnalysis[selectedAlert.id].technicalDetail}
                  </p>
                </div>

                <div>
                  <div style={{ color: '#c084fc', fontWeight: 600, marginBottom: '6px' }}>Incident Remediation Playbook</div>
                  <ul style={{ paddingLeft: '18px', margin: 0, display: 'flex', flexDirection: 'column', gap: '6px', color: '#cbd5e1' }}>
                    {aiAnalysis[selectedAlert.id].remediationSteps?.map((step: string, idx: number) => (
                      <li key={idx} style={{ position: 'relative' }}>
                        <div>{step}</div>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '12px 0' }}>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8', margin: '0 0 16px 0' }}>
                  Run AI-assisted triage to attribute threat actor and retrieve instant CLI command remedies.
                </p>
                <button className="btn btn-primary" onClick={() => handleAIAnalyze(selectedAlert.id)} style={{ width: '100%', background: 'linear-gradient(135deg, #a78bfa 0%, #6366f1 100%)', border: 'none', gap: '6px' }}>
                  <Sparkles size={14} /> Analyze Alert with AI
                </button>
              </div>
            )}
          </div>

          {/* Raw Log Event */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '0.8rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Terminal size={14} /> RAW EVENT JSON DATA
              </span>
            </div>
            <pre style={{
              background: '#09090b',
              padding: '12px',
              borderRadius: '8px',
              border: '1px solid hsl(var(--border-muted))',
              overflowX: 'auto',
              color: '#34d399',
              fontSize: '0.75rem',
              margin: 0
            }}>
              {JSON.stringify(JSON.parse(selectedAlert.rawLog || '{}'), null, 2)}
            </pre>
          </div>

        </div>
      )}
    </div>
  );
}
