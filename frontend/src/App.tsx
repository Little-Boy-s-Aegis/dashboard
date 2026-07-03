import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Monitor, FileText, Terminal, Activity, Clock, Zap } from 'lucide-react';
import type { Agent, Alert, FIMEvent, DashboardSummary, ActionLog } from './types';
import DashboardOverview from './components/DashboardOverview';
import AlertsManager from './components/AlertsManager';
import AgentManager from './components/AgentManager';
import FimDashboard from './components/FimDashboard';
import LogExplorer from './components/LogExplorer';
import ResponseCenter from './components/ResponseCenter';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>(() => localStorage.getItem('activeTab') || 'overview');
  const [timeRange, setTimeRange] = useState<string>(() => localStorage.getItem('timeRange') || '24h');
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [fimEvents, setFimEvents] = useState<FIMEvent[]>([]);
  const [actions, setActions] = useState<ActionLog[]>([]);
  const [alertsFilterMitreId, setAlertsFilterMitreId] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    localStorage.setItem('activeTab', activeTab);
  }, [activeTab]);

  useEffect(() => {
    localStorage.setItem('timeRange', timeRange);
  }, [timeRange]);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const refreshAllData = async () => {
    try {
      const [summaryRes, alertsRes, agentsRes, fimRes, actionsRes] = await Promise.allSettled([
        fetch('/api/summary'), fetch('/api/alerts'), fetch('/api/agents'), fetch('/api/fim'), fetch('/api/actions')
      ]);
      if (summaryRes.status === 'fulfilled' && summaryRes.value.ok) setSummary(await summaryRes.value.json());
      if (alertsRes.status === 'fulfilled' && alertsRes.value.ok) setAlerts(await alertsRes.value.json());
      if (agentsRes.status === 'fulfilled' && agentsRes.value.ok) setAgents(await agentsRes.value.json());
      if (fimRes.status === 'fulfilled' && fimRes.value.ok) setFimEvents(await fimRes.value.json());
      if (actionsRes.status === 'fulfilled' && actionsRes.value.ok) setActions(await actionsRes.value.json());
    } catch (e) { console.error('Data sync failed:', e); }
  };

  useEffect(() => {
    refreshAllData();
    const interval = setInterval(refreshAllData, 3000);
    return () => clearInterval(interval);
  }, []);

  const renderActiveView = () => {
    switch (activeTab) {
      case 'overview':
        return <DashboardOverview summary={summary} recentAlerts={alerts} agents={agents} actions={actions}
          timeRange={timeRange} setTimeRange={setTimeRange}
          onNavigate={(view, mitreId) => { if (mitreId) setAlertsFilterMitreId(mitreId); setActiveTab(view); }}
          onSimulate={refreshAllData} />;
      case 'alerts':
        return <AlertsManager alerts={alerts} onRefresh={refreshAllData}
          initialMitreFilter={alertsFilterMitreId} onClearMitreFilter={() => setAlertsFilterMitreId(null)} />;
      case 'actions':
        return <ResponseCenter agents={agents} alerts={alerts} actions={actions}
          timeRange={timeRange} setTimeRange={setTimeRange} onRefresh={refreshAllData} />;
      case 'agents':
        return <AgentManager agents={agents} />;
      case 'fim':
        return <FimDashboard fimEvents={fimEvents} onRefresh={refreshAllData} />;
      case 'logs':
        return <LogExplorer onRefresh={refreshAllData} />;
      default:
        return <div style={{ padding: 40, textAlign: 'center' }}><h2>Not Found</h2></div>;
    }
  };

  const hasCritical = summary && summary.criticalAlerts > 0;
  const totalActive = summary ? summary.criticalAlerts + summary.highAlerts : 0;

  const navItems = [
    { key: 'overview', icon: Activity, label: 'Overview' },
    { key: 'alerts', icon: AlertTriangle, label: 'Alerts', badge: totalActive },
    { key: 'actions', icon: Zap, label: 'Response Center' },
    { key: 'agents', icon: Monitor, label: 'Hosts' },
    { key: 'fim', icon: FileText, label: 'File Integrity' },
    { key: 'logs', icon: Terminal, label: 'Logs' },
  ];

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="logo-container">
          <Shield size={18} className="logo-icon" style={{ color: 'var(--accent)' }} />
          <span className="logo-text" style={{ letterSpacing: '0.05em' }}>AEGIS</span>
        </div>

        <nav className="nav-links">
          {navItems.map(item => (
            <div key={item.key}
              className={`nav-item ${activeTab === item.key ? 'active' : ''}`}
              onClick={() => setActiveTab(item.key)}
            >
              <item.icon size={15} />
              <span>{item.label}</span>
              {item.badge != null && item.badge > 0 && (
                <span style={{
                  marginLeft: 'auto',
                  background: hasCritical ? 'var(--critical)' : 'var(--high)',
                  color: '#fff',
                  fontSize: '0.6rem',
                  fontWeight: 700,
                  padding: '0 5px',
                  borderRadius: '2px',
                  lineHeight: '16px',
                  fontFamily: "'IBM Plex Mono', monospace"
                }}>{item.badge}</span>
              )}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div style={{
            width: 6, height: 6,
            background: hasCritical ? 'var(--critical)' : 'var(--low)',
            animation: hasCritical ? 'pulseGlow 2s infinite' : 'none'
          }} />
          <div className="system-status">
            <span className="system-status-title">SYS STATUS</span>
            <span className="system-status-value" style={{ color: hasCritical ? 'var(--critical)' : 'var(--low)' }}>
              {hasCritical ? 'ALERTING' : 'SECURED'}
            </span>
          </div>
        </div>

        <div style={{
          padding: '8px 14px 12px',
          borderTop: '1px solid var(--border-1)',
          display: 'flex', alignItems: 'center', gap: 5,
          color: 'var(--text-3)', fontSize: '0.68rem',
          fontFamily: "'IBM Plex Mono', monospace"
        }}>
          <Clock size={10} />
          {currentTime.toLocaleTimeString('en-US', { hour12: false })}
        </div>
      </aside>

      <main className="main-content" style={{ display: 'flex', flexDirection: 'column', padding: '20px 24px' }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          borderBottom: '1px solid var(--border-1)', paddingBottom: 8, marginBottom: 16
        }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-2)' }}>Aegis SOC Workspace</span>
          <span style={{ fontSize: '0.72rem', color: 'var(--accent)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, background: 'var(--accent)', borderRadius: '50%' }} /> Live Stream Active
          </span>
        </div>
        {renderActiveView()}
      </main>
    </div>
  );
}
