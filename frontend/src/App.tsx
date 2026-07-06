import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Monitor, FileText, Terminal, Activity, Clock, Zap, LogOut, User, RefreshCw, Cpu } from 'lucide-react';
import type { Agent, Alert, FIMEvent, DashboardSummary, ActionLog } from './types';
import DashboardOverview from './components/DashboardOverview';
import AlertsManager from './components/AlertsManager';
import AgentManager from './components/AgentManager';
import FimDashboard from './components/FimDashboard';
import LogExplorer from './components/LogExplorer';
import ResponseCenter from './components/ResponseCenter';
import SoarPerformanceDashboard from './components/SoarPerformanceDashboard';
import Login from './components/Login';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [user, setUser] = useState<string>('');
  const [activeTab, setActiveTab] = useState<string>(() => localStorage.getItem('activeTab') || 'overview');
  const [timeRange, setTimeRange] = useState<string>(() => localStorage.getItem('timeRange') || '24h');
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [fimEvents, setFimEvents] = useState<FIMEvent[]>([]);
  const [actions, setActions] = useState<ActionLog[]>([]);
  const [alertsFilterMitreId, setAlertsFilterMitreId] = useState<string | null>(null);
  const [currentTime, setCurrentTime] = useState(new Date());

  // Check auth state on mount
  useEffect(() => {
    // Clickjacking Frame-Busting defense (Client-side)
    if (window.self !== window.top) {
      window.top!.location.href = window.self.location.href;
    }

    const verify = async () => {
      try {
        const res = await fetch('/api/auth/check');
        if (res.ok) {
          const data = await res.json();
          setIsAuthenticated(data.isAuthenticated);
          if (data.isAuthenticated) {
            setUser(data.username);
          }
        } else {
          setIsAuthenticated(false);
        }
      } catch {
        setIsAuthenticated(false);
      }
    };
    verify();
  }, []);

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
    if (isAuthenticated !== true) return;
    try {
      const [summaryRes, alertsRes, agentsRes, fimRes, actionsRes] = await Promise.allSettled([
        fetch('/api/summary'), fetch('/api/alerts'), fetch('/api/agents'), fetch('/api/fim'), fetch('/api/actions')
      ]);

      const hasUnauthorized = [summaryRes, alertsRes, agentsRes, fimRes, actionsRes].some(
        res => res.status === 'fulfilled' && res.value.status === 401
      );
      if (hasUnauthorized) {
        setIsAuthenticated(false);
        return;
      }

      if (summaryRes.status === 'fulfilled' && summaryRes.value.ok) setSummary(await summaryRes.value.json());
      if (alertsRes.status === 'fulfilled' && alertsRes.value.ok) setAlerts(await alertsRes.value.json());
      if (agentsRes.status === 'fulfilled' && agentsRes.value.ok) setAgents(await agentsRes.value.json());
      if (fimRes.status === 'fulfilled' && fimRes.value.ok) setFimEvents(await fimRes.value.json());
      if (actionsRes.status === 'fulfilled' && actionsRes.value.ok) setActions(await actionsRes.value.json());
    } catch (e) { console.error('Data sync failed:', e); }
  };

  useEffect(() => {
    if (isAuthenticated === true) {
      refreshAllData();
      const interval = setInterval(refreshAllData, 3000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated]);

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {
      console.error('Logout failed:', e);
    }
    setIsAuthenticated(false);
    setUser('');
  };

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
          timeRange={timeRange} setTimeRange={setTimeRange} onRefresh={refreshAllData}
          currentUser={user} />;
      case 'soar-metrics':
        return <SoarPerformanceDashboard actions={actions} alerts={alerts} />;
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

  const isAlerting = summary && (summary.criticalAlerts > 0 || summary.highAlerts > 0 || summary.threatLevel === 'Severe' || summary.threatLevel === 'Elevated');
  const totalActive = summary ? summary.criticalAlerts + summary.highAlerts : 0;

  const navItems = [
    { key: 'overview', icon: Activity, label: 'Overview' },
    { key: 'alerts', icon: AlertTriangle, label: 'Alerts', badge: totalActive },
    { key: 'actions', icon: Zap, label: 'Response Center' },
    { key: 'soar-metrics', icon: Cpu, label: 'SOAR Performance' },
    { key: 'agents', icon: Monitor, label: 'Hosts' },
    { key: 'fim', icon: FileText, label: 'File Integrity' },
    { key: 'logs', icon: Terminal, label: 'Logs' },
  ];

  if (isAuthenticated === null) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: 'var(--bg-canvas)' }}>
        <RefreshCw size={24} className="spin" style={{ color: 'var(--accent)', marginBottom: 12 }} />
        <span style={{ fontSize: '0.78rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>VERIFYING SECURITY CONTEXT...</span>
      </div>
    );
  }

  if (isAuthenticated === false) {
    return <Login onLoginSuccess={(username) => {
      setIsAuthenticated(true);
      setUser(username);
    }} />;
  }

  return (
    <div className="app-container">
      <aside className="sidebar" style={{ display: 'flex', flexDirection: 'column' }}>
        <div className="logo-container">
          <Shield size={18} className="logo-icon" style={{ color: 'var(--accent)' }} />
          <span className="logo-text" style={{ letterSpacing: '0.05em' }}>AEGIS</span>
        </div>

        <nav className="nav-links" style={{ flex: 1 }}>
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
                  background: isAlerting ? 'var(--critical)' : 'var(--high)',
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
          
          {/* Sidebar Log Out Button */}
          <div className="nav-item" onClick={handleLogout} style={{ marginTop: 24, borderTop: '1px solid var(--border-0)', paddingTop: 14 }}>
            <LogOut size={15} style={{ color: 'var(--critical-dim)' }} />
            <span style={{ color: 'var(--critical-dim)' }}>Log Out</span>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div style={{
            width: 6, height: 6,
            background: isAlerting ? 'var(--critical)' : 'var(--low)',
            animation: isAlerting ? 'pulseGlow 2s infinite' : 'none'
          }} />
          <div className="system-status">
            <span className="system-status-title">SYS STATUS</span>
            <span className="system-status-value" style={{ color: isAlerting ? 'var(--critical)' : 'var(--low)' }}>
              {isAlerting ? 'ALERTING' : 'SECURED'}
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
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-2)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <User size={12} style={{ color: 'var(--accent)' }} />
            Aegis SOC Workspace <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>({user})</span>
          </span>
          <span style={{ fontSize: '0.72rem', color: 'var(--accent)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, background: 'var(--accent)', borderRadius: '50%' }} /> Live Stream Active
          </span>
        </div>
        {renderActiveView()}
      </main>
    </div>
  );
}
