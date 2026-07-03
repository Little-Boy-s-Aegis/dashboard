import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Users, FileText, Terminal, Activity } from 'lucide-react';
import type { Agent, Alert, FIMEvent, DashboardSummary } from './types';
import DashboardOverview from './components/DashboardOverview';
import AlertsManager from './components/AlertsManager';
import AgentManager from './components/AgentManager';
import FimDashboard from './components/FimDashboard';
import LogExplorer from './components/LogExplorer';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  
  // Global states
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [fimEvents, setFimEvents] = useState<FIMEvent[]>([]);

  // Function to refresh all data from Go APIs
  const refreshAllData = async () => {
    try {
      // Fetch summary
      const summaryRes = await fetch('/api/summary');
      if (summaryRes.ok) {
        const summaryData = await summaryRes.json();
        setSummary(summaryData);
      }

      // Fetch alerts
      const alertsRes = await fetch('/api/alerts');
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData);
      }

      // Fetch agents
      const agentsRes = await fetch('/api/agents');
      if (agentsRes.ok) {
        const agentsData = await agentsRes.json();
        setAgents(agentsData);
      }

      // Fetch FIM
      const fimRes = await fetch('/api/fim');
      if (fimRes.ok) {
        const fimData = await fimRes.json();
        setFimEvents(fimData);
      }
    } catch (e) {
      console.error('Failed to synchronize data with Go backend:', e);
    }
  };

  // Synchronize data on mount and poll every 3 seconds
  useEffect(() => {
    refreshAllData();
    const interval = setInterval(refreshAllData, 3000);
    return () => clearInterval(interval);
  }, []);

  const renderActiveView = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <DashboardOverview
            summary={summary}
            recentAlerts={alerts}
            agents={agents}
            onNavigate={(view) => setActiveTab(view)}
            onSimulate={refreshAllData}
          />
        );
      case 'alerts':
        return <AlertsManager alerts={alerts} onRefresh={refreshAllData} />;
      case 'agents':
        return <AgentManager agents={agents} />;
      case 'fim':
        return <FimDashboard fimEvents={fimEvents} onRefresh={refreshAllData} />;
      case 'logs':
        return <LogExplorer onRefresh={refreshAllData} />;
      default:
        return (
          <div style={{ padding: '40px', textAlign: 'center' }}>
            <h2>View Not Found</h2>
            <button className="btn btn-primary" onClick={() => setActiveTab('overview')}>Back to Dashboard</button>
          </div>
        );
    }
  };

  // Check if system has critical alerts
  const hasCriticalIncident = summary && summary.criticalAlerts > 0;

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="logo-container">
          <Shield size={26} className="logo-icon" />
          <span className="logo-text">AEGIS SOC</span>
        </div>

        <nav className="nav-links">
          <div 
            className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Activity size={18} />
            <span>Overview Dashboard</span>
          </div>

          <div 
            className={`nav-item ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
            style={{ position: 'relative' }}
          >
            <AlertTriangle size={18} />
            <span>Security Alerts</span>
            {summary && summary.criticalAlerts + summary.highAlerts > 0 && (
              <span style={{
                position: 'absolute',
                right: '12px',
                background: hasCriticalIncident ? '#f43f5e' : '#f97316',
                color: '#fff',
                fontSize: '0.65rem',
                fontWeight: 800,
                padding: '2px 6px',
                borderRadius: '9999px',
                boxShadow: hasCriticalIncident ? '0 0 10px rgba(244, 63, 94, 0.4)' : 'none'
              }}>
                {summary.criticalAlerts + summary.highAlerts}
              </span>
            )}
          </div>

          <div 
            className={`nav-item ${activeTab === 'agents' ? 'active' : ''}`}
            onClick={() => setActiveTab('agents')}
          >
            <Users size={18} />
            <span>Host Monitor</span>
          </div>

          <div 
            className={`nav-item ${activeTab === 'fim' ? 'active' : ''}`}
            onClick={() => setActiveTab('fim')}
          >
            <FileText size={18} />
            <span>File Integrity</span>
          </div>

          <div 
            className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`}
            onClick={() => setActiveTab('logs')}
          >
            <Terminal size={18} />
            <span>Elastic Logs</span>
          </div>
        </nav>

        {/* Sidebar Footer */}
        <div className="sidebar-footer">
          <div style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: hasCriticalIncident ? '#f43f5e' : '#10b981',
            boxShadow: hasCriticalIncident ? '0 0 8px #f43f5e' : '0 0 8px #10b981',
            animation: hasCriticalIncident ? 'pulseGlow 1.5s infinite ease-in-out' : 'none'
          }} />
          <div className="system-status">
            <span className="system-status-title">SOC HEALTH</span>
            <span className="system-status-value" style={{ color: hasCriticalIncident ? '#f43f5e' : '#10b981' }}>
              {hasCriticalIncident ? 'ALERTING' : 'SECURE'}
            </span>
          </div>
        </div>
      </aside>

      {/* Main View Panel */}
      <main className="main-content">
        {renderActiveView()}
      </main>
    </div>
  );
}
