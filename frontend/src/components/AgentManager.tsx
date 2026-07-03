import { useState, useEffect } from 'react';
import { Server, Cpu, HardDrive, ShieldAlert, CheckCircle2, ChevronRight, Terminal, RefreshCw } from 'lucide-react';
import type { Agent, Alert, FIMEvent } from '../types';

interface AgentManagerProps {
  agents: Agent[];
}

export default function AgentManager({ agents }: AgentManagerProps) {
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [agentDetail, setAgentDetail] = useState<{
    agent: Agent;
    alerts: Alert[];
    fim: FIMEvent[];
  } | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'alerts' | 'fim' | 'deploy'>('alerts');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  // Fetch agent detail when an agent is selected
  useEffect(() => {
    if (selectedAgentId) {
      setLoading(true);
      fetch(`/api/agents/${selectedAgentId}`)
        .then(res => res.json())
        .then(data => {
          setAgentDetail(data);
          setLoading(false);
        })
        .catch(err => {
          console.error(err);
          setLoading(false);
        });
    } else {
      setAgentDetail(null);
    }
  }, [selectedAgentId, agents]); // Reload detail if agents list updates (e.g. CPU spikes)

  const copyCommand = (cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'alerting':
        return <ShieldAlert size={18} style={{ color: '#fb7185' }} />;
      case 'active':
        return <CheckCircle2 size={18} style={{ color: '#34d399' }} />;
      default:
        return <Server size={18} style={{ color: '#94a3b8' }} />;
    }
  };

  const getProgressBarColor = (val: number) => {
    if (val > 85) return '#f43f5e'; // Red
    if (val > 65) return '#f97316'; // Orange
    return '#10b981'; // Green
  };

  const linuxInstallCmd = `curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.5.3-1_amd64.deb && WAZUH_MANAGER="192.168.10.250" dpkg -i wazuh-agent.deb && systemctl daemon-reload && systemctl enable wazuh-agent && systemctl start wazuh-agent`;
  
  const winInstallCmd = `Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.5.3-1.msi" -OutFile "wazuh-agent.msi"; Start-Process msiexec.exe -ArgumentList '/i wazuh-agent.msi /q WAZUH_MANAGER="192.168.10.250"' -Wait; Start-Service -Name "Wazuh"`;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedAgentId ? '1fr 1.2fr' : '1fr', gap: '24px', transition: 'all 0.3s ease' }}>
      
      {/* Agents List Card */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div className="page-header" style={{ marginBottom: '16px' }}>
          <div>
            <h1 className="page-title">Agent Host Monitor</h1>
            <p className="page-subtitle">Inspect endpoints, operational health, and active processes</p>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {agents.map((agent) => (
            <div
              key={agent.id}
              onClick={() => setSelectedAgentId(agent.id)}
              className={`glass-panel ${agent.status === 'alerting' ? 'pulse-alerting' : ''}`}
              style={{
                padding: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
                background: selectedAgentId === agent.id ? 'rgba(56, 189, 248, 0.05)' : 'rgba(13, 13, 18, 0.45)',
                borderLeft: agent.status === 'alerting' ? '3px solid #f43f5e' : agent.status === 'active' ? '3px solid #10b981' : '3px solid #64748b'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{
                  padding: '8px',
                  borderRadius: '8px',
                  background: 'rgba(255,255,255,0.03)',
                  display: 'flex',
                  alignItems: 'center'
                }}>
                  {getStatusIcon(agent.status)}
                </div>
                <div>
                  <h3 style={{ fontSize: '0.95rem' }}>{agent.name}</h3>
                  <div style={{ display: 'flex', gap: '8px', fontSize: '0.75rem', color: '#94a3b8', marginTop: '4px' }}>
                    <span>{agent.ip}</span>
                    <span>•</span>
                    <span>{agent.os}</span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                {/* Micro usage charts */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '0.7rem', width: '80px', color: '#94a3b8' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>CPU</span>
                    <span style={{ fontWeight: 600 }}>{agent.cpuUsage.toFixed(0)}%</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${agent.cpuUsage}%`, height: '100%', background: getProgressBarColor(agent.cpuUsage) }} />
                  </div>
                </div>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '0.7rem', width: '80px', color: '#94a3b8' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>RAM</span>
                    <span style={{ fontWeight: 600 }}>{agent.ramUsage.toFixed(0)}%</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${agent.ramUsage}%`, height: '100%', background: getProgressBarColor(agent.ramUsage) }} />
                  </div>
                </div>

                <ChevronRight size={16} style={{ color: '#64748b' }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Agent Detail Panel */}
      {selectedAgentId && (
        <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px', height: 'fit-content', border: '1px solid rgba(255,255,255,0.08)' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '60px 0', color: '#38bdf8' }}>
              <RefreshCw size={24} className="pulse-alerting" style={{ animation: 'spin 1.5s linear infinite', margin: '0 auto 10px auto' }} />
              <span style={{ fontSize: '0.85rem' }}>Gathering host diagnostic info...</span>
            </div>
          ) : agentDetail ? (
            <>
              {/* Detail Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className={`badge ${agentDetail.agent.status === 'active' ? 'badge-info' : agentDetail.agent.status === 'alerting' ? 'badge-critical' : 'badge-neutral'}`}>
                      {agentDetail.agent.status}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'JetBrains Mono' }}>{agentDetail.agent.id}</span>
                  </div>
                  <h2 style={{ fontSize: '1.25rem', marginTop: '6px' }}>{agentDetail.agent.name}</h2>
                  <p style={{ margin: '4px 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>IP Address: {agentDetail.agent.ip} | OS: {agentDetail.agent.os}</p>
                </div>
                <button className="btn btn-outline" onClick={() => setSelectedAgentId(null)} style={{ padding: '4px 10px' }}>
                  ✕ Close
                </button>
              </div>

              {/* Resource Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.03)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '8px' }}>
                    <Cpu size={14} /> CPU LOAD
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800 }}>{agentDetail.agent.cpuUsage.toFixed(1)}%</div>
                  <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.08)', borderRadius: '2px', overflow: 'hidden', marginTop: '8px' }}>
                    <div style={{ width: `${agentDetail.agent.cpuUsage}%`, height: '100%', background: getProgressBarColor(agentDetail.agent.cpuUsage) }} />
                  </div>
                </div>

                <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.03)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '8px' }}>
                    <Server size={14} /> RAM UTILS
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800 }}>{agentDetail.agent.ramUsage.toFixed(1)}%</div>
                  <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.08)', borderRadius: '2px', overflow: 'hidden', marginTop: '8px' }}>
                    <div style={{ width: `${agentDetail.agent.ramUsage}%`, height: '100%', background: getProgressBarColor(agentDetail.agent.ramUsage) }} />
                  </div>
                </div>

                <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.03)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '8px' }}>
                    <HardDrive size={14} /> DISK STORAGE
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800 }}>{agentDetail.agent.diskUsage.toFixed(1)}%</div>
                  <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.08)', borderRadius: '2px', overflow: 'hidden', marginTop: '8px' }}>
                    <div style={{ width: `${agentDetail.agent.diskUsage}%`, height: '100%', background: '#3b82f6' }} />
                  </div>
                </div>
              </div>

              {/* Navigation Tabs */}
              <div style={{ display: 'flex', borderBottom: '1px solid hsl(var(--border-muted))', gap: '16px' }}>
                <span 
                  onClick={() => setActiveTab('alerts')}
                  style={{
                    paddingBottom: '8px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    color: activeTab === 'alerts' ? '#38bdf8' : '#64748b',
                    borderBottom: activeTab === 'alerts' ? '2px solid #38bdf8' : 'none'
                  }}
                >
                  Active Alerts ({agentDetail.alerts.filter(a => a.status !== 'resolved').length})
                </span>
                <span 
                  onClick={() => setActiveTab('fim')}
                  style={{
                    paddingBottom: '8px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    color: activeTab === 'fim' ? '#38bdf8' : '#64748b',
                    borderBottom: activeTab === 'fim' ? '2px solid #38bdf8' : 'none'
                  }}
                >
                  FIM Events ({agentDetail.fim.length})
                </span>
                <span 
                  onClick={() => setActiveTab('deploy')}
                  style={{
                    paddingBottom: '8px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    color: activeTab === 'deploy' ? '#38bdf8' : '#64748b',
                    borderBottom: activeTab === 'deploy' ? '2px solid #38bdf8' : 'none'
                  }}
                >
                  Deployment Guide
                </span>
              </div>

              {/* Tab Contents */}
              <div style={{ minHeight: '150px' }}>
                {activeTab === 'alerts' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {agentDetail.alerts.filter(a => a.status !== 'resolved').map(alert => (
                      <div key={alert.id} style={{
                        padding: '12px',
                        background: 'rgba(255,255,255,0.01)',
                        border: '1px solid rgba(255,255,255,0.03)',
                        borderRadius: '6px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className={`badge badge-${alert.severity}`} style={{ fontSize: '0.6rem', padding: '1px 6px' }}>
                              {alert.severity}
                            </span>
                            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <div style={{ fontSize: '0.85rem', fontWeight: 600, marginTop: '4px', color: '#f1f5f9' }}>{alert.title}</div>
                        </div>
                      </div>
                    ))}
                    {agentDetail.alerts.filter(a => a.status !== 'resolved').length === 0 && (
                      <div style={{ color: '#64748b', fontSize: '0.8rem', textAlign: 'center', padding: '30px 0' }}>
                        No active/open threats detected on this host.
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'fim' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {agentDetail.fim.slice(0, 5).map(event => (
                      <div key={event.id} style={{
                        padding: '10px',
                        background: 'rgba(255,255,255,0.01)',
                        borderRadius: '6px',
                        fontSize: '0.8rem'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b', marginBottom: '4px' }}>
                          <span>Event: 
                            <strong style={{
                              marginLeft: '4px',
                              color: event.eventType === 'delete' ? '#f43f5e' : event.eventType === 'create' ? '#10b981' : '#eab308'
                            }}>{event.eventType}</strong>
                          </span>
                          <span>{new Date(event.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div style={{ fontFamily: 'JetBrains Mono', color: '#cbd5e1' }}>{event.filePath}</div>
                        <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '2px' }}>Process: {event.process} | User: {event.user}</div>
                      </div>
                    ))}
                    {agentDetail.fim.length === 0 && (
                      <div style={{ color: '#64748b', fontSize: '0.8rem', textAlign: 'center', padding: '30px 0' }}>
                        No File Integrity Monitoring events logged.
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'deploy' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {/* Linux script */}
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <Terminal size={12} /> Debian/Ubuntu Linux Installation
                        </span>
                        <button className="btn btn-outline" onClick={() => copyCommand(linuxInstallCmd, 'linux')} style={{ padding: '2px 6px', fontSize: '0.65rem' }}>
                          {copiedCmd === 'linux' ? 'Copied!' : 'Copy Script'}
                        </button>
                      </div>
                      <pre style={{
                        background: '#09090b',
                        padding: '10px',
                        borderRadius: '6px',
                        border: '1px solid hsl(var(--border-muted))',
                        color: '#cbd5e1',
                        fontSize: '0.7rem',
                        whiteSpace: 'pre-wrap',
                        margin: 0
                      }}>
                        {linuxInstallCmd}
                      </pre>
                    </div>

                    {/* Windows script */}
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <Terminal size={12} /> Windows PowerShell Installer
                        </span>
                        <button className="btn btn-outline" onClick={() => copyCommand(winInstallCmd, 'windows')} style={{ padding: '2px 6px', fontSize: '0.65rem' }}>
                          {copiedCmd === 'windows' ? 'Copied!' : 'Copy Script'}
                        </button>
                      </div>
                      <pre style={{
                        background: '#09090b',
                        padding: '10px',
                        borderRadius: '6px',
                        border: '1px solid hsl(var(--border-muted))',
                        color: '#cbd5e1',
                        fontSize: '0.7rem',
                        whiteSpace: 'pre-wrap',
                        margin: 0
                      }}>
                        {winInstallCmd}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : null}
        </div>
      )}
    </div>
  );
}

// Spin animation keyframe helper added inside useEffect in App or main index.css
