import { useState, useEffect } from 'react';
import { Server, Cpu, HardDrive, ShieldAlert, CheckCircle2, ChevronRight, Terminal, RefreshCw, Activity, Wifi } from 'lucide-react';
import type { Agent, Alert, FIMEvent } from '../types';

interface Props { agents: Agent[]; }

export default function AgentManager({ agents }: Props) {
  const [selId, setSelId] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ agent: Agent; alerts: Alert[]; fim: FIMEvent[] } | null>(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<'alerts' | 'fim' | 'deploy'>('alerts');
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (selId) {
      const isInitial = !detail || detail.agent.id !== selId;
      if (isInitial) {
        setLoading(true);
      }
      fetch(`/api/agents/${selId}`)
        .then(r => r.json())
        .then(d => {
          setDetail(d);
          setLoading(false);
        })
        .catch(() => setLoading(false));
    } else {
      setDetail(null);
    }
  }, [selId, agents]);

  const copy = (cmd: string, id: string) => { navigator.clipboard.writeText(cmd); setCopied(id); setTimeout(() => setCopied(null), 2000); };

  const statusIcon = (s: string) => {
    if (s === 'alerting') return <ShieldAlert size={14} style={{ color: 'var(--critical)' }} />;
    if (s === 'active') return <CheckCircle2 size={14} style={{ color: 'var(--low)' }} />;
    return <Server size={14} style={{ color: 'var(--text-3)' }} />;
  };

  const barColor = (v: number) => v > 85 ? 'var(--critical)' : v > 65 ? 'var(--high)' : 'var(--low)';
  const threatColor = (s: number) => s >= 70 ? 'var(--critical)' : s >= 40 ? 'var(--high)' : 'var(--low)';
  const threatLabel = (s: number) => s >= 70 ? 'SEVERE' : s >= 40 ? 'SUSPICIOUS' : 'SECURE';

  const Bar = ({ v, color }: { v: number; color: string }) => (
    <div style={{ width: '100%', height: 3, background: 'var(--border-0)', borderRadius: 1 }}>
      <div style={{ width: `${v}%`, height: '100%', background: color, borderRadius: 1, transition: 'width 0.3s' }} />
    </div>
  );

  const agentHostname = detail?.agent?.name || 'TARGET_HOST';
  const managerHost = typeof window !== 'undefined' && window.location.hostname ? window.location.hostname : 'wazuh.internal.aegis.com';
  const linuxCmd = `curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_latest_amd64.deb && WAZUH_MANAGER="${managerHost}" WAZUH_AGENT_NAME="${agentHostname}" dpkg -i wazuh-agent.deb && systemctl enable --now wazuh-agent`;
  const winCmd = `Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-latest.msi" -OutFile "wazuh-agent.msi"; msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="${managerHost}" WAZUH_AGENT_NAME="${agentHostname}"; Start-Service Wazuh`;

  const tabItems = [
    { key: 'alerts', label: `Alerts (${detail?.alerts.filter(a => a.status !== 'resolved').length || 0})` },
    { key: 'fim', label: `FIM (${detail?.fim.length || 0})` },
    { key: 'deploy', label: 'Deploy' },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selId ? '1fr 1.2fr' : '1fr', gap: 16, animation: 'fadeInUp 0.25s ease-out' }}>
      {/* List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="page-header" style={{ marginBottom: 6 }}>
          <div>
            <h1 className="page-title">Host Monitor</h1>
            <p className="page-subtitle">Endpoints, network, and threat scores</p>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 1, background: 'var(--border-1)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-xs)', overflow: 'hidden' }}>
          {agents.map(a => (
            <div key={a.id} onClick={() => setSelId(a.id)} style={{
              padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              cursor: 'pointer', background: selId === a.id ? 'var(--bg-elevated)' : 'var(--bg-canvas)',
              transition: 'background 0.1s'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ padding: 5, background: 'var(--bg-surface)', borderRadius: 'var(--r-xs)', display: 'flex', border: '1px solid var(--border-0)' }}>
                  {statusIcon(a.status)}
                </div>
                <div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-0)' }}>{a.name}</div>
                  <div style={{ display: 'flex', gap: 6, fontSize: '0.7rem', color: 'var(--text-3)', marginTop: 2, fontFamily: "'IBM Plex Mono', monospace" }}>
                    <span>{a.ip}</span>
                    <span style={{ opacity: 0.3 }}>·</span>
                    <span>{a.os}</span>
                    <span style={{ opacity: 0.3 }}>·</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <Wifi size={8} /> ↓{a.networkIn.toFixed(1)}/↑{a.networkOut.toFixed(1)}
                    </span>
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, width: 52, fontSize: '0.62rem', color: 'var(--text-3)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>CPU</span><span style={{ fontWeight: 600, color: barColor(a.cpuUsage), fontFamily: "'IBM Plex Mono', monospace" }}>{a.cpuUsage.toFixed(0)}%</span></div>
                  <Bar v={a.cpuUsage} color={barColor(a.cpuUsage)} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, width: 52, fontSize: '0.62rem', color: 'var(--text-3)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>RAM</span><span style={{ fontWeight: 600, color: barColor(a.ramUsage), fontFamily: "'IBM Plex Mono', monospace" }}>{a.ramUsage.toFixed(0)}%</span></div>
                  <Bar v={a.ramUsage} color={barColor(a.ramUsage)} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 55 }}>
                  <span style={{ fontSize: '0.55rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.04em' }}>THREAT</span>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: threatColor(a.threatScore), fontFamily: "'IBM Plex Mono', monospace" }}>{a.threatScore}/100</span>
                </div>
                <ChevronRight size={12} style={{ color: 'var(--text-4)' }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detail */}
      {selId && (
        <div className="glass-panel" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14, height: 'fit-content', animation: 'fadeInUp 0.2s' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--accent)' }}>
              <RefreshCw size={18} style={{ animation: 'spin 1.5s linear infinite', display: 'block', margin: '0 auto 8px' }} />
              <span style={{ fontSize: '0.78rem' }}>Loading...</span>
            </div>
          ) : detail ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <span className={`badge ${detail.agent.status === 'active' ? 'badge-success' : detail.agent.status === 'alerting' ? 'badge-critical' : 'badge-neutral'}`}>{detail.agent.status}</span>
                    <code style={{ fontSize: '0.68rem', color: 'var(--text-3)' }}>{detail.agent.id}</code>
                  </div>
                  <h2 style={{ fontSize: '1.1rem', marginTop: 4 }}>{detail.agent.name}</h2>
                  <p style={{ margin: '2px 0 0', fontSize: '0.76rem', color: 'var(--text-3)' }}>{detail.agent.ip} · {detail.agent.os}</p>
                </div>
                <button className="btn btn-outline" onClick={() => setSelId(null)} style={{ padding: '2px 8px', height: 'fit-content' }}>✕</button>
              </div>

              {/* Metrics */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 1, background: 'var(--border-1)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-xs)', overflow: 'hidden' }}>
                {[
                  { icon: <Cpu size={12} />, label: 'CPU', val: detail.agent.cpuUsage, c: barColor(detail.agent.cpuUsage) },
                  { icon: <Server size={12} />, label: 'RAM', val: detail.agent.ramUsage, c: barColor(detail.agent.ramUsage) },
                  { icon: <HardDrive size={12} />, label: 'DISK', val: detail.agent.diskUsage, c: 'var(--accent)' },
                ].map((m, i) => (
                  <div key={i} style={{ padding: 10, background: 'var(--bg-canvas)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.62rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.04em', marginBottom: 6 }}>{m.icon} {m.label}</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-0)', fontFamily: "'IBM Plex Mono', monospace" }}>{m.val.toFixed(1)}%</div>
                    <div style={{ marginTop: 6 }}><Bar v={m.val} color={m.c} /></div>
                  </div>
                ))}
              </div>

              {/* Network + Threat */}
              <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 1, background: 'var(--border-1)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-xs)', overflow: 'hidden' }}>
                <div style={{ padding: 10, background: 'var(--bg-canvas)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.62rem', color: 'var(--text-3)', fontWeight: 600, marginBottom: 8 }}>
                    <Activity size={12} style={{ color: 'var(--accent)' }} /> NETWORK I/O
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-around' }}>
                    <div>
                      <span style={{ fontSize: '0.58rem', color: 'var(--text-3)', fontWeight: 600, display: 'block' }}>DOWN</span>
                      <span style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--low)', fontFamily: "'IBM Plex Mono', monospace" }}>↓{detail.agent.networkIn.toFixed(1)}</span>
                      <span style={{ fontSize: '0.68rem', color: 'var(--text-3)' }}> Mbps</span>
                    </div>
                    <div style={{ width: 1, background: 'var(--border-1)' }} />
                    <div>
                      <span style={{ fontSize: '0.58rem', color: 'var(--text-3)', fontWeight: 600, display: 'block' }}>UP</span>
                      <span style={{ fontSize: '1rem', fontWeight: 700, color: detail.agent.networkOut > 500 ? 'var(--critical)' : 'var(--high)', fontFamily: "'IBM Plex Mono', monospace" }}>↑{detail.agent.networkOut.toFixed(1)}</span>
                      <span style={{ fontSize: '0.68rem', color: 'var(--text-3)' }}> Mbps</span>
                    </div>
                  </div>
                </div>
                <div style={{ padding: 10, background: 'var(--bg-canvas)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.62rem', color: 'var(--text-3)', fontWeight: 600, marginBottom: 6 }}>
                    <ShieldAlert size={12} style={{ color: threatColor(detail.agent.threatScore) }} /> THREAT
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                    <span style={{ fontSize: '1.2rem', fontWeight: 700, color: threatColor(detail.agent.threatScore), fontFamily: "'IBM Plex Mono', monospace" }}>
                      {detail.agent.threatScore}<span style={{ fontSize: '0.7rem', color: 'var(--text-3)', fontWeight: 400 }}>/100</span>
                    </span>
                    <span style={{ fontSize: '0.62rem', fontWeight: 700, color: threatColor(detail.agent.threatScore) }}>{threatLabel(detail.agent.threatScore)}</span>
                  </div>
                  <div style={{ marginTop: 6 }}><Bar v={detail.agent.threatScore || 2} color={threatColor(detail.agent.threatScore)} /></div>
                </div>
              </div>

              {/* Tabs */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-1)', gap: 0, marginTop: 4 }}>
                {tabItems.map(t => (
                  <span key={t.key} onClick={() => setTab(t.key as any)} style={{
                    padding: '6px 12px', fontSize: '0.78rem', fontWeight: 600, cursor: 'pointer',
                    color: tab === t.key ? 'var(--accent)' : 'var(--text-3)',
                    borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent',
                    transition: 'all 0.1s'
                  }}>{t.label}</span>
                ))}
              </div>

              <div style={{ minHeight: 100 }}>
                {tab === 'alerts' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {detail.alerts.filter(a => a.status !== 'resolved').map(a => (
                      <div key={a.id} style={{ padding: '8px 10px', background: 'var(--bg-surface)', border: '1px solid var(--border-0)', borderRadius: 'var(--r-xs)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                          <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>{new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                        </div>
                        <div style={{ fontSize: '0.82rem', fontWeight: 600, marginTop: 3, color: 'var(--text-0)' }}>{a.title}</div>
                      </div>
                    ))}
                    {detail.alerts.filter(a => a.status !== 'resolved').length === 0 && <p style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text-3)', fontSize: '0.8rem' }}>No active threats</p>}
                  </div>
                )}
                {tab === 'fim' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {detail.fim.slice(0, 5).map(e => (
                      <div key={e.id} style={{ padding: '8px 10px', background: 'var(--bg-surface)', borderRadius: 'var(--r-xs)', fontSize: '0.8rem', border: '1px solid var(--border-0)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-3)', marginBottom: 2 }}>
                          <strong style={{ color: e.eventType === 'delete' ? 'var(--critical)' : e.eventType === 'create' ? 'var(--low)' : 'var(--medium)' }}>{e.eventType}</strong>
                          <span>{new Date(e.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                        </div>
                        <div style={{ fontFamily: "'IBM Plex Mono', monospace", color: 'var(--text-1)', fontSize: '0.78rem' }}>{e.filePath}</div>
                      </div>
                    ))}
                    {detail.fim.length === 0 && <p style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text-3)', fontSize: '0.8rem' }}>No FIM events</p>}
                  </div>
                )}
                {tab === 'deploy' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {[{ label: 'Linux', cmd: linuxCmd, id: 'lx' }, { label: 'Windows', cmd: winCmd, id: 'win' }].map(i => (
                      <div key={i.id}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                          <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--accent)' }}><Terminal size={10} /> {i.label}</span>
                          <button className="btn btn-outline" onClick={() => copy(i.cmd, i.id)} style={{ padding: '1px 5px', fontSize: '0.6rem' }}>{copied === i.id ? '✓' : 'Copy'}</button>
                        </div>
                        <pre style={{ background: 'var(--bg-body)', padding: 8, borderRadius: 'var(--r-xs)', border: '1px solid var(--border-1)', color: 'var(--text-2)', fontSize: '0.68rem', whiteSpace: 'pre-wrap', margin: 0, fontFamily: "'IBM Plex Mono', monospace" }}>{i.cmd}</pre>
                      </div>
                    ))}
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
