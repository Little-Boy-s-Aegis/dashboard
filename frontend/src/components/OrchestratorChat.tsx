import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal, Zap, Send, CheckCircle, XCircle, Server, Database, Key, MessageSquare
} from 'lucide-react';
import type { Agent } from '../types';

interface Props {
  agents: Agent[];
}

interface ChatMessage {
  id: string;
  sender: 'agent' | 'orchestrator';
  senderName: string;
  timestamp: string;
  message: string;
  details?: string; // Expandable JSON string or logs
  actionExecuted?: {
    type: string;
    target: string;
    status: 'success' | 'failed' | 'pending';
    message: string;
    payload?: string;
  };
}

interface Conversation {
  agentId: string;
  agentName: string;
  agentIp: string;
  agentOs: string;
  agentIcon: React.ReactNode;
  messages: ChatMessage[];
}

export default function OrchestratorChat({ agents }: Props) {
  const [activeTab, setActiveTab] = useState<string>('agent-01');
  const [userInput, setUserInput] = useState<string>('');
  const [conversations, setConversations] = useState<Record<string, Conversation>>({});
  const [isTyping, setIsTyping] = useState<boolean>(false);
  const [expandedDetailsId, setExpandedDetailsId] = useState<string | null>(null);
  const [inspectJsonMode, setInspectJsonMode] = useState<boolean>(true);
  
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Initialize conversations with highly detailed mock security logs and SOAR reactions
  useEffect(() => {
    // Attempt to match with real agents if available, otherwise default to mock metadata
    const webAgent = agents.find(a => a.name.toLowerCase().includes('web') || a.id === 'agent-01') || {
      id: 'agent-01', name: 'Web-Prod-01', ip: '10.0.1.45', os: 'Ubuntu 22.04 LTS', threatScore: 85
    };
    const dbAgent = agents.find(a => a.name.toLowerCase().includes('db') || a.id === 'agent-02') || {
      id: 'agent-02', name: 'DB-Internal-02', ip: '10.0.2.89', os: 'RedHat Enterprise 9', threatScore: 15
    };
    const authAgent = agents.find(a => a.name.toLowerCase().includes('auth') || a.id === 'agent-03') || {
      id: 'agent-03', name: 'Auth-Gateway-03', ip: '10.0.0.12', os: 'Debian 11 Minimal', threatScore: 50
    };

    setConversations({
      'agent-01': {
        agentId: webAgent.id,
        agentName: webAgent.name,
        agentIp: webAgent.ip,
        agentOs: webAgent.os,
        agentIcon: <Server size={16} />,
        messages: [
          {
            id: 'web-m1',
            sender: 'agent',
            senderName: webAgent.name,
            timestamp: new Date(Date.now() - 45 * 60000).toLocaleTimeString(),
            message: 'SECURITY ALERT: Nginx detected high frequency of SQL injection payloads hitting API endpoint /v1/auth/login.',
            details: JSON.stringify({
              log_source: "nginx-access-logger",
              event_type: "signature_match",
              signature_name: "OWASP_TOP_10_SQL_INJECTION",
              http_request: {
                method: "POST",
                path: "/v1/auth/login",
                user_agent: "Mozilla/5.0 (Hydra-Scanner/v9.2)",
                client_ip: "149.88.23.87",
                payload: "admin' OR '1'='1'--",
                payload_hex: "61646d696e27204f52202731273d2731272d2d"
              },
              alert_count_1m: 145,
              severity_score: 8.5
            }, null, 2)
          },
          {
            id: 'web-m2',
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: new Date(Date.now() - 44 * 60000).toLocaleTimeString(),
            message: 'AI Assessment: Threat verified. Attacker IP 149.88.23.87 is conducting active exploitation scanner against authentication route. Autopilot rule triggered: Containment Active.',
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.99,
                triage_summary: "Confirmed malicious SQL injection scanner. Signature matches Hydra-automated vulnerability scanner trying classic authentication bypass strings.",
                incident_risk_level: "High",
                recommended_action: "Immediate Ingress Block at WAF / Edge Router"
              },
              mitre_mapping: {
                tactic: "Exploitation for Privilege Escalation",
                technique_id: "T1190",
                technique_name: "Exploit Public-Facing Application"
              }
            }, null, 2),
            actionExecuted: {
              type: "AWS WAF Block IP",
              target: "149.88.23.87/32",
              status: "success",
              message: "Successfully synchronized SOAR network ACL IP block. WAF rule 2017 applied to CloudFront WebACL.",
              payload: JSON.stringify({
                waf_action: "Block",
                ip_set_id: "aegis-blocked-ips-ipset",
                ip_range: "149.88.23.87/32",
                arn: "arn:aws:wafv2:ap-southeast-1:080641082881:regional/ipset/aegis-blocked-ips/6844f0fb"
              }, null, 2)
            }
          },
          {
            id: 'web-m3',
            sender: 'agent',
            senderName: webAgent.name,
            timestamp: new Date(Date.now() - 30 * 60000).toLocaleTimeString(),
            message: 'STATUS SYNC: Inbound HTTP traffic from IP 149.88.23.87 has dropped to 0. Threat mitigated. CPU usage stabilizing.',
            details: JSON.stringify({
              agent_status: "Healthy",
              ingress_bps: 0,
              cpu_utilization: 24.5,
              active_threat_score: 12
            }, null, 2)
          }
        ]
      },
      'agent-02': {
        agentId: dbAgent.id,
        agentName: dbAgent.name,
        agentIp: dbAgent.ip,
        agentOs: dbAgent.os,
        agentIcon: <Database size={16} />,
        messages: [
          {
            id: 'db-m1',
            sender: 'agent',
            senderName: dbAgent.name,
            timestamp: new Date(Date.now() - 90 * 60000).toLocaleTimeString(),
            message: 'INTEGRITY REPORT: Syscheck detected unauthorized file modification in system configuration directories.',
            details: JSON.stringify({
              audit_type: "file_integrity_monitoring",
              file_modified: "/etc/postgresql/15/main/pg_hba.conf",
              modification_details: {
                event: "modify",
                user: "postgres",
                process: "/usr/lib/postgresql/15/bin/postgres",
                md5_old: "f9b88ef25b88cdeee21115",
                md5_new: "3499fa1b5ef999bb3cdeee",
                permission_diff: "-rw-r--r-- -> -rwxrwxrwx"
              },
              threat_indicators: [
                "Unexpected daemon binary modifying configuration",
                "Wide open file permissions added (777)"
              ]
            }, null, 2)
          },
          {
            id: 'db-m2',
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: new Date(Date.now() - 89 * 60000).toLocaleTimeString(),
            message: 'AI Assessment: Severity High. Modification to database host files allows broad network access to secure database. Autopilot rule triggered: Revert Configuration and Isolate Host.',
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.94,
                triage_summary: "Suspicious pg_hba.conf modification. Added wide open connection access rules (host all all 0.0.0.0/0 trust). Indicates potential SQL privilege escalation or database hijacking attempt.",
                incident_risk_level: "High",
                recommended_action: "Revert configuration to master template, quarantine DB access from external gateway."
              }
            }, null, 2),
            actionExecuted: {
              type: "AWS Security Group Quarantine",
              target: dbAgent.ip,
              status: "success",
              message: "Successfully attached isolation security group sg-0dbdb0998 to EC2 Instance. Denied ingress/egress except for SOC debug subnet.",
              payload: JSON.stringify({
                target_instance_id: "i-099abccde121ff89f",
                action: "ReplaceSecurityGroups",
                old_groups: ["sg-default-db"],
                new_groups: ["sg-aegis-quarantine-soc"]
              }, null, 2)
            }
          },
          {
            id: 'db-m3',
            sender: 'agent',
            senderName: dbAgent.name,
            timestamp: new Date(Date.now() - 88 * 60000).toLocaleTimeString(),
            message: 'INTEGRITY SYNC: Reverted /etc/postgresql/15/main/pg_hba.conf to default config from configuration master. Postgres restarted successfully.',
            details: JSON.stringify({
              reversion_status: "Successful",
              md5_current: "f9b88ef25b88cdeee21115",
              pg_service_status: "Active"
            }, null, 2)
          }
        ]
      },
      'agent-03': {
        agentId: authAgent.id,
        agentName: authAgent.name,
        agentIp: authAgent.ip,
        agentOs: authAgent.os,
        agentIcon: <Key size={16} />,
        messages: [
          {
            id: 'auth-m1',
            sender: 'agent',
            senderName: authAgent.name,
            timestamp: new Date(Date.now() - 15 * 60000).toLocaleTimeString(),
            message: 'SECURITY ALERT: Multiple SSH login failures detected on root account from external address 104.28.163.100.',
            details: JSON.stringify({
              log_source: "pam_secure_logger",
              event_type: "auth_failure",
              user_targeted: "root",
              attempts_count_5s: 38,
              client_ip: "104.28.163.100",
              geo_ip: "United States (Cloudflare Routing)",
              auth_method: "password"
            }, null, 2)
          },
          {
            id: 'auth-m2',
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: new Date(Date.now() - 14 * 60000).toLocaleTimeString(),
            message: 'AI Assessment: Severity Medium. Active brute-force attack targeting gateway ssh services. Autopilot containment initiated: Add IP to SOAR Blocklist.',
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.88,
                triage_summary: "Authentication brute force on SSH port 22. Highly suggestive of dictionary scan. Recommending ingress IP lock.",
                recommended_action: "Deploy host ACL deny rule, block IP globally."
              }
            }, null, 2),
            actionExecuted: {
              type: "Host iptables IP ban",
              target: "104.28.163.100",
              status: "success",
              message: "Successfully synchronized local iptables blocklist. Added drop rule for 104.28.163.100.",
              payload: JSON.stringify({
                command: "iptables -A INPUT -s 104.28.163.100 -j DROP",
                chain: "INPUT",
                target_action: "DROP"
              }, null, 2)
            }
          }
        ]
      }
    });
  }, [agents]);

  // Scroll to bottom of chat when messages change
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [conversations, activeTab, isTyping]);

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;

    const currentTab = activeTab;
    const userMessageText = userInput;
    setUserInput('');

    // Append User Message to active conversation
    const userMsg: ChatMessage = {
      id: `usr-m-${Date.now()}`,
      sender: 'agent',
      senderName: 'SOC Analyst Console',
      timestamp: new Date().toLocaleTimeString(),
      message: userMessageText
    };

    setConversations(prev => ({
      ...prev,
      [currentTab]: {
        ...prev[currentTab],
        messages: [...prev[currentTab].messages, userMsg]
      }
    }));

    // Trigger AI Orchestrator Response Simulation after a short delay
    setIsTyping(true);

    setTimeout(() => {
      setIsTyping(false);
      let responseMsgText = '';
      let responseDetails = '';
      let mockAction: ChatMessage['actionExecuted'] = undefined;

      const lowerInput = userMessageText.toLowerCase();

      if (currentTab === 'agent-01') {
        if (lowerInput.includes('status') || lowerInput.includes('check')) {
          responseMsgText = 'Orchestrator AI Response: Web-Prod-01 status query parsed. Analyzing traffic metrics. WAF rule 2017 remains active. Attacker IP 149.88.23.87 remains blocked. Ingress latency is 4ms (nominal).';
          responseDetails = JSON.stringify({
            latency_check: "OK",
            active_rules: ["WAF-2017-BLOCK-SQLI"],
            health: "98/100"
          }, null, 2);
        } else if (lowerInput.includes('unban') || lowerInput.includes('clear')) {
          responseMsgText = 'Orchestrator AI Action: Clear request authorized. Unblocking IP range 149.88.23.87 on AWS WAF.';
          responseDetails = JSON.stringify({
            action: "DeleteWafEntry",
            ip: "149.88.23.87/32"
          }, null, 2);
          mockAction = {
            type: "AWS WAF Unblock IP",
            target: "149.88.23.87/32",
            status: "success",
            message: "Removed 149.88.23.87 from WAF WebACL block IP set."
          };
        } else {
          responseMsgText = `Orchestrator AI Response: I have received your request regarding Web-Prod-01. I am currently running continuous packet analysis on ingress web traffic. No active threats detected at this time.`;
          responseDetails = JSON.stringify({
            last_analysis: new Date().toISOString(),
            status: "Monitoring"
          }, null, 2);
        }
      } else if (currentTab === 'agent-02') {
        if (lowerInput.includes('quarantine') || lowerInput.includes('isolate') || lowerInput.includes('reconnect')) {
          const isReconnecting = lowerInput.includes('reconnect');
          responseMsgText = isReconnecting 
            ? 'Orchestrator AI Action: Restoring network access to DB-Internal-02. Attaching default security group pg-default-db.' 
            : 'Orchestrator AI Action: DB-Internal-02 remains in isolated security group. Only SOC debug traffic is authorized.';
          
          mockAction = {
            type: isReconnecting ? "Restore Network" : "Quarantine Verification",
            target: "DB-Internal-02",
            status: "success",
            message: isReconnecting 
              ? "Replaced sg-aegis-quarantine-soc with sg-default-db on DB host."
              : "Security Group quarantine validated. sg-aegis-quarantine-soc is attached."
          };
        } else {
          responseMsgText = 'Orchestrator AI Response: DB-Internal-02 configuration integrity is normal. File integrity monitor is scanning `/etc/postgresql` every 5 minutes. No new modification events detected.';
        }
      } else if (currentTab === 'agent-03') {
        responseMsgText = 'Orchestrator AI Response: Auth-Gateway-03 SSH monitoring active. Blocklist synced with 1 active iptables rule. Brute-force threats contained.';
        responseDetails = JSON.stringify({
          active_blocklist_ips: ["104.28.163.100"],
          ssh_attempts_10m: 0
        }, null, 2);
      }

      const orcMsg: ChatMessage = {
        id: `orc-m-${Date.now()}`,
        sender: 'orchestrator',
        senderName: 'L2 SOAR Orchestrator (AI Triage)',
        timestamp: new Date().toLocaleTimeString(),
        message: responseMsgText,
        details: responseDetails || undefined,
        actionExecuted: mockAction
      };

      setConversations(prev => ({
        ...prev,
        [currentTab]: {
          ...prev[currentTab],
          messages: [...prev[currentTab].messages, orcMsg]
        }
      }));

    }, 1500);

  };

  const activeConv = conversations[activeTab];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0, height: 'calc(100vh - 120px)', animation: 'fadeInUp 0.25s ease-out' }}>
      
      {/* Header section */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>AEGIS / CENTRAL SOAR</span>
          <span style={{ fontSize: '0.65rem', background: 'rgba(34,197,94,0.15)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)', padding: '1px 4px', borderRadius: 2 }}>Orchestrator Engaged</span>
        </div>
        <h1 className="page-title" style={{ fontSize: '1.25rem', marginTop: 3, display: 'flex', alignItems: 'center', gap: 8 }}>
          <MessageSquare size={18} style={{ color: 'var(--accent)' }} /> Orchestrator Agent Dialogs
          <span style={{ fontSize: '0.8rem', color: 'var(--text-3)', fontWeight: 400 }}>· Real-time incident logs & commands</span>
        </h1>
      </div>

      <div style={{ height: 1, background: 'var(--border-1)', width: '100%' }} />

      {/* Main Split Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16, flex: 1, minHeight: 0 }}>
        
        {/* Left Side: 3 Agent nodes list */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: 12, gap: 10, overflowY: 'auto' }}>
          <h3 style={{ fontSize: '0.74rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 4 }}>
            Monitored Telemetry Nodes
          </h3>
          
          {Object.entries(conversations).map(([key, conv]) => {
            const isActive = activeTab === key;
            const lastMsg = conv.messages[conv.messages.length - 1];
            
            // Get threat tag color
            let threatColor = '#10b981';
            let threatBg = 'rgba(16,185,129,0.1)';
            if (conv.agentId === 'agent-01') {
              threatColor = 'var(--critical)';
              threatBg = 'rgba(239,68,68,0.1)';
            } else if (conv.agentId === 'agent-03') {
              threatColor = 'var(--warning)';
              threatBg = 'rgba(245,158,11,0.1)';
            }

            return (
              <div
                key={key}
                onClick={() => setActiveTab(key)}
                className={`hover-card ${isActive ? 'active-tab' : ''}`}
                style={{
                  padding: 10,
                  borderRadius: 'var(--r-md)',
                  cursor: 'pointer',
                  border: isActive ? '1px solid var(--accent)' : '1px solid var(--border-0)',
                  background: isActive ? 'rgba(255, 153, 0, 0.05)' : 'rgba(255,255,255,0.01)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                  transition: 'all 0.2s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ color: isActive ? 'var(--accent)' : 'var(--text-2)' }}>
                      {conv.agentIcon}
                    </div>
                    <strong style={{ fontSize: '0.78rem', color: 'var(--text-0)' }}>{conv.agentName}</strong>
                  </div>
                  <span style={{ 
                    fontSize: '0.58rem', 
                    color: threatColor, 
                    background: threatBg, 
                    padding: '1px 4px', 
                    borderRadius: 3, 
                    fontWeight: 600 
                  }}>
                    THREAT: {conv.agentId === 'agent-01' ? '85/100' : conv.agentId === 'agent-03' ? '50/100' : '15/100'}
                  </span>
                </div>
                
                <div style={{ fontSize: '0.66rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>
                  IP: {conv.agentIp}
                </div>

                <div style={{ 
                  fontSize: '0.7rem', 
                  color: 'var(--text-2)', 
                  whiteSpace: 'nowrap', 
                  overflow: 'hidden', 
                  textOverflow: 'ellipsis',
                  borderTop: '1px solid var(--border-0)',
                  paddingTop: 6,
                  marginTop: 2
                }}>
                  {lastMsg ? lastMsg.message : 'No alerts recorded'}
                </div>
              </div>
            );
          })}

          <div style={{ flex: 1 }} />
          
          {/* Orchestrator status footer */}
          <div style={{ borderTop: '1px solid var(--border-0)', paddingTop: 10, fontSize: '0.7rem', color: 'var(--text-3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span>Orchestrator Mode:</span>
              <strong style={{ color: 'var(--accent)' }}>AUTOPILOT (ON)</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>AI Engine Level:</span>
              <span style={{ color: 'var(--text-1)' }}>L2 Meta Triage</span>
            </div>
          </div>
        </div>

        {/* Right Side: Chat Timeline Feed */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          
          {/* Chat Header */}
          {activeConv && (
            <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border-0)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(0,0,0,0.1)' }}>
              <div>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-0)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  {activeConv.agentIcon} {activeConv.agentName} Telemetry Dialog
                </h3>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-3)' }}>
                  OS: {activeConv.agentOs} · Host IP: {activeConv.agentIp}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', userSelect: 'none' }}>
                  <input 
                    type="checkbox" 
                    checked={inspectJsonMode} 
                    onChange={(e) => setInspectJsonMode(e.target.checked)} 
                    style={{ accentColor: '#ff9900', cursor: 'pointer' }}
                  />
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-2)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Terminal size={12} style={{ color: 'var(--accent)' }} /> Inspect JSON Mode
                  </span>
                </label>
                <span className="badge badge-active" style={{ fontSize: '0.62rem', background: 'rgba(34,197,94,0.15)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.2)' }}>
                  Wazuh Agent Active
                </span>
              </div>
            </div>
          )}

          {/* Split Content Pane */}
          <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
            
            {/* Left Column: Timeline feed & Input */}
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1, borderRight: inspectJsonMode ? '1px solid var(--border-1)' : undefined, minWidth: 0 }}>
              
              {/* Messages Feed Area */}
              <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
                
                {activeConv?.messages.map((m) => {
                  const isOrchestrator = m.sender === 'orchestrator';
                  return (
                    <div 
                      key={m.id}
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: isOrchestrator ? 'flex-end' : 'flex-start',
                        maxWidth: '85%',
                        alignSelf: isOrchestrator ? 'flex-end' : 'flex-start'
                      }}
                    >
                      {/* Sender Name & Time */}
                      <div style={{ display: 'flex', gap: 6, fontSize: '0.65rem', color: 'var(--text-3)', marginBottom: 3, padding: '0 4px' }}>
                        <strong>{m.senderName}</strong>
                        <span>·</span>
                        <span>{m.timestamp}</span>
                      </div>

                      {/* Message Bubble */}
                      <div
                        style={{
                          background: isOrchestrator ? 'rgba(255, 153, 0, 0.08)' : 'rgba(255,255,255,0.03)',
                          border: isOrchestrator ? '1px solid rgba(255, 153, 0, 0.25)' : '1px solid var(--border-0)',
                          borderRadius: 'var(--r-md)',
                          padding: '10px 12px',
                          fontSize: '0.78rem',
                          color: 'var(--text-1)',
                          lineHeight: 1.4,
                          boxShadow: isOrchestrator ? '0 4px 12px rgba(255, 153, 0, 0.03)' : '0 4px 12px rgba(0,0,0,0.05)'
                        }}
                      >
                        <div>{m.message}</div>

                        {/* Action Executed Section (SOAR Actions) */}
                        {m.actionExecuted && (
                          <div 
                            style={{ 
                              marginTop: 8, 
                              padding: '6px 10px', 
                              background: 'rgba(0,0,0,0.2)', 
                              border: '1px solid var(--border-0)', 
                              borderRadius: 4, 
                              fontSize: '0.7rem',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: 4
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <Zap size={11} style={{ color: 'var(--accent)' }} />
                              <strong style={{ color: 'var(--text-0)' }}>SOAR AUTOMATION EXECUTED:</strong>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 2 }}>
                              <span style={{ color: 'var(--text-2)', fontFamily: "'IBM Plex Mono', monospace" }}>
                                {m.actionExecuted.type} ({m.actionExecuted.target})
                              </span>
                              <span style={{ 
                                color: m.actionExecuted.status === 'success' ? '#10b981' : 'var(--critical)', 
                                fontSize: '0.62rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3 
                              }}>
                                {m.actionExecuted.status === 'success' ? <CheckCircle size={10} /> : <XCircle size={10} />}
                                {m.actionExecuted.status.toUpperCase()}
                              </span>
                            </div>
                            <div style={{ color: 'var(--text-3)', fontSize: '0.68rem', marginTop: 2 }}>
                              {m.actionExecuted.message}
                            </div>
                          </div>
                        )}

                        {/* Expandable JSON details */}
                        {m.details && !inspectJsonMode && (
                          <div style={{ marginTop: 8 }}>
                            <button
                              type="button"
                              onClick={() => setExpandedDetailsId(expandedDetailsId === m.id ? null : m.id)}
                              style={{
                                background: 'rgba(255,255,255,0.04)',
                                border: '1px solid var(--border-0)',
                                color: 'var(--text-2)',
                                fontSize: '0.62rem',
                                padding: '2px 6px',
                                borderRadius: 3,
                                cursor: 'pointer',
                                display: 'flex',
                                alignItems: 'center',
                                gap: 4
                              }}
                            >
                              <Terminal size={10} />
                              {expandedDetailsId === m.id ? 'Hide payload details' : 'Show payload details (JSON)'}
                            </button>
                            
                            {expandedDetailsId === m.id && (
                              <pre 
                                style={{ 
                                  marginTop: 6, 
                                  background: '#090d16', 
                                  border: '1px solid rgba(255,255,255,0.05)', 
                                  padding: 8, 
                                  borderRadius: 4, 
                                  fontSize: '0.68rem', 
                                  fontFamily: "'IBM Plex Mono', monospace", 
                                  color: '#38bdf8',
                                  overflowX: 'auto',
                                  maxHeight: 180,
                                  lineHeight: 1.2
                                }}
                              >
                                {m.details}
                              </pre>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}

                {isTyping && (
                  <div style={{ alignSelf: 'flex-end', display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-3)', marginBottom: 3 }}>
                      L2 SOAR Orchestrator AI is typing...
                    </div>
                    <div style={{ background: 'rgba(255, 153, 0, 0.05)', border: '1px solid rgba(255, 153, 0, 0.15)', borderRadius: 'var(--r-md)', padding: '8px 12px', fontSize: '0.78rem' }}>
                      <span className="dot-blink" style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)', marginRight: 3 }} />
                      <span className="dot-blink" style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)', marginRight: 3, animationDelay: '0.2s' }} />
                      <span className="dot-blink" style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)', animationDelay: '0.4s' }} />
                    </div>
                  </div>
                )}

                <div ref={chatEndRef} />
              </div>

              {/* Chat Console Input Bar */}
              <form onSubmit={handleSendMessage} style={{ padding: 12, borderTop: '1px solid var(--border-0)', display: 'flex', gap: 8, background: 'rgba(0,0,0,0.15)' }}>
                <input
                  type="text"
                  value={userInput}
                  onChange={(e) => setUserInput(e.target.value)}
                  placeholder={`Ask Orchestrator AI or send shell command to ${activeConv?.agentName}...`}
                  style={{
                    flex: 1,
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-1)',
                    borderRadius: 'var(--r-xs)',
                    padding: '6px 12px',
                    fontSize: '0.8rem',
                    color: 'var(--text-1)'
                  }}
                />
                <button 
                  type="submit" 
                  className="btn btn-primary" 
                  style={{ 
                    background: '#ff9900', 
                    borderColor: '#ff9900', 
                    padding: '0 12px', 
                    height: 32, 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'center', 
                    gap: 6,
                    fontSize: '0.78rem' 
                  }}
                >
                  <Send size={12} /> Send
                </button>
              </form>

            </div>

            {/* Right Column: Live JSON Inspector Stream */}
            {inspectJsonMode && (
              <div 
                style={{ 
                  width: '42%', 
                  background: '#04070d', 
                  display: 'flex', 
                  flexDirection: 'column', 
                  overflowY: 'auto', 
                  padding: 14, 
                  fontFamily: "'IBM Plex Mono', monospace", 
                  borderBottomRightRadius: 'var(--r-md)',
                  gap: 16
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingBottom: 8, borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  <Terminal size={12} style={{ color: 'var(--accent)' }} />
                  <span style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-0)', letterSpacing: '0.04em' }}>
                    JSON TELEMETRY STREAM
                  </span>
                </div>

                {activeConv?.messages.filter(m => m.details || (m.actionExecuted && m.actionExecuted.payload)).length === 0 ? (
                  <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', color: 'var(--text-3)' }}>
                    No JSON payloads recorded in this session.
                  </div>
                ) : (
                  activeConv?.messages.map((m) => {
                    if (!m.details && (!m.actionExecuted || !m.actionExecuted.payload)) return null;
                    const isOrchestrator = m.sender === 'orchestrator';
                    return (
                      <div 
                        key={`stream-${m.id}`} 
                        style={{ 
                          fontSize: '0.66rem', 
                          background: 'rgba(255,255,255,0.01)', 
                          border: '1px solid rgba(255,255,255,0.04)', 
                          borderRadius: 4, 
                          padding: 10,
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 6
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px dashed rgba(255,255,255,0.05)', paddingBottom: 4 }}>
                          <span style={{ fontWeight: 600, color: isOrchestrator ? '#f59e0b' : '#38bdf8' }}>
                            {isOrchestrator ? '◀ ORCHESTRATOR RESPONSE' : '▶ AGENT INBOUND PUSH'}
                          </span>
                          <span style={{ color: 'var(--text-3)', fontSize: '0.58rem' }}>{m.timestamp}</span>
                        </div>

                        <div style={{ color: 'var(--text-2)', fontSize: '0.62rem', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 2 }}>
                          {isOrchestrator 
                            ? `AWS_ACTION: ${m.actionExecuted?.type || 'AI_TRIAGE_DECISION'}`
                            : `METHOD: POST /api/telemetry`
                          }
                        </div>

                        {m.details && (
                          <pre style={{ margin: 0, color: '#38bdf8', overflowX: 'auto', whiteSpace: 'pre', lineHeight: 1.25 }}>
                            {m.details}
                          </pre>
                        )}

                        {m.actionExecuted?.payload && (
                          <div style={{ marginTop: 4 }}>
                            <div style={{ fontSize: '0.58rem', color: 'var(--text-3)', marginBottom: 2 }}>Action Payload:</div>
                            <pre style={{ margin: 0, color: '#f59e0b', overflowX: 'auto', whiteSpace: 'pre', lineHeight: 1.25 }}>
                              {m.actionExecuted.payload}
                            </pre>
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            )}

          </div>
        </div>
      </div>
    </div>
  );
}
