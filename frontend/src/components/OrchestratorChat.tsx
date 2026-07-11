import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal, Zap, Send, CheckCircle, XCircle, Server, Database, Key, MessageSquare, Monitor
} from 'lucide-react';
import type { Agent, Alert, ActionLog } from '../types';

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
  const [activeTab, setActiveTab] = useState<string>(() => agents[0]?.id || 'agent-01');
  const [userInput, setUserInput] = useState<string>('');
  const [isTyping, setIsTyping] = useState<boolean>(false);
  const [expandedDetailsId, setExpandedDetailsId] = useState<string | null>(null);
  const [inspectJsonMode, setInspectJsonMode] = useState<boolean>(true);
  
  const [realAlerts, setRealAlerts] = useState<Alert[]>([]);
  const [realActions, setRealActions] = useState<ActionLog[]>([]);
  const [customMessages, setCustomMessages] = useState<Record<string, ChatMessage[]>>({});

  const chatEndRef = useRef<HTMLDivElement>(null);
  const jsonStreamRef = useRef<HTMLDivElement>(null);
  const chatScrollContainerRef = useRef<HTMLDivElement>(null);
  const isScrollingChat = useRef(false);
  const isScrollingJson = useRef(false);

  // Fetch real-time security events & SOAR actions from the backend APIs
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsRes, actionsRes] = await Promise.all([
          fetch('/api/alerts'),
          fetch('/api/actions')
        ]);
        if (alertsRes.ok) {
          const alertsData = await alertsRes.json();
          setRealAlerts(alertsData || []);
        }
        if (actionsRes.ok) {
          const actionsData = await actionsRes.json();
          setRealActions(actionsData || []);
        }
      } catch (e) {
        console.error('OrchestratorChat backend fetch failed:', e);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  // Compute conversations dynamically by merging baseline histories and live database events
  const conversations = React.useMemo(() => {
    const record: Record<string, Conversation> = {};

    agents.forEach((agent) => {
      // Determine node icon based on host role / name
      let icon = <Monitor size={16} />;
      const nameLower = agent.name.toLowerCase();
      if (nameLower.includes('web')) {
        icon = <Server size={16} />;
      } else if (nameLower.includes('db') || nameLower.includes('replica')) {
        icon = <Database size={16} />;
      } else if (nameLower.includes('ad') || nameLower.includes('auth') || nameLower.includes('controller') || nameLower.includes('gateway')) {
        icon = <Key size={16} />;
      }

      // 1. Build customized baseline conversation logs using correct Agent IP and OS
      const baselineMessages: ChatMessage[] = [];
      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 3600 * 1000);
      const twoDaysAgo = new Date(Date.now() - 2 * 24 * 3600 * 1000);

      if (nameLower.includes('web')) {
        baselineMessages.push(
          {
            id: `${agent.id}-base-1`,
            sender: 'agent',
            senderName: agent.name,
            timestamp: new Date(threeDaysAgo.getTime() + 15 * 60000).toISOString(),
            message: 'SECURITY ALERT: Nginx detected high frequency of SQL injection payloads hitting API endpoint /v1/auth/login.',
            details: JSON.stringify({
              log_source: "nginx-access-logger",
              event_type: "signature_match",
              signature_name: "OWASP_TOP_10_SQL_INJECTION",
              http_request: {
                method: "POST",
                path: "/v1/auth/login",
                user_agent: "Mozilla/5.0 (Hydra-Scanner/v9.2)",
                client_ip: agent.ip || "192.168.10.11",
                payload: "admin' OR '1'='1'--",
                payload_hex: "61646d696e27204f52202731273d2731272d2d"
              },
              alert_count_1m: 145,
              severity_score: 8.5
            }, null, 2)
          },
          {
            id: `${agent.id}-base-2`,
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: new Date(threeDaysAgo.getTime() + 16 * 60000).toISOString(),
            message: `AI Assessment: Threat verified. Attacker IP is conducting active exploitation scanner against ${agent.name}. Autopilot rule triggered: Containment Active.`,
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.99,
                triage_summary: `Confirmed malicious SQL injection scanner targeting ${agent.name}.`,
                incident_risk_level: "High",
                recommended_action: "Immediate Ingress Block at WAF / Edge Router"
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
          }
        );
      } else if (nameLower.includes('db') || nameLower.includes('replica')) {
        baselineMessages.push(
          {
            id: `${agent.id}-base-1`,
            sender: 'agent',
            senderName: agent.name,
            timestamp: new Date(twoDaysAgo.getTime() + 17 * 60000).toISOString(),
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
              }
            }, null, 2)
          },
          {
            id: `${agent.id}-base-2`,
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: new Date(twoDaysAgo.getTime() + 18 * 60000).toISOString(),
            message: `AI Assessment: Severity High. Modification to database host files allows broad network access to secure database on ${agent.name}. Autopilot rule triggered: Revert Configuration and Isolate Host.`,
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.94,
                triage_summary: "pg_hba.conf connection access expanded. Potential database hijack attempt."
              }
            }, null, 2),
            actionExecuted: {
              type: "AWS Security Group quarantine",
              target: agent.ip,
              status: "success",
              message: `Successfully attached isolation security group sg-0dbdb0998 to EC2 Instance. Denied access except for SOC.`,
              payload: JSON.stringify({
                target_instance_id: "i-099abccde121ff89f",
                action: "ReplaceSecurityGroups",
                old_groups: ["sg-default-db"],
                new_groups: ["sg-aegis-quarantine-soc"]
              }, null, 2)
            }
          },
          {
            id: `${agent.id}-base-3`,
            sender: 'agent',
            senderName: agent.name,
            timestamp: new Date(twoDaysAgo.getTime() + 19 * 60000).toISOString(),
            message: 'INTEGRITY SYNC: Reverted /etc/postgresql/15/main/pg_hba.conf to default config from configuration master. Postgres restarted successfully.',
            details: JSON.stringify({
              reversion_status: "Successful",
              md5_current: "f9b88ef25b88cdeee21115"
            }, null, 2)
          }
        );
      } else {
        baselineMessages.push(
          {
            id: `${agent.id}-base-1`,
            sender: 'agent',
            senderName: agent.name,
            timestamp: new Date(twoDaysAgo.getTime() + 20 * 60000).toISOString(),
            message: 'SECURITY ALERT: Multiple SSH login failures detected on root account from external address 104.28.163.100.',
            details: JSON.stringify({
              log_source: "pam_secure_logger",
              event_type: "auth_failure",
              user_targeted: "root",
              attempts_count_5s: 38,
              client_ip: "104.28.163.100"
            }, null, 2)
          },
          {
            id: `${agent.id}-base-2`,
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: new Date(twoDaysAgo.getTime() + 21 * 60000).toISOString(),
            message: `AI Assessment: Severity Medium. Active brute-force attack targeting gateway ssh services on ${agent.name}. Autopilot containment initiated: Add IP to SOAR Blocklist.`,
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.88
              }
            }, null, 2),
            actionExecuted: {
              type: "Host iptables IP ban",
              target: "104.28.163.100",
              status: "success",
              message: "Successfully synchronized local iptables blocklist. Added drop rule for 104.28.163.100."
            }
          }
        );
      }

      // 2. Fetch and format live alerts from PostgreSQL matching this specific agent (forgiving regex-like search)
      const agentNameLower = agent.name.toLowerCase();
      const matchedAlerts = realAlerts.filter(a => {
        const aAgentName = a.agentName ? a.agentName.toLowerCase() : '';
        const aAgentId = a.agentId ? a.agentId.toLowerCase() : '';
        const aDescription = a.description ? a.description.toLowerCase() : '';
        const aRawLog = a.rawLog ? a.rawLog.toLowerCase() : '';

        return (
          aAgentId === agent.id.toLowerCase() ||
          aAgentName === agentNameLower ||
          (aAgentName && aAgentName.includes(agentNameLower)) ||
          (aAgentName && agentNameLower.includes(aAgentName)) ||
          aDescription.includes(agentNameLower) ||
          aRawLog.includes(agentNameLower) ||
          (agent.ip && aRawLog.includes(agent.ip.toLowerCase()))
        );
      });

      const realMsgList: ChatMessage[] = [];
      matchedAlerts.forEach((alert) => {
        const alertTime = new Date(alert.timestamp).toISOString();
        const alertMsgId = `real-alert-${alert.id}`;

        realMsgList.push({
          id: alertMsgId,
          sender: 'agent',
          senderName: alert.agentName || agent.name,
          timestamp: alertTime,
          message: `SECURITY ALERT: ${alert.title}. ${alert.description}`,
          details: JSON.stringify({
            alert_id: alert.id,
            rule_id: alert.ruleId,
            severity: alert.severity,
            mitre_technique: alert.mitreTechnique,
            mitre_tactics: alert.mitreTactics,
            raw_log: alert.rawLog
          }, null, 2)
        });

        // 3. Find matching live SOAR response action executed by the orchestrator (forgiving search)
        const matchedAction = realActions.find(act => {
          const actTarget = act.target ? act.target.toLowerCase() : '';
          const aRawLog = alert.rawLog ? alert.rawLog.toLowerCase() : '';
          return (
            act.target === alert.agentId || 
            act.target === agent.ip || 
            actTarget.includes(agentNameLower) ||
            agentNameLower.includes(actTarget) ||
            aRawLog.includes(actTarget)
          );
        });

        if (matchedAction) {
          realMsgList.push({
            id: `real-action-${matchedAction.id}`,
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: new Date(matchedAction.timestamp).toISOString(),
            message: `AI Assessment: Threat detected on ${agent.name}. Severity ${alert.severity.toUpperCase()}. Autopilot rule triggered: ${matchedAction.actionType}.`,
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.96,
                incident_risk_level: alert.severity === 'critical' || alert.severity === 'high' ? 'High' : 'Medium',
                action: matchedAction.actionType
              }
            }, null, 2),
            actionExecuted: {
              type: matchedAction.actionType,
              target: matchedAction.target,
              status: matchedAction.status,
              message: matchedAction.message,
              payload: JSON.stringify({
                action_id: matchedAction.id,
                actor: matchedAction.actor,
                target: matchedAction.target,
                status: matchedAction.status,
                message: matchedAction.message
              }, null, 2)
            }
          });
        } else {
          realMsgList.push({
            id: `real-ai-${alert.id}`,
            sender: 'orchestrator',
            senderName: 'L2 SOAR Orchestrator (AI Triage)',
            timestamp: alertTime,
            message: `AI Assessment: Incident registered on ${agent.name}. Threat level is ${alert.severity.toUpperCase()}. Monitoring host parameters for anomalies.`,
            details: JSON.stringify({
              ai_triage: {
                model: "Aegis-L2-Triage-Sonnet",
                confidence_score: 0.85,
                incident_status: "monitoring"
              }
            }, null, 2)
          });
        }
      });

      // Combine all messages and sort them chronologically by timestamp
      const allMessages = [...baselineMessages, ...realMsgList, ...(customMessages[agent.id] || [])];
      allMessages.sort((a, b) => {
        const timeA = new Date(a.timestamp).getTime();
        const timeB = new Date(b.timestamp).getTime();
        if (isNaN(timeA) || isNaN(timeB)) return 0;
        return timeA - timeB;
      });

      record[agent.id] = {
        agentId: agent.id,
        agentName: agent.name,
        agentIp: agent.ip,
        agentOs: agent.os,
        agentIcon: icon,
        messages: allMessages
      };
    });

    return record;
  }, [agents, realAlerts, realActions, customMessages]);

  // Keep selected tab updated when agents load
  useEffect(() => {
    if (agents.length > 0 && !conversations[activeTab]) {
      setActiveTab(agents[0].id);
    }
  }, [agents, conversations, activeTab]);

  // Ref to track last active tab and message count to prevent scrolling during active reading
  const prevTabRef = useRef(activeTab);
  const prevMsgCountRef = useRef(0);

  // Helper to check if chat is near the bottom
  const isNearBottom = () => {
    if (!chatScrollContainerRef.current) return true;
    const el = chatScrollContainerRef.current;
    return el.scrollHeight - el.clientHeight - el.scrollTop < 180;
  };

  // Scroll to bottom of chat and json stream when messages change, but respect user scrolling
  useEffect(() => {
    const chatEl = chatScrollContainerRef.current;
    const jsonEl = jsonStreamRef.current;
    const msgCount = activeConv?.messages.length || 0;

    const tabChanged = prevTabRef.current !== activeTab;
    const newMsgAdded = msgCount > prevMsgCountRef.current;
    
    // Auto scroll if tab changed, or user is already near the bottom
    const shouldScroll = tabChanged || (newMsgAdded && isNearBottom());

    if (shouldScroll) {
      if (chatEl) {
        chatEl.scrollTop = chatEl.scrollHeight;
      }
      if (jsonEl) {
        jsonEl.scrollTop = jsonEl.scrollHeight;
      }
    }

    prevTabRef.current = activeTab;
    prevMsgCountRef.current = msgCount;
  }, [conversations, activeTab, isTyping]);

  const handleChatScroll = () => {
    if (isScrollingJson.current) return;
    if (chatScrollContainerRef.current && jsonStreamRef.current) {
      isScrollingChat.current = true;
      const chatEl = chatScrollContainerRef.current;
      const jsonEl = jsonStreamRef.current;

      const chatChildren = Array.from(chatEl.children);
      const scrollTop = chatEl.scrollTop;
      let activeId = null;
      let offsetDiff = 0;

      for (let i = 0; i < chatChildren.length; i++) {
        const child = chatChildren[i] as HTMLElement;
        if (child.id && child.id.startsWith('msg-left-')) {
          const childTop = child.offsetTop;
          if (childTop + child.clientHeight >= scrollTop) {
            activeId = child.id.replace('msg-left-', '');
            offsetDiff = scrollTop - childTop;
            break;
          }
        }
      }

      if (activeId) {
        const rightEl = document.getElementById(`msg-right-${activeId}`);
        if (rightEl) {
          jsonEl.scrollTop = rightEl.offsetTop + offsetDiff;
        }
      }

      setTimeout(() => {
        isScrollingChat.current = false;
      }, 50);
    }
  };

  const handleJsonScroll = () => {
    if (isScrollingChat.current) return;
    if (chatScrollContainerRef.current && jsonStreamRef.current) {
      isScrollingJson.current = true;
      const chatEl = chatScrollContainerRef.current;
      const jsonEl = jsonStreamRef.current;

      const jsonChildren = Array.from(jsonEl.children);
      const scrollTop = jsonEl.scrollTop;
      let activeId = null;
      let offsetDiff = 0;

      for (let i = 0; i < jsonChildren.length; i++) {
        const child = jsonChildren[i] as HTMLElement;
        if (child.id && child.id.startsWith('msg-right-')) {
          const childTop = child.offsetTop;
          if (childTop + child.clientHeight >= scrollTop) {
            activeId = child.id.replace('msg-right-', '');
            offsetDiff = scrollTop - childTop;
            break;
          }
        }
      }

      if (activeId) {
        const leftEl = document.getElementById(`msg-left-${activeId}`);
        if (leftEl) {
          chatEl.scrollTop = leftEl.offsetTop + offsetDiff;
        }
      }

      setTimeout(() => {
        isScrollingJson.current = false;
      }, 50);
    }
  };

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userInput.trim()) return;

    const currentTab = activeTab;
    const userMessageText = userInput;
    setUserInput('');

    // Append User Message to active agent's customMessages state
    const userMsg: ChatMessage = {
      id: `usr-m-${Date.now()}`,
      sender: 'agent',
      senderName: 'SOC Analyst Console',
      timestamp: new Date().toISOString(),
      message: userMessageText
    };

    setCustomMessages(prev => ({
      ...prev,
      [currentTab]: [...(prev[currentTab] || []), userMsg]
    }));

    // Trigger AI Orchestrator Response Simulation after a short delay
    setIsTyping(true);

    setTimeout(() => {
      setIsTyping(false);
      let responseMsgText = '';
      let responseDetails = '';
      let mockAction: ChatMessage['actionExecuted'] = undefined;

      const lowerInput = userMessageText.toLowerCase();
      const currentAgent = agents.find(a => a.id === currentTab) || { name: 'Agent', ip: '127.0.0.1' };

      if (lowerInput.includes('status') || lowerInput.includes('check')) {
        responseMsgText = `Orchestrator AI Response: ${currentAgent.name} status query parsed. Core parameters checked. Threat level normal. CPU and latency values are within threshold.`;
        responseDetails = JSON.stringify({
          check_timestamp: new Date().toISOString(),
          status: "OK",
          agent_ip: currentAgent.ip
        }, null, 2);
      } else if (lowerInput.includes('quarantine') || lowerInput.includes('isolate')) {
        responseMsgText = `Orchestrator AI Action: Isolation authorized. Instigating quarantine rules for target ${currentAgent.name} (${currentAgent.ip}).`;
        mockAction = {
          type: "AWS Security Group Quarantine",
          target: currentAgent.ip,
          status: "success",
          message: `Attached sg-aegis-quarantine-soc to ${currentAgent.name}. Disallowed normal ports ingress.`,
          payload: JSON.stringify({
            action: "Quarantine",
            target_ip: currentAgent.ip,
            target_name: currentAgent.name
          }, null, 2)
        };
      } else {
        responseMsgText = `Orchestrator AI Response: Message received for ${currentAgent.name}. Analysis complete. SOC prompt processed.`;
        responseDetails = JSON.stringify({
          received_message: userMessageText,
          processed_at: new Date().toISOString()
        }, null, 2);
      }

      const orcMsg: ChatMessage = {
        id: `orc-m-${Date.now()}`,
        sender: 'orchestrator',
        senderName: 'L2 SOAR Orchestrator (AI Triage)',
        timestamp: new Date().toISOString(),
        message: responseMsgText,
        details: responseDetails || undefined,
        actionExecuted: mockAction
      };

      setCustomMessages(prev => ({
        ...prev,
        [currentTab]: [...(prev[currentTab] || []), orcMsg]
      }));

    }, 1500);

  };

  const activeConv = conversations[activeTab];

  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column', 
      gap: 14, 
      minWidth: 0, 
      height: 'calc(100vh - 120px)', 
      maxHeight: 'calc(100vh - 120px)', 
      overflow: 'hidden', 
      animation: 'fadeInUp 0.25s ease-out' 
    }}>
      
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
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16, flex: 1, minHeight: 0, height: '100%', overflow: 'hidden' }}>
        
        {/* Left Side: 3 Agent nodes list */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: 12, gap: 10, overflowY: 'auto', minHeight: 0, height: '100%' }}>
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

        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, height: '100%', overflow: 'hidden' }}>
          
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
          <div style={{ display: 'flex', flex: 1, minHeight: 0, overflow: 'hidden', height: '100%' }}>
            
            {/* Left Column: Timeline feed & Input */}
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1, borderRight: inspectJsonMode ? '1px solid var(--border-1)' : undefined, minWidth: 0, height: '100%', minHeight: 0, overflow: 'hidden' }}>
              
              {/* Messages Feed Area */}
              <div ref={chatScrollContainerRef} onScroll={handleChatScroll} style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 14, position: 'relative' }}>
                
                {activeConv?.messages.map((m) => {
                  const isOrchestrator = m.sender === 'orchestrator';
                  return (
                    <div 
                      id={`msg-left-${m.id}`}
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
                        <span>
                          {(() => {
                            const d = new Date(m.timestamp);
                            if (isNaN(d.getTime())) return m.timestamp;
                            return d.toLocaleString('en-US', {
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: '2-digit',
                              hour12: false
                            });
                          })()}
                        </span>
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
                ref={jsonStreamRef}
                onScroll={handleJsonScroll}
                style={{ 
                  width: '42%', 
                  background: '#04070d', 
                  display: 'flex', 
                  flexDirection: 'column', 
                  overflowY: 'auto', 
                  padding: 14, 
                  fontFamily: "'IBM Plex Mono', monospace", 
                  borderBottomRightRadius: 'var(--r-md)',
                  gap: 16,
                  height: '100%',
                  minHeight: 0,
                  position: 'relative'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingBottom: 8, borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  <Terminal size={12} style={{ color: 'var(--accent)' }} />
                  <span style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-0)', letterSpacing: '0.04em' }}>
                    JSON TELEMETRY STREAM
                  </span>
                </div>

                {!activeConv || activeConv.messages.length === 0 ? (
                  <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', color: 'var(--text-3)' }}>
                    No JSON payloads recorded in this session.
                  </div>
                ) : (
                  activeConv.messages.map((m) => {
                    const hasJson = m.details || (m.actionExecuted && m.actionExecuted.payload);
                    const isOrchestrator = m.sender === 'orchestrator';

                    if (!hasJson) {
                      return (
                        <div 
                          id={`msg-right-${m.id}`}
                          key={`stream-placeholder-${m.id}`} 
                          style={{ 
                            fontSize: '0.62rem', 
                            color: 'rgba(255,255,255,0.22)', 
                            background: 'rgba(255,255,255,0.01)', 
                            border: '1px dashed rgba(255,255,255,0.02)', 
                            borderRadius: 4, 
                            padding: '6px 10px',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center'
                          }}
                        >
                          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            <span>💬</span>
                            <span>Dialog: {isOrchestrator ? 'Orchestrator' : 'Agent'}</span>
                          </span>
                          <span style={{ fontSize: '0.55rem', color: 'var(--text-3)' }}>
                            No JSON Telemetry
                          </span>
                        </div>
                      );
                    }

                    return (
                      <div 
                        id={`msg-right-${m.id}`}
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
                          <span style={{ color: 'var(--text-3)', fontSize: '0.58rem' }}>
                            {(() => {
                              const d = new Date(m.timestamp);
                              if (isNaN(d.getTime())) return m.timestamp;
                              return d.toLocaleString('en-US', {
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                hour12: false
                              });
                            })()}
                          </span>
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
