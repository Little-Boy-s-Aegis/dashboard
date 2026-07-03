export interface Agent {
  id: string;
  name: string;
  ip: string;
  os: string;
  status: 'active' | 'disconnected' | 'alerting';
  lastSeen: string;
  cpuUsage: number;
  ramUsage: number;
  diskUsage: number;
}

export interface Alert {
  id: string;
  ruleId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  agentId: string;
  agentName: string;
  mitreTechnique: string;
  mitreTactics: string[];
  category: string;
  timestamp: string;
  rawLog: string;
  status: 'open' | 'investigating' | 'resolved';
}

export interface FIMEvent {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  filePath: string;
  eventType: 'create' | 'modify' | 'delete';
  size: number;
  md5: string;
  sha256: string;
  user: string;
  process: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  facility: 'auth' | 'syslog' | 'daemon' | 'web';
  severity: 'info' | 'warning' | 'error' | 'alert';
  message: string;
  sourceIp?: string;
  statusCode?: number;
}

export interface AIAnalysis {
  alertId: string;
  summary: string;
  threatActor: string;
  confidence: number;
  impactRating: string;
  technicalDetail: string;
  remediationSteps: string[];
}

export interface DashboardSummary {
  activeAgents: number;
  alertingAgents: number;
  totalAgents: number;
  alertCount24h: number;
  criticalAlerts: number;
  highAlerts: number;
  mediumAlerts: number;
  lowAlerts: number;
  threatLevel: 'Normal' | 'Elevated' | 'Severe';
  alertsByCategory: Record<string, number>;
  mitreCoverage: Record<string, number>;
}
