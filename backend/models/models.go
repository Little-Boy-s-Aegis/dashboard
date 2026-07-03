package models

import "time"

type Agent struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	OS        string    `json:"os"`
	Status    string    `json:"status"` // active, disconnected, alerting
	LastSeen  time.Time `json:"lastSeen"`
	CPUUsage  float64   `json:"cpuUsage"`
	RAMUsage  float64   `json:"ramUsage"`
	DiskUsage float64   `json:"diskUsage"`
}

type Alert struct {
	ID             string    `json:"id"`
	RuleID         string    `json:"ruleId"`
	Severity       string    `json:"severity"` // low, medium, high, critical
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	AgentID        string    `json:"agentId"`
	AgentName      string    `json:"agentName"`
	MITRETechnique string    `json:"mitreTechnique"` // e.g. T1059 (Command and Scripting Interpreter)
	MITRETactics   []string  `json:"mitreTactics"`   // e.g. ["Execution", "Defense Evasion"]
	Category       string    `json:"category"`       // malware, auth, network, audit, fim
	Timestamp      time.Time `json:"timestamp"`
	RawLog         string    `json:"rawLog"`
	Status         string    `json:"status"` // open, investigating, resolved
}

type FIMEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	AgentID   string    `json:"agentId"`
	AgentName string    `json:"agentName"`
	FilePath  string    `json:"filePath"`
	EventType string    `json:"eventType"` // create, modify, delete
	Size      int64     `json:"size"`
	MD5       string    `json:"md5"`
	SHA256    string    `json:"sha256"`
	User      string    `json:"user"`
	Process   string    `json:"process"`
}

type LogEntry struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	AgentID    string    `json:"agentId"`
	AgentName  string    `json:"agentName"`
	Facility   string    `json:"facility"` // auth, syslog, daemon, web
	Severity   string    `json:"severity"` // info, warning, error, alert
	Message    string    `json:"message"`
	SourceIP   string    `json:"sourceIp,omitempty"`
	StatusCode int       `json:"statusCode,omitempty"`
}

type AIAnalysis struct {
	AlertID        string   `json:"alertId"`
	Summary        string   `json:"summary"`
	ThreatActor    string   `json:"threatActor"`
	Confidence     int      `json:"confidence"` // percentage 0-100
	ImpactRating   string   `json:"impactRating"` // Low, Medium, High, Critical
	TechnicalDetail string   `json:"technicalDetail"`
	RemediationSteps []string `json:"remediationSteps"`
}

type DashboardSummary struct {
	ActiveAgents    int            `json:"activeAgents"`
	AlertingAgents  int            `json:"alertingAgents"`
	TotalAgents     int            `json:"totalAgents"`
	AlertCount24h   int            `json:"alertCount24h"`
	CriticalAlerts  int            `json:"criticalAlerts"`
	HighAlerts      int            `json:"highAlerts"`
	MediumAlerts    int            `json:"mediumAlerts"`
	LowAlerts       int            `json:"lowAlerts"`
	ThreatLevel     string         `json:"threatLevel"` // Elevated, Severe, Normal
	AlertsByCategory map[string]int `json:"alertsByCategory"`
	MitreCoverage    map[string]int `json:"mitreCoverage"`
}
