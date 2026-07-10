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
	NetworkIn   float64   `json:"networkIn"`
	NetworkOut  float64   `json:"networkOut"`
	ThreatScore int       `json:"threatScore"`
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
	Assignee       string    `json:"assignee"` // assignee analyst name
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
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	AgentID        string    `json:"agentId"`
	AgentName      string    `json:"agentName"`
	Facility       string    `json:"facility"` // auth, syslog, daemon, web
	Severity       string    `json:"severity"` // info, warning, error, alert
	Message        string    `json:"message"`
	SourceIP       string    `json:"sourceIp,omitempty"`
	StatusCode     int       `json:"statusCode,omitempty"`
	GeoIP          string    `json:"geoIp,omitempty"`
	ASN            string    `json:"asn,omitempty"`
	AssetCritical  string    `json:"assetCritical,omitempty"`
	ThreatFlagged  bool      `json:"threatFlagged,omitempty"`
	ThreatType     string    `json:"threatType,omitempty"`
	DecodedPayload string    `json:"decodedPayload,omitempty"`

	// ECS (Elastic Common Schema) Standard Fields
	ECSTimestamp   string    `json:"@timestamp"`
	ECSLogLevel    string    `json:"log.level"`
	ECSEventDataset string   `json:"event.dataset"`
	ECSEventID     string    `json:"event.id"`
	ECSSourceIP    string    `json:"source.ip"`
	ECSHTTPStatus  int       `json:"http.response.status_code,omitempty"`
	ECSGeoCountry  string    `json:"source.geo.country_name,omitempty"`
	ECSASNName     string    `json:"source.as.organization.name,omitempty"`
	ECSServiceName string    `json:"service.name"`
	ECSURLOriginal string    `json:"url.original,omitempty"`
	ECSAgentID     string    `json:"agent.id"`
	ECSAgentName   string    `json:"agent.name"`
	ECSAgentType   string    `json:"agent.type"`
	ECSEventCat    []string  `json:"event.category,omitempty"`
	ECSEventKind   string    `json:"event.kind"`
	ECSEventOutcome string   `json:"event.outcome"`
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

type ActionLog struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`      // "AI" or "SOC (username)"
	ActionType string    `json:"actionType"` // "Isolate Host", "Block IP", "Terminate Process", "Revoke Credentials"
	Target     string    `json:"target"`     // e.g. "Web-Prod-01", "IP 198.51.100.222"
	Status     string    `json:"status"`     // "success", "failed", "pending"
	Message    string    `json:"message"`    // Details of the action result
}

type AuthRequest struct {
	UID string `json:"uid"`
}

type AuthResponse struct {
	UID      string    `json:"uid"`
	Username string    `json:"username"`
	Token    string    `json:"token"`
	Expiry   time.Time `json:"expiry"`
}

type LoginRequest struct {
	UID   string `json:"uid"`
	Token string `json:"token"`
}

type LoginResponse struct {
	UID          string    `json:"uid"`
	Username     string    `json:"username"`
	SessionToken string    `json:"sessionToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type AuthStatus struct {
	IsAuthenticated bool      `json:"isAuthenticated"`
	Username        string    `json:"username"`
	UID             string    `json:"uid,omitempty"`
	ExpiresAt       time.Time `json:"expiresAt,omitempty"`
}

type BannedIP struct {
	IPAddress string    `json:"ipAddress"`
	BannedAt  time.Time `json:"bannedAt"`
	BannedBy  string    `json:"bannedBy"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason"`
}

