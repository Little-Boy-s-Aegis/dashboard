package store

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"dashboard/backend/models"
)

type Database struct {
	Mu            sync.RWMutex
	Agents        map[string]*models.Agent
	Alerts        []*models.Alert
	FIMEvents     []*models.FIMEvent
	Logs          []*models.LogEntry
	AIAnalyses    map[string]*models.AIAnalysis
	BannedIPs     map[string]*models.BannedIP
	ActionLogs    []*models.ActionLog
	AlertCounter  int
	FimCounter    int
	LogCounter    int
	ActionCounter int
}

var DB *Database
var (
	securityAlertHookMu sync.RWMutex
	securityAlertHook   func(*models.Alert)
)

func RegisterSecurityAlertHook(hook func(*models.Alert)) {
	securityAlertHookMu.Lock()
	defer securityAlertHookMu.Unlock()
	securityAlertHook = hook
}

func NotifySecurityAlert(alert *models.Alert) {
	if alert == nil {
		return
	}

	securityAlertHookMu.RLock()
	hook := securityAlertHook
	securityAlertHookMu.RUnlock()
	if hook == nil {
		return
	}

	alertCopy := *alert
	hook(&alertCopy)
}

func SecurityAlertSeverity(attackType string, status string, payload string, description string) string {
	statusUpper := strings.ToUpper(strings.TrimSpace(status))
	isSQLi := IsSQLInjectionText(attackType, payload, description)

	if statusUpper == "ALLOWED" {
		if isSQLi {
			return "high"
		}
		return "critical"
	}

	attackTypeUpper := strings.ToUpper(strings.TrimSpace(attackType))
	if attackTypeUpper == "BRUTE_FORCE" || attackTypeUpper == "PARAMETER_TAMPERING" || attackTypeUpper == "XSS" || attackTypeUpper == "JSON_ESCAPING" {
		return "low"
	}

	if isSQLi {
		return "medium"
	}
	return "high"
}

func IsSQLInjectionText(parts ...string) bool {
	for _, part := range parts {
		normalized := strings.ToUpper(part)
		if strings.Contains(normalized, "SQL_INJECTION") ||
			strings.Contains(normalized, "SQL INJECTION") ||
			strings.Contains(normalized, "SQLI") {
			return true
		}
	}
	return false
}

func IsPersistentSecurityActionType(actionType string) bool {
	switch strings.TrimSpace(actionType) {
	case "Block IP", "Unblock IP", "Unblock All IPs", "Isolate Host", "Terminate Process", "Revoke Credentials", "Force Logout", "Resolve Alert", "Assign Alert", "Bulk Resolve", "Bulk Assign":
		return true
	default:
		return false
	}
}

func ShouldPersistSecurityLog(entry *models.LogEntry) bool {
	if entry == nil {
		return false
	}
	if entry.ThreatFlagged || entry.Facility == "soc_audit" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(entry.Severity)) {
	case "critical", "high", "medium", "low", "alert", "error":
		return true
	default:
		return false
	}
}

func init() {
	DB = &Database{
		Agents:     make(map[string]*models.Agent),
		Alerts:     make([]*models.Alert, 0),
		FIMEvents:  make([]*models.FIMEvent, 0),
		Logs:       make([]*models.LogEntry, 0),
		AIAnalyses: make(map[string]*models.AIAnalysis),
		BannedIPs:  make(map[string]*models.BannedIP),
		ActionLogs: make([]*models.ActionLog, 0),
	}

	// Seed default agents for inventory tracking
	DB.dbDefaultAgents()
	DB.seedFIMEvents()

	if os.Getenv("AEGIS_SIMULATION_ENABLED") == "true" {
		log.Printf("[SIMULATOR] Simulation mode enabled. Seeding mock history & starting background simulator...")
		DB.seedHistory()
		go DB.startSimulator()
	} else {
		log.Printf("[SIMULATOR] Simulation mode disabled. Running in 100%% dynamic mode.")
		go DB.startSyncLoop()
	}
}

func populateECSFields(entry *models.LogEntry) {
	if entry == nil {
		return
	}
	entry.ECSTimestamp = entry.Timestamp.Format(time.RFC3339Nano)
	entry.ECSLogLevel = entry.Severity
	entry.ECSEventDataset = fmt.Sprintf("%s.logs", entry.Facility)
	entry.ECSEventID = entry.ID
	entry.ECSSourceIP = entry.SourceIP
	entry.ECSHTTPStatus = entry.StatusCode
	entry.ECSServiceName = entry.AgentName
	entry.ECSURLOriginal = entry.DecodedPayload
	entry.ECSAgentID = entry.AgentID
	entry.ECSAgentName = entry.AgentName
	entry.ECSAgentType = "fluent-bit"

	if entry.Facility == "web" || entry.Facility == "apigw" || entry.Facility == "waf" {
		entry.ECSEventCat = []string{"web"}
	} else {
		entry.ECSEventCat = []string{"process"}
	}
	entry.ECSEventKind = "event"
	if entry.StatusCode >= 400 || entry.Severity == "alert" || entry.Severity == "error" || entry.Severity == "critical" || entry.Severity == "warning" {
		entry.ECSEventOutcome = "failure"
	} else {
		entry.ECSEventOutcome = "success"
	}
}

func (db *Database) AddLog(entry *models.LogEntry) {
	populateECSFields(entry)
	db.Logs = append(db.Logs, entry)
	if UsePostgres && ShouldPersistSecurityLog(entry) {
		go func(e *models.LogEntry) {
			_ = SaveSQLLogEntry(e)
		}(entry)
	}
}

func (db *Database) AddAlert(alert *models.Alert) {
	db.Alerts = append(db.Alerts, alert)
	if len(db.Alerts) > 100 {
		db.Alerts = db.Alerts[len(db.Alerts)-100:]
	}
	if UsePostgres {
		go func(a *models.Alert) {
			_ = SaveSQLAlert(a)
		}(alert)
	}
}

func (db *Database) AddFIMEvent(fim *models.FIMEvent) {
	db.FIMEvents = append(db.FIMEvents, fim)
	if UsePostgres {
		go func(f *models.FIMEvent) {
			_ = SaveSQLFIMEvent(f)
		}(fim)
	}
}

func (db *Database) SaveAgent(agent *models.Agent) {
	if UsePostgres {
		_ = SaveSQLAgent(agent)
	}
}

func (db *Database) SaveAlert(alert *models.Alert) {
	if UsePostgres {
		_ = SaveSQLAlert(alert)
	}
}

func (db *Database) dbDefaultAgents() {
	db.Mu.Lock()
	defer db.Mu.Unlock()

	// Seed 5 agents
	agentsData := []models.Agent{
		{ID: "agent-01", Name: "Web-Prod-01", IP: "192.168.10.11", OS: "Ubuntu 22.04 LTS", Status: "active", CPUUsage: 24.5, RAMUsage: 62.1, DiskUsage: 78.2, NetworkIn: 8.5, NetworkOut: 4.2},
		{ID: "agent-02", Name: "DB-Replica-01", IP: "192.168.10.12", OS: "RedHat Enterprise Linux 9", Status: "active", CPUUsage: 12.8, RAMUsage: 45.4, DiskUsage: 55.1, NetworkIn: 15.1, NetworkOut: 8.4},
		{ID: "agent-03", Name: "AD-Controller-01", IP: "192.168.10.20", OS: "Windows Server 2022", Status: "active", CPUUsage: 8.4, RAMUsage: 35.8, DiskUsage: 42.9, NetworkIn: 5.2, NetworkOut: 2.1},
		{ID: "agent-04", Name: "K8s-Worker-Node-A", IP: "10.0.12.100", OS: "Ubuntu 20.04 LTS", Status: "active", CPUUsage: 55.2, RAMUsage: 81.3, DiskUsage: 66.8, NetworkIn: 12.4, NetworkOut: 11.2},
		{ID: "agent-05", Name: "Jumpbox-SSH", IP: "192.168.10.5", OS: "Debian 12", Status: "active", CPUUsage: 1.5, RAMUsage: 18.2, DiskUsage: 29.4, NetworkIn: 1.8, NetworkOut: 0.9},
	}

	for i := range agentsData {
		agentsData[i].LastSeen = time.Now()
		db.Agents[agentsData[i].ID] = &agentsData[i]
	}
}

func (db *Database) seedFIMEvents() {
	db.Mu.Lock()
	defer db.Mu.Unlock()
	if len(db.FIMEvents) > 0 {
		return
	}
	now := time.Now()
	fimSeeds := []*models.FIMEvent{
		{ID: "fim-0001", Timestamp: now.Add(-45 * time.Minute), AgentID: "agent-01", AgentName: "Web-Prod-01", FilePath: "/etc/nginx/nginx.conf", EventType: "modify", Size: 4096, MD5: "8f683457a123b098f6bcd4621d373cad", SHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", User: "root", Process: "nginx"},
		{ID: "fim-0002", Timestamp: now.Add(-30 * time.Minute), AgentID: "agent-01", AgentName: "Web-Prod-01", FilePath: "/var/www/html/app.py", EventType: "modify", Size: 12480, MD5: "e4d909c290d0fb1ca068ffaddf22cbd0", SHA256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", User: "www-data", Process: "gunicorn"},
		{ID: "fim-0003", Timestamp: now.Add(-20 * time.Minute), AgentID: "agent-02", AgentName: "DB-Replica-01", FilePath: "/etc/postgresql/15/main/pg_hba.conf", EventType: "modify", Size: 3200, MD5: "3499fa1b5ef999bb3cdeee21115f9b88", SHA256: "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef", User: "postgres", Process: "postgres"},
		{ID: "fim-0004", Timestamp: now.Add(-15 * time.Minute), AgentID: "agent-03", AgentName: "AD-Controller-01", FilePath: "C:\\Windows\\System32\\drivers\\etc\\hosts", EventType: "create", Size: 1024, MD5: "7d098f6bcd4621d373cade4e832627b4", SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", User: "Administrator", Process: "powershell.exe"},
		{ID: "fim-0005", Timestamp: now.Add(-10 * time.Minute), AgentID: "agent-04", AgentName: "K8s-Worker-Node-A", FilePath: "/etc/kubernetes/manifests/kube-apiserver.yaml", EventType: "modify", Size: 2560, MD5: "b4621d373cade4e832627b4f6098f6bc", SHA256: "15d6c15b0f00a089f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd", User: "kube", Process: "kubelet"},
		{ID: "fim-0006", Timestamp: now.Add(-5 * time.Minute), AgentID: "agent-05", AgentName: "Jumpbox-SSH", FilePath: "/etc/pam.d/common-auth", EventType: "modify", Size: 1850, MD5: "4621d373cade4e832627b4f6098f6bc0", SHA256: "055ad015a3bf4f1b2b0b822cd15d6c15b0f00a089f86d081884c7d659a2feaa", User: "root", Process: "sshd"},
	}
	db.FIMEvents = fimSeeds
	db.FimCounter = len(fimSeeds)
	if UsePostgres {
		for _, f := range fimSeeds {
			_ = SaveSQLFIMEvent(f)
		}
	}
}

func (db *Database) seedHistory() {
	db.Mu.Lock()
	defer db.Mu.Unlock()

	// Seed historical Alerts (last 24 hours)
	db.AlertCounter = 0
	mitreTechniques := []struct {
		tech  string
		tacs  []string
		title string
		desc  string
		cat   string
		sev   string
	}{
		{"T1059", []string{"Execution"}, "Suspicious PowerShell Execution", "A PowerShell process executed with flags (-enc) commonly used to bypass security controls.", "malware", "high"},
		{"T1078", []string{"Defense Evasion", "Persistence"}, "Multiple Failed Administrator Logins", "Multiple failed login attempts detected for account Administrator within a 2-minute window.", "auth", "medium"},
		{"T1021", []string{"Lateral Movement"}, "RDP Session from Untrusted Subnet", "An active RDP session was established from public IP address 198.51.100.87.", "network", "high"},
		{"T1485", []string{"Impact"}, "Volume Shadow Copy Deletion", "Command 'vssadmin delete shadows' was executed. This is highly indicative of ransomware preparatory activity.", "malware", "critical"},
		{"T1046", []string{"Discovery"}, "Internal Port Scanning Activity", "Local port scan detected: Host scanned 150 ports on 192.168.10.12 in 5 seconds.", "network", "medium"},
		{"T1116", []string{"Credential Access"}, "Lsass Process Memory Dump", "Lsass.exe memory was dumped by a non-system account, indicating credential theft (mimikatz).", "malware", "critical"},
		{"T1496", []string{"Impact"}, "Unusual CPU Spike / Cryptomining Indicators", "CPU usage surged to 100% and connection attempts to a known mining pool IP were blocked.", "audit", "low"},
		{"T1168", []string{"Persistence"}, "Cron Job Modification", "New cron job added to root crontab calling /tmp/.sys_update.", "fim", "medium"},
	}

	for i := 0; i < 20; i++ {
		techIdx := i % len(mitreTechniques)
		tech := mitreTechniques[techIdx]
		agentID := fmt.Sprintf("agent-0%d", (i%5)+1)
		agent := db.Agents[agentID]

		db.AlertCounter++
		alertID := fmt.Sprintf("alt-%04d", db.AlertCounter)
		timeAgo := time.Duration(24-i) * time.Hour
		alertTime := time.Now().Add(-timeAgo)

		status := "open"
		assignee := ""
		if i%3 == 1 {
			status = "investigating"
			assignee = "Alex Miller"
		} else if i%3 == 2 {
			status = "resolved"
			assignee = "Sarah Connor"
		}

		db.Alerts = append(db.Alerts, &models.Alert{
			ID:             alertID,
			RuleID:         fmt.Sprintf("rule-10%03d", techIdx),
			Severity:       tech.sev,
			Title:          tech.title,
			Description:    fmt.Sprintf("%s on host %s.", tech.desc, agent.Name),
			AgentID:        agent.ID,
			AgentName:      agent.Name,
			MITRETechnique: tech.tech,
			MITRETactics:   tech.tacs,
			Category:       tech.cat,
			Timestamp:      alertTime,
			RawLog:         fmt.Sprintf(`{"timestamp":"%s","rule":{"id":"%s","description":"%s","level":%d},"agent":{"id":"%s","name":"%s","ip":"%s"},"mitre":{"id":"%s","tactics":%v}}`, alertTime.Format(time.RFC3339), fmt.Sprintf("rule-10%03d", techIdx), tech.title, 8, agent.ID, agent.Name, agent.IP, tech.tech, tech.tacs),
			Status:         status,
			Assignee:       assignee,
		})
	}

	// Seed FIM events
	db.FimCounter = 0

	for i := 0; i < 15; i++ {
		agentID := fmt.Sprintf("agent-0%d", (i%5)+1)
		agent := db.Agents[agentID]
		isWindows := strings.Contains(strings.ToLower(agent.OS), "windows")

		var path string
		var user string
		var proc string
		var ev string

		if isWindows {
			winFimFiles := []struct {
				path string
				user string
				proc string
				ev   string
			}{
				{"C:\\Windows\\System32\\drivers\\etc\\hosts", "Administrator", "notepad.exe", "modify"},
				{"C:\\Users\\admin\\AppData\\Local\\Temp\\malware.exe", "admin", "chrome.exe", "create"},
				{"C:\\Windows\\System32\\cmd.exe", "SYSTEM", "msiexec.exe", "modify"},
				{"C:\\Users\\admin\\Documents\\confidential.docx", "admin", "svchost_cipher.exe", "delete"},
			}
			idx := i % len(winFimFiles)
			path = winFimFiles[idx].path
			user = winFimFiles[idx].user
			proc = winFimFiles[idx].proc
			ev = winFimFiles[idx].ev
		} else {
			linuxFimFiles := []struct {
				path string
				user string
				proc string
				ev   string
			}{
				{"/etc/passwd", "root", "/usr/sbin/useradd", "modify"},
				{"/etc/shadow", "root", "/usr/sbin/chpasswd", "modify"},
				{"/var/tmp/.lib_sys.so", "user1", "curl", "create"},
				{"/etc/ssh/sshd_config", "root", "nano", "modify"},
				{"/var/www/html/index.php", "www-data", "apache2", "modify"},
				{"/tmp/malware.bin", "nobody", "wget", "create"},
				{"/usr/bin/sudo", "root", "apt-get", "delete"},
			}
			idx := i % len(linuxFimFiles)
			path = linuxFimFiles[idx].path
			user = linuxFimFiles[idx].user
			proc = linuxFimFiles[idx].proc
			ev = linuxFimFiles[idx].ev
		}

		db.FimCounter++
		fimID := fmt.Sprintf("fim-%04d", db.FimCounter)
		timeAgo := time.Duration(15-i) * 30 * time.Minute
		fimTime := time.Now().Add(-timeAgo)

		hashSource := fmt.Sprintf("%s-%s-%s", path, fimTime.String(), agent.ID)
		md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(hashSource)))
		shaHash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashSource)))

		db.FIMEvents = append(db.FIMEvents, &models.FIMEvent{
			ID:        fimID,
			Timestamp: fimTime,
			AgentID:   agent.ID,
			AgentName: agent.Name,
			FilePath:  path,
			EventType: ev,
			Size:      int64(1024 + rand.Intn(4096)),
			MD5:       md5Hash,
			SHA256:    shaHash,
			User:      user,
			Process:   proc,
		})
	}

	// Seed logs
	db.LogCounter = 0
	logTemplates := []struct {
		facility string
		severity string
		msg      string
		code     int
	}{
		{"auth", "info", "Accepted publickey for root from 192.168.1.150 port 52210 ssh2", 0},
		{"web", "warning", "GET /admin/config.php HTTP/1.1 - Attempted unauthorized access to admin panel", 403},
		{"web", "info", "GET /index.html HTTP/1.1 - Success", 200},
		{"syslog", "info", "systemd[1]: Started Periodic Command Scheduler.", 0},
		{"daemon", "info", "cron[492]: (root) CMD (/usr/local/bin/cleanup.sh > /dev/null 2>&1)", 0},
		{"auth", "warning", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.42  user=root", 0},
		{"web", "error", "POST /login.php HTTP/1.1 - Database connection timed out", 500},
		{"daemon", "warning", "dockerd[821]: Container container-db-replica-01 exited unexpectedly with code 137", 0},
	}

	for i := 0; i < 100; i++ {
		tmplIdx := i % len(logTemplates)
		tmpl := logTemplates[tmplIdx]
		agentID := fmt.Sprintf("agent-0%d", (i%5)+1)
		agent := db.Agents[agentID]

		db.LogCounter++
		logID := fmt.Sprintf("log-%05d", db.LogCounter)
		timeAgo := time.Duration(100-i) * 10 * time.Minute
		logTime := time.Now().Add(-timeAgo)

		db.AddLog(&models.LogEntry{
			ID:         logID,
			Timestamp:  logTime,
			AgentID:    agent.ID,
			AgentName:  agent.Name,
			Facility:   tmpl.facility,
			Severity:   tmpl.severity,
			Message:    tmpl.msg,
			SourceIP:   "198.51.100.42",
			StatusCode: tmpl.code,
		})
	}

	// Seed Action Logs (AI & SOC actions)
	db.ActionCounter = 0
	actions := []struct {
		actor  string
		aType  string
		target string
		status string
		msg    string
		ago    time.Duration
	}{
		{"AI Agent", "Isolate Host", "Web-Prod-01 (192.168.10.11)", "success", "Host isolated successfully. Outbound traffic blocked. Local firewall rules applied.", 2 * time.Hour},
		{"SOC (Sarah Connor)", "Block IP", "IP 198.51.100.42", "success", "IP successfully blocked on external edge firewall.", 3 * time.Hour},
		{"AI Agent", "Terminate Process", "svchost_cipher.exe on DB-Replica-01", "success", "Process svchost_cipher.exe (PID: 4802) successfully terminated.", 4 * time.Hour},
		{"SOC (Alex Miller)", "Revoke Credentials", "Administrator", "success", "Administrator Active Directory credentials revoked. Password reset forced.", 6 * time.Hour},
		{"AI Agent", "Block IP", "IP 203.0.113.88", "success", "Malicious C2 IP added to blocklist globally.", 8 * time.Hour},
		{"SOC (Sarah Connor)", "Isolate Host", "AD-Controller-01 (192.168.10.20)", "failed", "Isolation request rejected: Target is a Domain Controller. Manual review required.", 12 * time.Hour},
	}

	for _, act := range actions {
		db.ActionCounter++
		db.ActionLogs = append(db.ActionLogs, &models.ActionLog{
			ID:         fmt.Sprintf("act-%04d", db.ActionCounter),
			Timestamp:  time.Now().Add(-act.ago),
			Actor:      act.actor,
			ActionType: act.aType,
			Target:     act.target,
			Status:     act.status,
			Message:    act.msg,
		})
	}

}

func (db *Database) persistSeed() {
	db.Mu.Lock()
	defer db.Mu.Unlock()

	if !UsePostgres {
		return
	}

	loadedAgents, err := LoadSQLAgents()
	if err == nil && len(loadedAgents) > 0 {
		log.Printf("[DATABASE] Loaded %d agents from PostgreSQL on reconnect.", len(loadedAgents))
		db.Agents = loadedAgents

		loadedAlerts, err := LoadSQLAlerts()
		if err == nil {
			db.Alerts = loadedAlerts
			maxVal := 0
			for _, alert := range loadedAlerts {
				var suffix int
				if _, err := fmt.Sscanf(alert.ID, "alt-%d", &suffix); err == nil {
					if suffix > maxVal {
						maxVal = suffix
					}
				}
				if _, err := fmt.Sscanf(alert.ID, "alt-soar-%d", &suffix); err == nil {
					if suffix > maxVal {
						maxVal = suffix
					}
				}
			}
			db.AlertCounter = maxVal
		}

		loadedFim, err := LoadSQLFIMEvents()
		if err == nil {
			db.FIMEvents = loadedFim
			maxVal := 0
			for _, fim := range loadedFim {
				var suffix int
				if _, err := fmt.Sscanf(fim.ID, "fim-%d", &suffix); err == nil {
					if suffix > maxVal {
						maxVal = suffix
					}
				}
			}
			db.FimCounter = maxVal
		}

		loadedLogs, err := LoadSQLLogEntries()
		if err == nil {
			db.Logs = loadedLogs
			maxVal := 0
			for _, logEntry := range loadedLogs {
				var suffix int
				if _, err := fmt.Sscanf(logEntry.ID, "log-%d", &suffix); err == nil {
					if suffix > maxVal {
						maxVal = suffix
					}
				}
			}
			db.LogCounter = maxVal
		}

		loadedActions, err := LoadSQLActionLogs()
		if err == nil {
			db.ActionLogs = loadedActions
			maxVal := 0
			for _, act := range loadedActions {
				var suffix int
				if _, err := fmt.Sscanf(act.ID, "act-%d", &suffix); err == nil {
					if suffix > maxVal {
						maxVal = suffix
					}
				}
				if _, err := fmt.Sscanf(act.ID, "act-soar-%d", &suffix); err == nil {
					if suffix > maxVal {
						maxVal = suffix
					}
				}
			}
			db.ActionCounter = maxVal
		}
		return
	}

	// Persist the memory-seeded data to PostgreSQL
	for _, a := range db.Agents {
		_ = SaveSQLAgent(a)
	}
	for _, a := range db.Alerts {
		_ = SaveSQLAlert(a)
	}
	for _, f := range db.FIMEvents {
		_ = SaveSQLFIMEvent(f)
	}
	for _, l := range db.Logs {
		_ = SaveSQLLogEntry(l)
	}
	log.Printf("[DATABASE] Memory seeded entities successfully persisted to PostgreSQL.")
}

func (db *Database) startSyncLoop() {
	syncTicker := time.NewTicker(2 * time.Second)
	metricTicker := time.NewTicker(3 * time.Second)
	log.Printf("[SYNC] Starting background security log synchronization loop...")
	for {
		select {
		case <-syncTicker.C:
			db.syncBankSecurityLogs()
		case <-metricTicker.C:
			db.Mu.Lock()
			// Keep storage/heartbeat moving; CPU/RAM are recalculated from threat state below.
			for _, agent := range db.Agents {
				agent.DiskUsage = clamp(agent.DiskUsage+rand.Float64()*0.1, 10.0, 99.0)
				agent.LastSeen = time.Now()
			}
			db.updateAgentThreatsAndNetwork()
			db.Mu.Unlock()
		}
	}
}

func (db *Database) startSimulator() {
	// Tickers
	metricTicker := time.NewTicker(3 * time.Second)
	alertTicker := time.NewTicker(8 * time.Second)
	logTicker := time.NewTicker(1 * time.Second)
	syncTicker := time.NewTicker(2 * time.Second)

	for {
		select {
		case <-syncTicker.C:
			db.syncBankSecurityLogs()
		case <-metricTicker.C:
			db.Mu.Lock()
			// Keep storage/heartbeat moving; CPU/RAM are recalculated from threat state below.
			for _, agent := range db.Agents {
				agent.DiskUsage = clamp(agent.DiskUsage+rand.Float64()*0.1, 10.0, 99.0)
				agent.LastSeen = time.Now()
			}
			db.updateAgentThreatsAndNetwork()
			db.Mu.Unlock()

		case <-logTicker.C:
			db.Mu.Lock()
			// Generate 1-3 new background logs
			numLogs := rand.Intn(3) + 1
			for i := 0; i < numLogs; i++ {
				db.LogCounter++
				agentID := fmt.Sprintf("agent-0%d", rand.Intn(5)+1)
				agent := db.Agents[agentID]

				facilities := []string{"web", "auth", "syslog", "daemon"}
				facility := facilities[rand.Intn(len(facilities))]
				severities := []string{"info", "info", "info", "warning"}
				severity := severities[rand.Intn(len(severities))]

				var msg string
				var code int
				var srcIP string

				switch facility {
				case "web":
					pages := []string{"/index.html", "/assets/js/main.js", "/api/v1/status", "/about", "/contact"}
					page := pages[rand.Intn(len(pages))]
					codes := []int{200, 200, 200, 204, 304, 404}
					code = codes[rand.Intn(len(codes))]
					msg = fmt.Sprintf("GET %s HTTP/1.1 - Status %d", page, code)
					srcIP = fmt.Sprintf("192.168.1.%d", rand.Intn(254)+1)
				case "auth":
					users := []string{"root", "admin", "dev_user", "billing", "analyst"}
					user := users[rand.Intn(len(users))]
					if rand.Float64() > 0.9 {
						msg = fmt.Sprintf("Failed password for %s from 203.0.113.88 port %d ssh2", user, rand.Intn(60000)+1024)
						severity = "warning"
					} else {
						msg = fmt.Sprintf("Session opened for user %s by (uid=0)", user)
					}
				case "syslog":
					msgs := []string{
						"Network interface eth0 link up, 10Gbps/Full",
						"rsyslogd: [origin software=\"rsyslogd\" swVersion=\"8.2112.0\"] daemon shutdown",
						"systemd[1]: Reloading System Daemon.",
						"systemd[1]: Reloaded LSB: Apache2 web server.",
					}
					msg = msgs[rand.Intn(len(msgs))]
				case "daemon":
					msgs := []string{
						"ntpd[653]: Selected source 192.168.10.1 (local)",
						"postfix/qmgr[1082]: A3D4C1021F: removed",
						"named[551]: client @0x7f4c9c100 - query: my-domain.local IN A +ED",
					}
					msg = msgs[rand.Intn(len(msgs))]
				}

				db.AddLog(&models.LogEntry{
					ID:         fmt.Sprintf("log-%05d", db.LogCounter),
					Timestamp:  time.Now(),
					AgentID:    agent.ID,
					AgentName:  agent.Name,
					Facility:   facility,
					Severity:   severity,
					Message:    msg,
					SourceIP:   srcIP,
					StatusCode: code,
				})
			}
			// Cap logs at 3000
			if len(db.Logs) > 3000 {
				db.Logs = db.Logs[len(db.Logs)-3000:]
			}
			db.Mu.Unlock()

		case <-alertTicker.C:
			// Occasional mild alert or FIM event (30% chance)
			if rand.Float64() > 0.7 {
				db.Mu.Lock()
				agentID := fmt.Sprintf("agent-0%d", rand.Intn(5)+1)
				agent := db.Agents[agentID]

				db.AlertCounter++
				alertID := fmt.Sprintf("alt-%04d", db.AlertCounter)

				options := []struct {
					title string
					desc  string
					tech  string
					tacs  []string
					cat   string
					sev   string
				}{
					{"Unauthorized Login Attempt", "Multiple login attempts with invalid username.", "T1110", []string{"Credential Access"}, "auth", "medium"},
					{"Suspicious Binary execution in /tmp", "A process was executed from /tmp directory which is writable by all users.", "T1059", []string{"Execution"}, "malware", "high"},
					{"DNS Request to Dynamic DNS Provider", "Host queried a known dynamic DNS service, which is frequently used by C2 malware.", "T1071", []string{"Command and Control"}, "network", "medium"},
					{"System File Permissions Modified", "Permissions of sensitive config files changed to 777.", "T1222", []string{"Defense Evasion"}, "fim", "high"},
					{"ICMP Ping Sweep Detected", "Reconnaissance ping sweep targeting local subnet ranges.", "T1046", []string{"Discovery"}, "network", "low"},
					{"Unoptimized Database Query Warning", "A query executed slow and consumed excessive system resources temporarily.", "T1496", []string{"Impact"}, "audit", "low"},
				}
				opt := options[rand.Intn(len(options))]

				db.AddAlert(&models.Alert{
					ID:             alertID,
					RuleID:         fmt.Sprintf("rule-20%03d", rand.Intn(100)),
					Severity:       opt.sev,
					Title:          opt.title,
					Description:    fmt.Sprintf("%s on host %s.", opt.desc, agent.Name),
					AgentID:        agent.ID,
					AgentName:      agent.Name,
					MITRETechnique: opt.tech,
					MITRETactics:   opt.tacs,
					Category:       opt.cat,
					Timestamp:      time.Now(),
					RawLog:         fmt.Sprintf(`{"timestamp":"%s","rule":{"id":"rule-auto","description":"%s","level":5},"agent":{"id":"%s","name":"%s"},"mitre":{"id":"%s"}}`, time.Now().Format(time.RFC3339), opt.title, agent.ID, agent.Name, opt.tech),
					Status:         "open",
				})

				// If severity high/critical, set agent status to alerting
				if opt.sev == "high" || opt.sev == "critical" {
					agent.Status = "alerting"
					db.SaveAgent(agent)
				}

				// Generate matching FIM event if it's a FIM alert
				if opt.cat == "fim" {
					db.FimCounter++
					fimID := fmt.Sprintf("fim-%04d", db.FimCounter)
					db.AddFIMEvent(&models.FIMEvent{
						ID:        fimID,
						Timestamp: time.Now(),
						AgentID:   agent.ID,
						AgentName: agent.Name,
						FilePath:  "/etc/security/limits.conf",
						EventType: "modify",
						Size:      4096,
						MD5:       "5d41402abc4b2a76b9719d911017c592",
						SHA256:    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
						User:      "root",
						Process:   "chmod",
					})
				}
				db.Mu.Unlock()
			}
		}
	}
}

// clamp helper
func clamp(val, min, max float64) float64 {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// Threat simulation triggers
func (db *Database) SimulateAttack(agentID string, attackType string) string {
	db.Mu.Lock()
	defer db.Mu.Unlock()

	agent, exists := db.Agents[agentID]
	if !exists {
		return "Agent not found"
	}

	agent.Status = "alerting"
	db.SaveAgent(agent)
	now := time.Now()

	switch attackType {
	case "ransomware":
		var isWindows = strings.Contains(strings.ToLower(agent.OS), "windows")
		var files []string
		var user string
		var process string
		var cmdStr string
		var alertDesc string
		var rawLogStr string
		var logMsg string

		if isWindows {
			files = []string{
				"C:\\Users\\admin\\Documents\\report.docx",
				"C:\\Users\\admin\\Documents\\financials.xlsx",
				"C:\\Users\\admin\\Pictures\\photo.png",
				"C:\\Users\\admin\\Desktop\\credentials.txt",
			}
			user = "Administrator"
			process = "svchost_cipher.exe"
			cmdStr = "vssadmin.exe delete shadows /all /quiet"
			alertDesc = fmt.Sprintf("Command '%s' executed on %s. Multiple system backups are being wiped.", cmdStr, agent.Name)
			rawLogStr = fmt.Sprintf(`{"timestamp":"%s","process":{"name":"vssadmin.exe","cmd":"%s"},"parent":{"name":"cmd.exe"},"user":"%s","agent":{"id":"%s","name":"%s"}}`, now.Format(time.RFC3339), cmdStr, user, agent.ID, agent.Name)
			logMsg = "Process 'svchost_cipher.exe' spawned by Administrator with elevated privileges."
		} else {
			files = []string{
				"/home/admin/Documents/report.docx",
				"/home/admin/Documents/financials.xlsx",
				"/home/admin/Pictures/photo.png",
				"/home/admin/Desktop/credentials.txt",
			}
			user = "root"
			process = "svchost_cipher"
			cmdStr = "rm -rf /var/backups/* /etc/backup.conf"
			alertDesc = fmt.Sprintf("Command '%s' executed on %s. Multiple system backups and configuration files are being wiped.", cmdStr, agent.Name)
			rawLogStr = fmt.Sprintf(`{"timestamp":"%s","process":{"name":"rm","cmd":"%s"},"parent":{"name":"bash"},"user":"%s","agent":{"id":"%s","name":"%s"}}`, now.Format(time.RFC3339), cmdStr, user, agent.ID, agent.Name)
			logMsg = "Process 'svchost_cipher' spawned by root with elevated privileges."
		}

		db.AlertCounter++
		id1 := fmt.Sprintf("alt-%04d", db.AlertCounter)
		db.AddAlert(&models.Alert{
			ID:             id1,
			RuleID:         "rule-ransom-01",
			Severity:       "critical",
			Title:          "Ransomware - Data Encryption Attempt",
			Description:    alertDesc,
			AgentID:        agent.ID,
			AgentName:      agent.Name,
			MITRETechnique: "T1485",
			MITRETactics:   []string{"Impact"},
			Category:       "malware",
			Timestamp:      now,
			RawLog:         rawLogStr,
			Status:         "open",
		})

		for i, f := range files {
			db.FimCounter++
			db.AddFIMEvent(&models.FIMEvent{
				ID:        fmt.Sprintf("fim-%04d", db.FimCounter),
				Timestamp: now.Add(time.Duration(i) * time.Millisecond * 100),
				AgentID:   agent.ID,
				AgentName: agent.Name,
				FilePath:  f + ".locked",
				EventType: "create",
				Size:      8192,
				MD5:       "098f6bcd4621d373cade4e832627b4f6",
				SHA256:    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				User:      user,
				Process:   process,
			})
			db.FimCounter++
			db.AddFIMEvent(&models.FIMEvent{
				ID:        fmt.Sprintf("fim-%04d", db.FimCounter),
				Timestamp: now.Add(time.Duration(i)*time.Millisecond*100 + 50*time.Millisecond),
				AgentID:   agent.ID,
				AgentName: agent.Name,
				FilePath:  f,
				EventType: "delete",
				Size:      0,
				User:      user,
				Process:   process,
			})
		}

		db.LogCounter++
		db.AddLog(&models.LogEntry{
			ID:        fmt.Sprintf("log-%05d", db.LogCounter),
			Timestamp: now,
			AgentID:   agent.ID,
			AgentName: agent.Name,
			Facility:  "syslog",
			Severity:  "alert",
			Message:   "Backup services stopped unexpectedly.",
		})
		db.LogCounter++
		db.AddLog(&models.LogEntry{
			ID:        fmt.Sprintf("log-%05d", db.LogCounter),
			Timestamp: now.Add(100 * time.Millisecond),
			AgentID:   agent.ID,
			AgentName: agent.Name,
			Facility:  "auth",
			Severity:  "warning",
			Message:   logMsg,
		})

		return id1

	case "bruteforce":
		// Trigger Authentication Brute Force alert
		db.AlertCounter++
		id2 := fmt.Sprintf("alt-%04d", db.AlertCounter)
		srcIP := "198.51.100.222"
		db.AddAlert(&models.Alert{
			ID:             id2,
			RuleID:         "rule-brute-01",
			Severity:       "high",
			Title:          "Brute Force Attack - SSH Logs",
			Description:    fmt.Sprintf("Over 150 failed SSH authentication attempts from IP %s on user account 'root' in 15 seconds.", srcIP),
			AgentID:        agent.ID,
			AgentName:      agent.Name,
			MITRETechnique: "T1110.001",
			MITRETactics:   []string{"Credential Access"},
			Category:       "auth",
			Timestamp:      now,
			RawLog:         fmt.Sprintf(`{"timestamp":"%s","sshd":{"failed_attempts":154,"user":"root","rhost":"%s","port":48209},"agent":{"id":"%s","name":"%s"}}`, now.Format(time.RFC3339), srcIP, agent.ID, agent.Name),
			Status:         "open",
		})

		// Append multiple failed login logs
		for i := 0; i < 5; i++ {
			db.LogCounter++
			db.AddLog(&models.LogEntry{
				ID:        fmt.Sprintf("log-%05d", db.LogCounter),
				Timestamp: now.Add(time.Duration(-i) * time.Second),
				AgentID:   agent.ID,
				AgentName: agent.Name,
				Facility:  "auth",
				Severity:  "warning",
				Message:   fmt.Sprintf("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s user=root", srcIP),
				SourceIP:  srcIP,
			})
		}
		// Final success simulation showing compromised entry (or just keeping it failed)
		db.LogCounter++
		db.AddLog(&models.LogEntry{
			ID:        fmt.Sprintf("log-%05d", db.LogCounter),
			Timestamp: now.Add(100 * time.Millisecond),
			AgentID:   agent.ID,
			AgentName: agent.Name,
			Facility:  "auth",
			Severity:  "alert",
			Message:   fmt.Sprintf("Accepted password for root from %s port 52290 ssh2", srcIP),
			SourceIP:  srcIP,
		})

		return id2

	case "malware":
		var isWindows = strings.Contains(strings.ToLower(agent.OS), "windows")
		var alertTitle string
		var alertDesc string
		var rawLogStr string
		var fimPath string
		var fimUser string
		var fimProc string
		var logMsg string

		if isWindows {
			alertTitle = "Malware - Credentials Dumping (Mimikatz Activity)"
			alertDesc = fmt.Sprintf("Lsass.exe memory dumping detected on %s. Critical threat targeting Domain Administrator credentials.", agent.Name)
			rawLogStr = fmt.Sprintf(`{"timestamp":"%s","win_event":{"event_id":10,"source":"Microsoft-Windows-Sysmon","description":"Process accessed lsass.exe memory","target_process":"C:\\Windows\\System32\\lsass.exe","source_process":"C:\\Users\\public\\mktz.exe"},"agent":{"id":"%s","name":"%s"}}`, now.Format(time.RFC3339), agent.ID, agent.Name)
			fimPath = "C:\\Users\\public\\mktz.exe"
			fimUser = "public"
			fimProc = "chrome.exe"
			logMsg = "Sysmon Event ID 10: ProcessAccess (Source: mktz.exe, Target: lsass.exe, GrantedAccess: 0x1410)"
		} else {
			alertTitle = "Malware - Credentials Dumping (Shadow File Access)"
			alertDesc = fmt.Sprintf("Sensitive /etc/shadow read attempt detected on %s. Critical threat targeting Linux account credentials.", agent.Name)
			rawLogStr = fmt.Sprintf(`{"timestamp":"%s","linux_event":{"event_id":1100,"source":"auditd","description":"Process read sensitive shadow file","target_file":"/etc/shadow","source_process":"/tmp/mktz"},"agent":{"id":"%s","name":"%s"}}`, now.Format(time.RFC3339), agent.ID, agent.Name)
			fimPath = "/tmp/mktz"
			fimUser = "nobody"
			fimProc = "wget"
			logMsg = "Auditd Event: sensitive read on /etc/shadow by unauthorized process /tmp/mktz"
		}

		db.AlertCounter++
		id3 := fmt.Sprintf("alt-%04d", db.AlertCounter)
		db.AddAlert(&models.Alert{
			ID:             id3,
			RuleID:         "rule-malware-01",
			Severity:       "critical",
			Title:          alertTitle,
			Description:    alertDesc,
			AgentID:        agent.ID,
			AgentName:      agent.Name,
			MITRETechnique: "T1003.001",
			MITRETactics:   []string{"Credential Access"},
			Category:       "malware",
			Timestamp:      now,
			RawLog:         rawLogStr,
			Status:         "open",
		})

		db.FimCounter++
		db.AddFIMEvent(&models.FIMEvent{
			ID:        fmt.Sprintf("fim-%04d", db.FimCounter),
			Timestamp: now.Add(-5 * time.Second),
			AgentID:   agent.ID,
			AgentName: agent.Name,
			FilePath:  fimPath,
			EventType: "create",
			Size:      240192,
			MD5:       "d41d8cd98f00b204e9800998ecf8427e",
			SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			User:      fimUser,
			Process:   fimProc,
		})

		db.LogCounter++
		db.AddLog(&models.LogEntry{
			ID:        fmt.Sprintf("log-%05d", db.LogCounter),
			Timestamp: now,
			AgentID:   agent.ID,
			AgentName: agent.Name,
			Facility:  "syslog",
			Severity:  "alert",
			Message:   logMsg,
		})

		return id3
	}

	return ""
}

// Helper to calculate agent threat score and network throughput
func (db *Database) updateAgentThreatsAndNetwork() {
	threatCutoff := time.Now().Add(-agentThreatWindow())

	// For each agent, calculate threat score based on recent unresolved alerts.
	// Old incident backlog should stay in the alert history without pinning host load at 100%.
	for _, agent := range db.Agents {
		score := 0
		for _, alt := range db.Alerts {
			if alt.AgentID == agent.ID && alt.Status != "resolved" && !alt.Timestamp.Before(threatCutoff) {
				switch alt.Severity {
				case "critical":
					score += 50
				case "high":
					score += 30
				case "medium":
					score += 15
				case "low":
					score += 5
				}
			}
		}
		if score > 100 {
			score = 100
		}
		agent.ThreatScore = score
		if score > 0 {
			agent.Status = "alerting"
		} else if agent.Status == "alerting" {
			agent.Status = "active"
		}

		db.updateAgentLoad(agent, score)

		// Fluctuate network throughput based on threat level
		if score >= 70 {
			// Severe threat: Data exfiltration / flood simulation!
			agent.NetworkOut = clamp(agent.NetworkOut+rand.Float64()*100-50, 450.0, 980.0)
			agent.NetworkIn = clamp(agent.NetworkIn+rand.Float64()*10-5, 30.0, 80.0)
		} else if score >= 30 {
			// Elevated threat: suspicious traffic
			agent.NetworkOut = clamp(agent.NetworkOut+rand.Float64()*20-10, 80.0, 180.0)
			agent.NetworkIn = clamp(agent.NetworkIn+rand.Float64()*15-7, 40.0, 95.0)
		} else {
			// Normal background traffic
			agent.NetworkOut = clamp(agent.NetworkOut+rand.Float64()*2-1, 1.5, 12.0)
			agent.NetworkIn = clamp(agent.NetworkIn+rand.Float64()*4-2, 2.0, 25.0)
		}
		db.SaveAgent(agent)
	}
}

func agentThreatWindow() time.Duration {
	raw := strings.TrimSpace(os.Getenv("AEGIS_AGENT_THREAT_WINDOW_MINUTES"))
	if raw == "" {
		return 30 * time.Minute
	}
	minutes, err := strconv.Atoi(raw)
	if err != nil || minutes < 1 {
		log.Printf("[DATABASE WARNING] Invalid AEGIS_AGENT_THREAT_WINDOW_MINUTES=%q; using 30 minutes", raw)
		return 30 * time.Minute
	}
	return time.Duration(minutes) * time.Minute
}

func (db *Database) updateAgentLoad(agent *models.Agent, threatScore int) {
	cpuTarget, ramTarget := baselineAgentLoad(agent.ID)
	cpuMin, cpuMax := 2.0, 95.0
	ramMin, ramMax := 10.0, 95.0

	if threatScore >= 70 {
		cpuTarget, ramTarget = 93.0, 92.0
		cpuMin, cpuMax = 65.0, 99.0
		ramMin, ramMax = 75.0, 98.0
	} else if threatScore >= 30 {
		cpuTarget, ramTarget = 72.0, 78.0
		cpuMin, cpuMax = 45.0, 92.0
		ramMin, ramMax = 55.0, 94.0
	}

	agent.CPUUsage = convergeMetric(agent.CPUUsage, cpuTarget, 14.0, 5.0, cpuMin, cpuMax)
	agent.RAMUsage = convergeMetric(agent.RAMUsage, ramTarget, 10.0, 3.0, ramMin, ramMax)
}

func baselineAgentLoad(agentID string) (float64, float64) {
	switch agentID {
	case "agent-01":
		return 24.5, 62.1
	case "agent-02":
		return 12.8, 45.4
	case "agent-03":
		return 8.4, 35.8
	case "agent-04":
		return 55.2, 81.3
	case "agent-05":
		return 1.5, 18.2
	default:
		return 20.0, 45.0
	}
}

func convergeMetric(current, target, maxStep, jitter, min, max float64) float64 {
	delta := target - current
	if delta > maxStep {
		delta = maxStep
	} else if delta < -maxStep {
		delta = -maxStep
	}
	return clamp(current+delta+rand.Float64()*jitter-jitter/2, min, max)
}

var lastIngestedBankLogID int64 = 0
var syncFailCount int = 0

func (db *Database) syncBankSecurityLogs() {
	client := &http.Client{Timeout: 10 * time.Second}
	bankURL := os.Getenv("BANK_BACKEND_URL")
	if bankURL == "" {
		bankURL = "http://be-backend:8080"
	}
	req, err := http.NewRequest("GET", bankURL+"/api/admin/security/logs", nil)
	if err != nil {
		log.Printf("[SYNC ERROR] Failed to create request: %v", err)
		return
	}
	// I-01 fix: use env var instead of hardcoded secret
	syncToken := os.Getenv("AEGIS_INTERNAL_TOKEN")
	if syncToken == "" {
		// In local mode without bank backend, silently skip
		return
	}
	req.Header.Set("X-Aegis-Token", syncToken)

	resp, err := client.Do(req)
	if err != nil {
		syncFailCount++
		// Only log every 30 failures (1 minute at 2s interval) to reduce spam
		if syncFailCount <= 3 || syncFailCount%30 == 0 {
			log.Printf("[SYNC WARNING] Failed to fetch bank logs from %s (attempt %d): %v", bankURL, syncFailCount, err)
		}
		return
	}
	defer resp.Body.Close()
	syncFailCount = 0

	if resp.StatusCode != http.StatusOK {
		log.Printf("[SYNC ERROR] Bank backend returned status %d", resp.StatusCode)
		return
	}

	var logs []struct {
		ID          int64       `json:"id"`
		Timestamp   interface{} `json:"timestamp"`
		AttackType  string      `json:"attackType"`
		Endpoint    string      `json:"endpoint"`
		Payload     string      `json:"payload"`
		Status      string      `json:"status"`
		ClientIP    string      `json:"clientIp"`
		Description string      `json:"description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		log.Printf("[SYNC ERROR] Failed to decode logs JSON: %v", err)
		return
	}

	db.Mu.Lock()

	hasNewAlerts := false
	alertsForHook := make([]*models.Alert, 0)
	for i := len(logs) - 1; i >= 0; i-- {
		logItem := logs[i]
		if logItem.ID > lastIngestedBankLogID {
			lastIngestedBankLogID = logItem.ID

			// Filter out internal SOC UI polling requests (/api/logs, /api/summary, /api/alerts, etc.)
			endpointLower := strings.ToLower(logItem.Endpoint)
			payloadLower := strings.ToLower(logItem.Payload)
			descLower := strings.ToLower(logItem.Description)
			if strings.Contains(endpointLower, "/api/logs") ||
				strings.Contains(endpointLower, "/api/admin/security") ||
				strings.Contains(endpointLower, "/api/summary") ||
				strings.Contains(endpointLower, "/api/agents") ||
				strings.Contains(endpointLower, "/api/alerts") ||
				strings.Contains(payloadLower, "/api/logs") ||
				strings.Contains(descLower, "/api/logs") {
				continue
			}

			mitreTech := "T1190"
			mitreTactics := []string{"Initial Access"}
			severity := SecurityAlertSeverity(logItem.AttackType, logItem.Status, logItem.Payload, logItem.Description)
			if !IsSQLInjectionText(logItem.AttackType, logItem.Payload, logItem.Description) &&
				(strings.Contains(strings.ToLower(logItem.Payload), "admin") || strings.Contains(strings.ToLower(logItem.Description), "admin")) {
				severity = "critical"
			}

			switch strings.ToUpper(logItem.AttackType) {
			case "SQL_INJECTION":
				mitreTech = "T1190"
				mitreTactics = []string{"Initial Access"}
			case "XSS":
				mitreTech = "T1189"
				mitreTactics = []string{"Initial Access"}
			case "BOLA/IDOR":
				mitreTech = "T1068"
				mitreTactics = []string{"Privilege Escalation"}
			case "PARAMETER_TAMPERING":
				mitreTech = "T1565.002"
				mitreTactics = []string{"Impact"}
			case "BRUTE_FORCE":
				mitreTech = "T1110"
				mitreTactics = []string{"Credential Access"}
			}

			db.AlertCounter++
			alertID := fmt.Sprintf("alt-%04d", db.AlertCounter)

			agent := db.Agents["agent-01"]
			if agent != nil {
				agent.Status = "alerting"
				db.SaveAgent(agent)
			}

			rawLogBytes, _ := json.Marshal(map[string]string{
				"timestamp":   time.Now().Format(time.RFC3339),
				"attack_type": logItem.AttackType,
				"attackType":  logItem.AttackType,
				"endpoint":    logItem.Endpoint,
				"payload":     logItem.Payload,
				"status":      logItem.Status,
				"client_ip":   logItem.ClientIP,
				"clientIp":    logItem.ClientIP,
				"description": logItem.Description,
			})
			alert := &models.Alert{
				ID:             alertID,
				RuleID:         fmt.Sprintf("rule-bank-%03d", logItem.ID),
				Severity:       severity,
				Title:          fmt.Sprintf("Aegis Bank - %s Detected", logItem.AttackType),
				Description:    logItem.Description,
				AgentID:        "agent-01",
				AgentName:      "Web-Prod-01",
				MITRETechnique: mitreTech,
				MITRETactics:   mitreTactics,
				Category:       "web",
				Timestamp:      time.Now(),
				RawLog:         string(rawLogBytes),
				Status:         "open",
			}
			db.AddAlert(alert)
			alertsForHook = append(alertsForHook, alert)

			db.LogCounter++
			db.AddLog(&models.LogEntry{
				ID:            fmt.Sprintf("log-%05d", db.LogCounter),
				Timestamp:     time.Now(),
				AgentID:       "agent-01",
				AgentName:     "Web-Prod-01",
				Facility:      "web",
				Severity:      severity,
				Message:       fmt.Sprintf("BANK SECURITY ALARM: %s payload detected on %s from IP %s. Status: %s. Detail: %s", logItem.AttackType, logItem.Endpoint, logItem.ClientIP, logItem.Status, logItem.Description),
				SourceIP:      logItem.ClientIP,
				ThreatFlagged: true,
				ThreatType:    logItem.AttackType,
			})

			hasNewAlerts = true
		}
	}

	if hasNewAlerts {
		log.Printf("[SYNC] Successfully ingested new bank security logs/alerts into PostgreSQL.")
		if len(db.Logs) > 3000 {
			db.Logs = db.Logs[len(db.Logs)-3000:]
		}
		db.updateAgentThreatsAndNetwork()
	}
	db.Mu.Unlock()

	for _, alert := range alertsForHook {
		NotifySecurityAlert(alert)
	}
}
