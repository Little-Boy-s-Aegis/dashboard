package store

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"dashboard/backend/models"
)

type Database struct {
	Mu           sync.RWMutex
	Agents       map[string]*models.Agent
	Alerts       []*models.Alert
	FIMEvents    []*models.FIMEvent
	Logs         []*models.LogEntry
	AIAnalyses   map[string]*models.AIAnalysis
	AlertCounter int
	FimCounter   int
	LogCounter   int
}

var DB *Database

func init() {
	DB = &Database{
		Agents:     make(map[string]*models.Agent),
		Alerts:     make([]*models.Alert, 0),
		FIMEvents:  make([]*models.FIMEvent, 0),
		Logs:       make([]*models.LogEntry, 0),
		AIAnalyses: make(map[string]*models.AIAnalysis),
	}
	DB.seed()
	go DB.startSimulator()
}

func (db *Database) seed() {
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

	// Seed historical Alerts (last 24 hours)
	db.AlertCounter = 0
	mitreTechniques := []struct {
		tech   string
		tacs   []string
		title  string
		desc   string
		cat    string
		sev    string
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
	fimFiles := []struct {
		path string
		user string
		proc string
		ev   string
	}{
		{"/etc/passwd", "root", "/usr/sbin/useradd", "modify"},
		{"/etc/shadow", "root", "/usr/sbin/chpasswd", "modify"},
		{"/var/tmp/.lib_sys.so", "user1", "curl", "create"},
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", "Administrator", "notepad.exe", "modify"},
		{"/etc/ssh/sshd_config", "root", "nano", "modify"},
		{"/var/www/html/index.php", "www-data", "apache2", "modify"},
		{"/tmp/malware.bin", "nobody", "wget", "create"},
		{"/usr/bin/sudo", "root", "apt-get", "delete"},
	}

	for i := 0; i < 15; i++ {
		fimIdx := i % len(fimFiles)
		fim := fimFiles[fimIdx]
		agentID := fmt.Sprintf("agent-0%d", (i%5)+1)
		agent := db.Agents[agentID]

		db.FimCounter++
		fimID := fmt.Sprintf("fim-%04d", db.FimCounter)
		timeAgo := time.Duration(15-i) * 30 * time.Minute
		fimTime := time.Now().Add(-timeAgo)

		hashSource := fmt.Sprintf("%s-%s-%s", fim.path, fimTime.String(), agent.ID)
		md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(hashSource)))
		shaHash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashSource)))

		db.FIMEvents = append(db.FIMEvents, &models.FIMEvent{
			ID:        fimID,
			Timestamp: fimTime,
			AgentID:   agent.ID,
			AgentName: agent.Name,
			FilePath:  fim.path,
			EventType: fim.ev,
			Size:      int64(1024 + rand.Intn(4096)),
			MD5:       md5Hash,
			SHA256:    shaHash,
			User:      fim.user,
			Process:   fim.proc,
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

		db.Logs = append(db.Logs, &models.LogEntry{
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
}

func (db *Database) startSimulator() {
	// Tickers
	metricTicker := time.NewTicker(3 * time.Second)
	alertTicker := time.NewTicker(8 * time.Second)
	logTicker := time.NewTicker(1 * time.Second)

	for {
		select {
		case <-metricTicker.C:
			db.Mu.Lock()
			// Fluctuate CPU/RAM/Disk metrics slightly
			for _, agent := range db.Agents {
				if agent.Status == "active" {
					agent.CPUUsage = clamp(agent.CPUUsage+rand.Float64()*10-5, 2.0, 95.0)
					agent.RAMUsage = clamp(agent.RAMUsage+rand.Float64()*4-2, 10.0, 95.0)
					agent.DiskUsage = clamp(agent.DiskUsage+rand.Float64()*0.1, 10.0, 99.0)
					agent.LastSeen = time.Now()
				} else if agent.Status == "alerting" {
					// Alerting agents have higher CPU/RAM usage
					agent.CPUUsage = clamp(agent.CPUUsage+rand.Float64()*10-3, 60.0, 99.0)
					agent.RAMUsage = clamp(agent.RAMUsage+rand.Float64()*5-1, 75.0, 98.0)
					agent.LastSeen = time.Now()
				}
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

				db.Logs = append(db.Logs, &models.LogEntry{
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
			// Cap logs at 500
			if len(db.Logs) > 500 {
				db.Logs = db.Logs[len(db.Logs)-500:]
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
				}
				opt := options[rand.Intn(len(options))]

				db.Alerts = append(db.Alerts, &models.Alert{
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
				}

				// Cap alerts
				if len(db.Alerts) > 100 {
					db.Alerts = db.Alerts[len(db.Alerts)-100:]
				}

				// Generate matching FIM event if it's a FIM alert
				if opt.cat == "fim" {
					db.FimCounter++
					fimID := fmt.Sprintf("fim-%04d", db.FimCounter)
					db.FIMEvents = append(db.FIMEvents, &models.FIMEvent{
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
	now := time.Now()

	switch attackType {
	case "ransomware":
		// Trigger Shadow Copy Deletion alert
		db.AlertCounter++
		id1 := fmt.Sprintf("alt-%04d", db.AlertCounter)
		db.Alerts = append(db.Alerts, &models.Alert{
			ID:             id1,
			RuleID:         "rule-ransom-01",
			Severity:       "critical",
			Title:          "Ransomware - Volume Shadow Copy Deletion",
			Description:    fmt.Sprintf("Command 'vssadmin.exe delete shadows /all /quiet' executed on %s. Multiple system backups are being wiped.", agent.Name),
			AgentID:        agent.ID,
			AgentName:      agent.Name,
			MITRETechnique: "T1485",
			MITRETactics:   []string{"Impact"},
			Category:       "malware",
			Timestamp:      now,
			RawLog:         fmt.Sprintf(`{"timestamp":"%s","process":{"name":"vssadmin.exe","cmd":"vssadmin.exe delete shadows /all /quiet"},"parent":{"name":"cmd.exe"},"user":"Administrator","agent":{"id":"%s","name":"%s"}}`, now.Format(time.RFC3339), agent.ID, agent.Name),
			Status:         "open",
		})

		// Trigger rapid FIM events (files modifying/deleting)
		files := []string{"C:\\Users\\admin\\Documents\\report.docx", "C:\\Users\\admin\\Documents\\financials.xlsx", "C:\\Users\\admin\\Pictures\\photo.png", "C:\\Users\\admin\\Desktop\\credentials.txt"}
		for i, f := range files {
			db.FimCounter++
			db.FIMEvents = append(db.FIMEvents, &models.FIMEvent{
				ID:        fmt.Sprintf("fim-%04d", db.FimCounter),
				Timestamp: now.Add(time.Duration(i) * time.Millisecond * 100),
				AgentID:   agent.ID,
				AgentName: agent.Name,
				FilePath:  f + ".locked",
				EventType: "create",
				Size:      8192,
				MD5:       "098f6bcd4621d373cade4e832627b4f6",
				SHA256:    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				User:      "Administrator",
				Process:   "svchost_cipher.exe",
			})
			db.FimCounter++
			db.FIMEvents = append(db.FIMEvents, &models.FIMEvent{
				ID:        fmt.Sprintf("fim-%04d", db.FimCounter),
				Timestamp: now.Add(time.Duration(i)*time.Millisecond*100 + 50*time.Millisecond),
				AgentID:   agent.ID,
				AgentName: agent.Name,
				FilePath:  f,
				EventType: "delete",
				Size:      0,
				User:      "Administrator",
				Process:   "svchost_cipher.exe",
			})
		}

		// Write matching threat logs
		db.LogCounter++
		db.Logs = append(db.Logs, &models.LogEntry{
			ID:        fmt.Sprintf("log-%05d", db.LogCounter),
			Timestamp: now,
			AgentID:   agent.ID,
			AgentName: agent.Name,
			Facility:  "syslog",
			Severity:  "alert",
			Message:   "VSS Backup service stopped unexpectedly. Event ID: 7036.",
		})
		db.LogCounter++
		db.Logs = append(db.Logs, &models.LogEntry{
			ID:        fmt.Sprintf("log-%05d", db.LogCounter),
			Timestamp: now.Add(100 * time.Millisecond),
			AgentID:   agent.ID,
			AgentName: agent.Name,
			Facility:  "auth",
			Severity:  "warning",
			Message:   "Process 'svchost_cipher.exe' spawned by Administrator with elevated privileges.",
		})

		return id1

	case "bruteforce":
		// Trigger Authentication Brute Force alert
		db.AlertCounter++
		id2 := fmt.Sprintf("alt-%04d", db.AlertCounter)
		srcIP := "198.51.100.222"
		db.Alerts = append(db.Alerts, &models.Alert{
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
			db.Logs = append(db.Logs, &models.LogEntry{
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
		db.Logs = append(db.Logs, &models.LogEntry{
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
		// Trigger Malware execution alert (Lsass memory dump or mimikatz)
		db.AlertCounter++
		id3 := fmt.Sprintf("alt-%04d", db.AlertCounter)
		db.Alerts = append(db.Alerts, &models.Alert{
			ID:             id3,
			RuleID:         "rule-malware-01",
			Severity:       "critical",
			Title:          "Malware - Credentials Dumping (Mimikatz Activity)",
			Description:    fmt.Sprintf("Lsass.exe memory dumping detected on %s. Critical threat targeting Domain Administrator credentials.", agent.Name),
			AgentID:        agent.ID,
			AgentName:      agent.Name,
			MITRETechnique: "T1003.001",
			MITRETactics:   []string{"Credential Access"},
			Category:       "malware",
			Timestamp:      now,
			RawLog:         fmt.Sprintf(`{"timestamp":"%s","win_event":{"event_id":10,"source":"Microsoft-Windows-Sysmon","description":"Process accessed lsass.exe memory","target_process":"C:\\Windows\\System32\\lsass.exe","source_process":"C:\\Users\\public\\mktz.exe"},"agent":{"id":"%s","name":"%s"}}`, now.Format(time.RFC3339), agent.ID, agent.Name),
			Status:         "open",
		})

		// Trigger file integrity: dropping the malware bin
		db.FimCounter++
		db.FIMEvents = append(db.FIMEvents, &models.FIMEvent{
			ID:        fmt.Sprintf("fim-%04d", db.FimCounter),
			Timestamp: now.Add(-5 * time.Second),
			AgentID:   agent.ID,
			AgentName: agent.Name,
			FilePath:  "C:\\Users\\public\\mktz.exe",
			EventType: "create",
			Size:      240192,
			MD5:       "d41d8cd98f00b204e9800998ecf8427e",
			SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			User:      "public",
			Process:   "chrome.exe",
		})

		// Logs
		db.LogCounter++
		db.Logs = append(db.Logs, &models.LogEntry{
			ID:        fmt.Sprintf("log-%05d", db.LogCounter),
			Timestamp: now,
			AgentID:   agent.ID,
			AgentName: agent.Name,
			Facility:  "syslog",
			Severity:  "alert",
			Message:   "Sysmon Event ID 10: ProcessAccess (Source: mktz.exe, Target: lsass.exe, GrantedAccess: 0x1410)",
		})

		return id3
	}

	return ""
}

// Helper to calculate agent threat score and network throughput
func (db *Database) updateAgentThreatsAndNetwork() {
	// For each agent, calculate threat score based on its unresolved alerts
	for _, agent := range db.Agents {
		score := 0
		for _, alt := range db.Alerts {
			if alt.AgentID == agent.ID && alt.Status != "resolved" {
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
	}
}
