package handlers

import (
	"bytes"
	"dashboard/backend/models"
	"dashboard/backend/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSoar_SchemaVersionMismatch verifies that payloads with incorrect/mismatched
// schema versions are rejected by the decision handler.
func TestSoar_SchemaVersionMismatch(t *testing.T) {
	setupTestStores()
	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")

	payload := `{
		"schema_version": "invalid.schema.version.v9",
		"timestamp": "2026-07-07T10:00:00Z"
	}`

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	req.Header.Set("X-Aegis-Internal-Key", "test-token")
	w := httptest.NewRecorder()

	HandleInternalSoarDecision(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d", w.Code)
	}
}

// TestSoar_OversizedPayload verifies that payloads exceeding the maximum request size limit
// (5 MB) are rejected.
func TestSoar_OversizedPayload(t *testing.T) {
	setupTestStores()
	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")

	// Generate a payload larger than 5 MB
	largePayload := make([]byte, 6*1024*1024)
	for i := range largePayload {
		largePayload[i] = 'A'
	}

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewReader(largePayload))
	req.Header.Set("X-Aegis-Internal-Key", "test-token")
	w := httptest.NewRecorder()

	HandleInternalSoarDecision(w, req)

	// MaxBytesReader returns bad request / request entity too large errors
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 400 or 413, got %d", w.Code)
	}
}

// TestSoar_MalformedJson verifies that malformed JSON request bodies are handled gracefully.
func TestSoar_MalformedJson(t *testing.T) {
	setupTestStores()
	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")

	payload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-07T10:00:00Z",
		malformed json
	}`

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	req.Header.Set("X-Aegis-Internal-Key", "test-token")
	w := httptest.NewRecorder()

	HandleInternalSoarDecision(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d", w.Code)
	}
}

// TestSoar_MissingRequiredFields verifies that decisions missing mandatory fields
// are rejected.
func TestSoar_MissingRequiredFields(t *testing.T) {
	setupTestStores()
	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")

	// Missing input_summary and decision fields
	payload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-07T10:00:00Z",
		"scoring": {"final_risk_score_0_10": 8.5}
	}`

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	req.Header.Set("X-Aegis-Internal-Key", "test-token")
	w := httptest.NewRecorder()

	HandleInternalSoarDecision(w, req)

	// Should reject missing fields with 400 Bad Request
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d", w.Code)
	}
}

// TestSoar_ExcessiveActions verifies that request with excessive number of actions is handled safely
// and does not cause server resource exhaustion.
func TestSoar_ExcessiveActions(t *testing.T) {
	setupTestStores()
	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")

	// Create a payload with 1000+ actions (simulated DoS)
	var actionsBuilder strings.Builder
	for i := 0; i < 1000; i++ {
		actionsBuilder.WriteString(`{"action_type":"block_ip","status":"executed","target":{"type":"ip","value_masked":"192.168.1.1"},"rationale":"test"},`)
	}
	actionsStr := actionsBuilder.String()
	if len(actionsStr) > 0 {
		actionsStr = actionsStr[:len(actionsStr)-1] // remove trailing comma
	}

	payload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-07T10:00:00Z",
		"input_summary": {"incident_id": "INC-DoS"},
		"verified_case": {"threat_confirmed": true, "title": "DoS test"},
		"scoring": {"final_risk_score_0_10": 9.9},
		"decision": {"final_decision": "block"},
		"actions": [` + actionsStr + `]
	}`

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	req.Header.Set("X-Aegis-Internal-Key", "test-token")
	w := httptest.NewRecorder()

	HandleInternalSoarDecision(w, req)

	// Depending on parsing logic, it should either process or reject. Ensure it doesn't crash (should be 200 or 400).
	if w.Code == http.StatusInternalServerError {
		t.Error("Server crashed with 500 when receiving excessive actions")
	}
}

func TestSoar_CriticalNonSQLiBlockIPDecisionPersistsBan(t *testing.T) {
	setupTestStores()
	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")
	t.Setenv("BANK_BACKEND_URL", "")

	payload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v8",
		"timestamp": "2026-07-10T14:18:21Z",
		"input_summary": {"incident_id": "INC-CRITICAL-BRUTE-FORCE"},
		"verified_case": {
			"threat_confirmed": true,
			"title": "Aegis Bank - BRUTE_FORCE Detected",
			"summary": "Critical credential attack against public banking authentication.",
			"entities": {"users": [], "accounts_masked": [], "hosts": ["Web-Prod-01"], "ips": ["42.114.204.232"]}
		},
		"scoring": {"final_risk_score_0_10": 9.5, "priority": "critical"},
		"decision": {"final_decision": "auto_execute", "justification": "PB-WEB-EDGE confirmed malicious brute-force source."},
		"actions": [{
			"action_id": "act-critical-ban",
			"action_type": "block_ip",
			"phase": "contain",
			"status": "executed",
			"rationale": "PB-WEB-EDGE step-3a block_ip executed.",
			"target": {"type": "IP", "value_masked": "42.114.204.232"}
		}]
	}`

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	req.Header.Set("X-Aegis-Internal-Key", "test-token")
	w := httptest.NewRecorder()

	HandleInternalSoarDecision(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := store.DB.BannedIPs["42.114.204.232"]; !ok {
		t.Fatal("Expected critical SOAR block_ip action to persist attacker IP ban")
	}
	if len(store.DB.ActionLogs) == 0 || store.DB.ActionLogs[len(store.DB.ActionLogs)-1].Actor != "SOAR L2 Orchestrator" {
		t.Fatal("Expected SOAR L2 Orchestrator action log for critical IP ban")
	}
}

func TestSoar_SQLiHighAndMediumAutoBlockDecisionDoesNotBan(t *testing.T) {
	cases := []struct {
		name     string
		priority string
		score    string
	}{
		{name: "high", priority: "high", score: "8.0"},
		{name: "medium", priority: "medium", score: "6.0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestStores()
			t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")
			t.Setenv("BANK_BACKEND_URL", "")

			payload := `{
				"schema_version": "littleboy.soc.layer2.orchestrator_decision.v8",
				"timestamp": "2026-07-10T14:18:21Z",
				"input_summary": {"incident_id": "INC-SQLI-` + tc.name + `"},
				"verified_case": {
					"threat_confirmed": true,
					"title": "Aegis Bank - SQL_INJECTION Detected",
					"summary": "SQL injection attempt against public banking authentication.",
					"entities": {"users": [], "accounts_masked": [], "hosts": ["Web-Prod-01"], "ips": ["42.114.204.232"]}
				},
				"scoring": {"final_risk_score_0_10": ` + tc.score + `, "priority": "` + tc.priority + `"},
				"decision": {"final_decision": "auto_execute", "justification": "SQLi detection stays alert-only below critical containment threshold."},
				"actions": [{
					"action_id": "act-sqli-ban",
					"action_type": "block_ip",
					"phase": "contain",
					"status": "executed",
					"rationale": "LLM attempted SQLi block_ip.",
					"target": {"type": "IP", "value_masked": "42.114.204.232"}
				}]
			}`

			req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
			req.Header.Set("X-Aegis-Internal-Key", "test-token")
			w := httptest.NewRecorder()

			HandleInternalSoarDecision(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
			}
			if _, ok := store.DB.BannedIPs["42.114.204.232"]; ok {
				t.Fatal("Expected SQLi high/medium automatic decision to avoid persisting attacker IP ban")
			}
			if len(store.DB.ActionLogs) == 0 {
				t.Fatal("Expected SOAR policy-block action log")
			}
			last := store.DB.ActionLogs[len(store.DB.ActionLogs)-1]
			if last.Status != "blocked_by_policy" {
				t.Fatalf("Expected blocked_by_policy action status, got %s", last.Status)
			}
		})
	}
}

func resetSoarActionStateForTest() {
	store.DB.Mu.Lock()
	defer store.DB.Mu.Unlock()
	store.DB.BannedIPs = make(map[string]*models.BannedIP)
	store.DB.ActionLogs = nil
	store.DB.Alerts = nil
	store.DB.AlertCounter = 0
	store.DB.ActionCounter = 0
}

func TestAlertAutobanFromOrchestratorCriticalNonSQLiExecutesBan(t *testing.T) {
	setupTestStores()
	resetSoarActionStateForTest()
	t.Setenv("BANK_BACKEND_URL", "")

	alert := &models.Alert{
		ID:             "alt-auto-critical",
		RuleID:         "rule-bruteforce",
		Severity:       "critical",
		Title:          "Aegis Bank - BRUTE_FORCE Detected",
		Description:    "Confirmed active credential attack against public banking login.",
		AgentID:        "agent-01",
		AgentName:      "Web-Prod-01",
		MITRETechnique: "T1110",
		MITRETactics:   []string{"Credential Access"},
		Category:       "web",
		Timestamp:      time.Now(),
		RawLog:         `{"clientIp":"42.114.204.232","attackType":"BRUTE_FORCE"}`,
		Status:         "open",
	}

	result, err := ExecuteAlertAutobanFromOrchestrator(alert, "test")
	if err != nil {
		t.Fatalf("Expected autoban execution without error, got %v", err)
	}
	if result.Status != "executed" {
		t.Fatalf("Expected autoban status executed, got %s: %s", result.Status, result.Reason)
	}
	if _, ok := store.DB.BannedIPs["42.114.204.232"]; !ok {
		t.Fatal("Expected critical non-SQLi alert autoban to persist attacker IP ban")
	}
	if len(store.DB.ActionLogs) == 0 {
		t.Fatal("Expected SOAR action log for automatic IP ban")
	}
	last := store.DB.ActionLogs[len(store.DB.ActionLogs)-1]
	if last.Actor != "SOAR L2 Orchestrator" || last.ActionType != "Block IP" || last.Status != "success" {
		t.Fatalf("Expected successful SOAR Block IP action, got actor=%s type=%s status=%s", last.Actor, last.ActionType, last.Status)
	}
}

func TestAlertAutobanFromOrchestratorSQLiHighAndMediumSkipsBan(t *testing.T) {
	cases := []struct {
		name     string
		severity string
		status   string
	}{
		{name: "high allowed SQLi", severity: "high", status: "ALLOWED"},
		{name: "medium blocked SQLi", severity: "medium", status: "BLOCKED"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestStores()
			resetSoarActionStateForTest()
			t.Setenv("BANK_BACKEND_URL", "")

			alert := &models.Alert{
				ID:             "alt-auto-sqli-" + tc.severity,
				RuleID:         "rule-sqli",
				Severity:       tc.severity,
				Title:          "Aegis Bank - SQL_INJECTION Detected",
				Description:    "SQL injection attempt against public banking login.",
				AgentID:        "agent-01",
				AgentName:      "Web-Prod-01",
				MITRETechnique: "T1190",
				MITRETactics:   []string{"Initial Access"},
				Category:       "web",
				Timestamp:      time.Now(),
				RawLog:         `{"clientIp":"42.114.204.232","attackType":"SQL_INJECTION","status":"` + tc.status + `"}`,
				Status:         "open",
			}

			result, err := ExecuteAlertAutobanFromOrchestrator(alert, "test")
			if err != nil {
				t.Fatalf("Expected SQLi autoban skip without error, got %v", err)
			}
			if result.Status != "skipped" {
				t.Fatalf("Expected SQLi autoban status skipped, got %s", result.Status)
			}
			if !strings.Contains(result.Reason, "SQL injection") {
				t.Fatalf("Expected SQLi skip reason, got %q", result.Reason)
			}
			if _, ok := store.DB.BannedIPs["42.114.204.232"]; ok {
				t.Fatal("Expected SQLi high/medium alert autoban to avoid persisting attacker IP ban")
			}
			if len(store.DB.ActionLogs) != 0 {
				t.Fatalf("Expected no SOAR action logs for skipped SQLi autoban, got %d", len(store.DB.ActionLogs))
			}
		})
	}
}

func TestAlertOrchestratedBanUsesPlaybookGateway(t *testing.T) {
	setupTestStores()
	t.Setenv("BANK_BACKEND_URL", "")

	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:             "alt-critical-sqli",
		RuleID:         "rule-sqli",
		Severity:       "critical",
		Title:          "Aegis Bank - SQL_INJECTION Detected",
		Description:    "Attacker 42.114.204.232 is targeting the banking web edge.",
		AgentID:        "agent-01",
		AgentName:      "Web-Prod-01",
		MITRETechnique: "T1190",
		MITRETactics:   []string{"Initial Access"},
		Category:       "network",
		Timestamp:      time.Now(),
		RawLog:         `{"clientIp":"42.114.204.232","attackType":"SQL_INJECTION"}`,
		Status:         "open",
	})

	req := httptest.NewRequest("POST", "/api/alerts/alt-critical-sqli/orchestrated-ban", bytes.NewBufferString(`{"target":"42.114.204.232"}`))
	w := httptest.NewRecorder()

	OrchestrateAlertBan(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := store.DB.BannedIPs["42.114.204.232"]; !ok {
		t.Fatal("Expected alert-table ban to persist through orchestrated PB-WEB-EDGE path")
	}
	last := store.DB.ActionLogs[len(store.DB.ActionLogs)-1]
	if last.Actor != "SOAR L2 Orchestrator" || last.ActionType != "Block IP" {
		t.Fatalf("Expected SOAR L2 Orchestrator Block IP action, got actor=%s type=%s", last.Actor, last.ActionType)
	}
}

// TestSoar_InjectionInPlaybookId verifies that malicious input in incident_id or playbook metadata
// (like path traversal or SQL injection strings) does not cause backend vulnerabilities.
func TestSoar_InjectionInPlaybookId(t *testing.T) {
	setupTestStores()
	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-token")

	payload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-07T10:00:00Z",
		"input_summary": {"incident_id": "../../../etc/passwd"},
		"verified_case": {
			"threat_confirmed": true,
			"title": "SQL Injection Test",
			"entities": {"ips": ["'; DROP TABLE alerts; --"]}
		},
		"scoring": {"final_risk_score_0_10": 9.9},
		"decision": {"final_decision": "block"},
		"actions": []
	}`

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	req.Header.Set("X-Aegis-Internal-Key", "test-token")
	w := httptest.NewRecorder()

	HandleInternalSoarDecision(w, req)

	// Should not crash and should return 200 or 400 (not 500)
	if w.Code == http.StatusInternalServerError {
		t.Error("Server crashed with 500 when injection payload sent in SOAR decision fields")
	}
}
