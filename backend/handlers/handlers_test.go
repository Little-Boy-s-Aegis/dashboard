package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"
)

func TestGetSummary(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()

	GetSummary(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var summary models.DashboardSummary
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal("Failed to parse summary response")
	}

	if summary.TotalAgents == 0 {
		t.Error("Expected seeded agents in summary count")
	}
}

func TestGetAgents(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/agents", nil)
	w := httptest.NewRecorder()

	GetAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var agents []*models.Agent
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil {
		t.Fatal("Failed to parse agents response")
	}

	if len(agents) == 0 {
		t.Error("Expected seeded agents in response list")
	}
}

func TestGetAgentDetail(t *testing.T) {
	t.Run("Valid Agent ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/agents/agent-01", nil)
		w := httptest.NewRecorder()

		GetAgentDetail(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var res struct {
			Agent models.Agent `json:"agent"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal("Failed to parse agent detail")
		}
		if res.Agent.ID != "agent-01" {
			t.Errorf("Expected agent-01, got %s", res.Agent.ID)
		}
	})

	t.Run("Invalid path parts", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/agents", nil)
		w := httptest.NewRecorder()
		GetAgentDetail(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Invalid Agent ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/agents/agent-nonexistent", nil)
		w := httptest.NewRecorder()

		GetAgentDetail(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", w.Code)
		}
	})
}

func TestGetFimEvents(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/fim", nil)
	w := httptest.NewRecorder()

	GetFimEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestGetLogs(t *testing.T) {
	t.Run("Normal Fetch", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/logs", nil)
		w := httptest.NewRecorder()
		GetLogs(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Filtered Fetch", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/logs?severity=high&q=firewall&agentId=agent-01", nil)
		w := httptest.NewRecorder()
		GetLogs(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

func TestAlertOperations(t *testing.T) {
	// Pre-seed specific alerts for contextual analysis testing
	store.DB.Mu.Lock()
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:             "al-ransomware-test",
		Title:          "Critical Ransomware Activity",
		Status:         "open",
		Severity:       "critical",
		MITRETechnique: "T1485",
	})
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:             "al-bruteforce-test",
		Title:          "SSH Brute Force",
		Status:         "open",
		Severity:       "high",
		MITRETechnique: "T1110.001",
	})
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:             "al-lsass-test",
		Title:          "Lsass memory dump activity",
		Status:         "open",
		Severity:       "critical",
		MITRETechnique: "T1003.001",
	})
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:             "al-powershell-test",
		Title:          "PowerShell execution alert",
		Status:         "open",
		Severity:       "high",
		MITRETechnique: "T1059",
	})
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:             "al-generic-test",
		Title:          "Generic suspicious alert",
		Status:         "open",
		Severity:       "medium",
		MITRETechnique: "T0000",
	})
	store.DB.Mu.Unlock()

	// 1. Get Alerts with Query Parameters
	req := httptest.NewRequest("GET", "/api/alerts?severity=critical&agentId=agent-01&status=open&q=ransomware", nil)
	w := httptest.NewRecorder()
	GetAlerts(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// 2. Get Alert Detail (Valid)
	req = httptest.NewRequest("GET", "/api/alerts/al-ransomware-test", nil)
	w = httptest.NewRecorder()
	GetAlertDetail(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// 3. Get Alert Detail (Invalid ID)
	req = httptest.NewRequest("GET", "/api/alerts", nil)
	w = httptest.NewRecorder()
	GetAlertDetail(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// 4. Assign Alert (Missing parameters)
	req = httptest.NewRequest("POST", "/api/alerts/al-ransomware-test/assign", bytes.NewBufferString("invalid-json"))
	w = httptest.NewRecorder()
	AssignAlert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// 5. Assign Alert (Invalid url path)
	req = httptest.NewRequest("POST", "/api", nil)
	w = httptest.NewRecorder()
	AssignAlert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// 6. Assign Alert (Success)
	payload := `{"assignee":"Sarah Connor"}`
	req = httptest.NewRequest("POST", "/api/alerts/al-ransomware-test/assign", bytes.NewBufferString(payload))
	w = httptest.NewRecorder()
	AssignAlert(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// 7. Resolve Alert (Invalid path)
	req = httptest.NewRequest("POST", "/api", nil)
	w = httptest.NewRecorder()
	ResolveAlert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// 7a. Resolve Alert (Method Not Allowed)
	req = httptest.NewRequest("GET", "/api/alerts/al-ransomware-test/resolve", nil)
	w = httptest.NewRecorder()
	ResolveAlert(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}

	// 7b. Resolve Alert (Alert Not Found)
	req = httptest.NewRequest("POST", "/api/alerts/al-nonexistent/resolve", nil)
	w = httptest.NewRecorder()
	ResolveAlert(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}

	// 7c. Resolve Alert (Success)
	req = httptest.NewRequest("POST", "/api/alerts/al-ransomware-test/resolve", nil)
	w = httptest.NewRecorder()
	ResolveAlert(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// 8. Analyze Alerts (Valid / Multi Caches)
	analysisIDs := []string{"al-ransomware-test", "al-bruteforce-test", "al-lsass-test", "al-powershell-test", "al-generic-test"}
	for _, aid := range analysisIDs {
		req = httptest.NewRequest("POST", "/api/alerts/"+aid+"/analyze", nil)
		w = httptest.NewRecorder()
		AnalyzeAlert(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected analyze status 200 for %s, got %d", aid, w.Code)
		}

		// Re-trigger to hit Cache exists branch
		req = httptest.NewRequest("POST", "/api/alerts/"+aid+"/analyze", nil)
		w = httptest.NewRecorder()
		AnalyzeAlert(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected cached analyze status 200 for %s, got %d", aid, w.Code)
		}
	}

	// 9. Analyze Alert (Invalid path)
	req = httptest.NewRequest("POST", "/api", nil)
	w = httptest.NewRecorder()
	AnalyzeAlert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestBulkAlertOperations(t *testing.T) {
	store.DB.Mu.Lock()
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:     "al-bulk-1",
		Status: "open",
	})
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:     "al-bulk-2",
		Status: "open",
	})
	store.DB.Mu.Unlock()

	t.Run("Bulk Assign Empty Payload", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/alerts/bulk-assign", bytes.NewBufferString("invalid-json"))
		w := httptest.NewRecorder()
		BulkAssignAlerts(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Bulk Assign Success", func(t *testing.T) {
		payload := `{"ids":["al-bulk-1","al-bulk-2"],"assignee":"SOC Operator"}`
		req := httptest.NewRequest("POST", "/api/alerts/bulk-assign", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		BulkAssignAlerts(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Bulk Resolve Empty Payload", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/alerts/bulk-resolve", bytes.NewBufferString("invalid-json"))
		w := httptest.NewRecorder()
		BulkResolveAlerts(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Bulk Resolve Success", func(t *testing.T) {
		payload := `{"ids":["al-bulk-1","al-bulk-2"]}`
		req := httptest.NewRequest("POST", "/api/alerts/bulk-resolve", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		BulkResolveAlerts(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

func TestSimulationAndActions(t *testing.T) {
	t.Run("Trigger Simulation Invalid Payload", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewBufferString("invalid-json"))
		w := httptest.NewRecorder()
		TriggerSimulation(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Trigger Simulation Missing fields", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewBufferString(`{"agentId":""}`))
		w := httptest.NewRecorder()
		TriggerSimulation(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Trigger Simulation Agent not found", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewBufferString(`{"agentId":"non-existent","type":"ransomware"}`))
		w := httptest.NewRecorder()
		TriggerSimulation(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", w.Code)
		}
	})

	t.Run("Trigger Simulation Invalid type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewBufferString(`{"agentId":"agent-01","type":"invalid-type"}`))
		w := httptest.NewRecorder()
		TriggerSimulation(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Perform Action Method Not Allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/actions", nil)
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})

	t.Run("Perform Action Invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString("invalid-json"))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Perform Action Missing Fields", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(`{"target":""}`))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Perform Action - Isolate Host (Valid Agent)", func(t *testing.T) {
		payload := `{"actionType":"Isolate Host","target":"agent-01"}`
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Perform Action - Isolate Host (Invalid Agent)", func(t *testing.T) {
		payload := `{"actionType":"Isolate Host","target":"agent-invalid"}`
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Perform Action - Terminate Process", func(t *testing.T) {
		payload := `{"actionType":"Terminate Process","target":"malware.exe"}`
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Perform Action - Revoke Credentials", func(t *testing.T) {
		payload := `{"actionType":"Revoke Credentials","target":"admin_user"}`
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Perform Action - Block IP normalizes target and enforces ban", func(t *testing.T) {
		setupTestStores()
		payload := `{"actionType":"Block IP","target":"IP 198.51.100.222"}`
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		if _, ok := store.DB.BannedIPs["198.51.100.222"]; !ok {
			t.Fatal("Expected normalized banned IP to be saved")
		}

		protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		authMu.Lock()
		sessionStore["blocked-session-token"] = sessionData{
			UID:       "10001",
			Username:  "admin",
			IPAddress: "198.51.100.222",
			ExpiresAt: time.Now().Add(time.Hour),
		}
		authMu.Unlock()
		banChecked := IPBanMiddleware(protected)
		blockedReq := httptest.NewRequest("GET", "/api/summary", nil)
		blockedReq.RemoteAddr = "198.51.100.222:45678"
		blockedReq.AddCookie(&http.Cookie{Name: "session_token", Value: "blocked-session-token"})
		blockedResp := httptest.NewRecorder()
		banChecked.ServeHTTP(blockedResp, blockedReq)
		if blockedResp.Code != http.StatusForbidden {
			t.Errorf("Expected banned IP middleware status 403, got %d", blockedResp.Code)
		}
		if blockedResp.Header().Get("X-Aegis-IP-Banned") != "true" {
			t.Error("Expected banned IP response marker header")
		}
		authMu.RLock()
		_, stillActive := sessionStore["blocked-session-token"]
		authMu.RUnlock()
		if stillActive {
			t.Fatal("Expected banned IP middleware to revoke the active session")
		}
	})

	t.Run("Perform Action - Block IP rejects invalid target", func(t *testing.T) {
		payload := `{"actionType":"Block IP","target":"not-an-ip"}`
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		PerformAction(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Get Actions list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/actions", nil)
		w := httptest.NewRecorder()
		GetActions(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}
