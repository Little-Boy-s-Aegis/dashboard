package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGetFimEvents(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/fim", nil)
	w := httptest.NewRecorder()

	GetFimEvents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestGetLogs(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/logs", nil)
	w := httptest.NewRecorder()

	GetLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAlertOperations(t *testing.T) {
	// 1. Get Alerts
	req := httptest.NewRequest("GET", "/api/alerts", nil)
	w := httptest.NewRecorder()
	GetAlerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var alerts []*models.Alert
	json.Unmarshal(w.Body.Bytes(), &alerts)
	if len(alerts) == 0 {
		t.Fatal("No seeded alerts found to perform tests")
	}

	targetAlertID := alerts[0].ID

	// 2. Assign Alert
	payload := `{"assignee":"Sarah Connor"}`
	req = httptest.NewRequest("POST", "/api/alerts/"+targetAlertID+"/assign", bytes.NewBufferString(payload))
	w = httptest.NewRecorder()
	AssignAlert(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected assign status 200, got %d", w.Code)
	}

	// 3. Resolve Alert
	req = httptest.NewRequest("POST", "/api/alerts/"+targetAlertID+"/resolve", nil)
	w = httptest.NewRecorder()
	ResolveAlert(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected resolve status 200, got %d", w.Code)
	}
}

func TestBulkAlertOperations(t *testing.T) {
	// Pre-seed alerts list
	store.DB.Mu.Lock()
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:       "al-test-1",
		Status:   "open",
		Severity: "medium",
		Title:    "Bulk Test Alert 1",
	})
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:       "al-test-2",
		Status:   "open",
		Severity: "high",
		Title:    "Bulk Test Alert 2",
	})
	store.DB.Mu.Unlock()

	t.Run("Bulk Assign", func(t *testing.T) {
		payload := `{"ids":["al-test-1","al-test-2"],"assignee":"Alex Miller"}`
		req := httptest.NewRequest("POST", "/api/alerts/bulk-assign", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		BulkAssignAlerts(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		store.DB.Mu.RLock()
		defer store.DB.Mu.RUnlock()
		for _, a := range store.DB.Alerts {
			if (a.ID == "al-test-1" || a.ID == "al-test-2") && a.Assignee != "Alex Miller" {
				t.Errorf("Alert %s was not assigned in bulk", a.ID)
			}
		}
	})

	t.Run("Bulk Resolve", func(t *testing.T) {
		payload := `{"ids":["al-test-1","al-test-2"]}`
		req := httptest.NewRequest("POST", "/api/alerts/bulk-resolve", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		BulkResolveAlerts(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		store.DB.Mu.RLock()
		defer store.DB.Mu.RUnlock()
		for _, a := range store.DB.Alerts {
			if (a.ID == "al-test-1" || a.ID == "al-test-2") && a.Status != "resolved" {
				t.Errorf("Alert %s was not resolved in bulk", a.ID)
			}
		}
	})
}

func TestSimulationAndActions(t *testing.T) {
	t.Run("Trigger Simulation", func(t *testing.T) {
		payload := `{"agentId":"agent-01","type":"ransomware"}`
		req := httptest.NewRequest("POST", "/api/simulate", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		TriggerSimulation(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "Ransomware") {
			t.Errorf("Expected simulation success output containing ransomware, got: %s", w.Body.String())
		}
	})

	t.Run("Perform Action - Authenticated SOC Admin", func(t *testing.T) {
		// Pre-seed an active session
		sessionToken := "admin-action-session"
		authMu.Lock()
		sessionStore[sessionToken] = sessionData{
			UID:       "10001",
			Username:  "admin",
			IPAddress: "192.0.2.10",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		authMu.Unlock()

		payload := `{"actionType":"Block IP","target":"10.0.0.1"}`
		req := httptest.NewRequest("POST", "/api/actions", bytes.NewBufferString(payload))
		req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
		req.RemoteAddr = "192.0.2.10:1234"
		w := httptest.NewRecorder()

		PerformAction(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var res models.ActionLog
		json.Unmarshal(w.Body.Bytes(), &res)

		if res.Actor != "SOC (admin)" {
			t.Errorf("Expected Actor to be SOC (admin), got %s", res.Actor)
		}
	})
}
