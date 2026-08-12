package processor

import (
	"encoding/json"
	"testing"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"
)

func TestThreatAlertRawLogIncludesSourceIP(t *testing.T) {
	originalDB := store.DB
	originalUsePostgres := store.UsePostgres
	store.UsePostgres = false
	store.DB = &store.Database{
		Agents:     map[string]*models.Agent{"agent-gateway": {ID: "agent-gateway", Name: "NginxGateway"}},
		Alerts:     []*models.Alert{},
		Logs:       []*models.LogEntry{},
		AIAnalyses: map[string]*models.AIAnalysis{},
		BannedIPs:  map[string]*models.BannedIP{},
	}
	t.Cleanup(func() {
		store.DB = originalDB
		store.UsePostgres = originalUsePostgres
	})

	pushToDashboardStore(&models.LogEntry{
		ID:             "log-siem-0001",
		Timestamp:      time.Now(),
		AgentID:        "agent-gateway",
		AgentName:      "NginxGateway",
		Facility:       "apigw",
		Severity:       "alert",
		Message:        "SQL injection payload detected",
		SourceIP:       "42.114.204.232",
		ThreatFlagged:  true,
		ThreatType:     "SQL_INJECTION",
		DecodedPayload: "/api/auth/login?id=' OR 1=1 --",
	})

	if len(store.DB.Alerts) != 1 {
		t.Fatalf("expected one SIEM alert, got %d", len(store.DB.Alerts))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(store.DB.Alerts[0].RawLog), &raw); err != nil {
		t.Fatalf("expected structured rawLog JSON, got %q: %v", store.DB.Alerts[0].RawLog, err)
	}
	if raw["sourceIp"] != "42.114.204.232" {
		t.Fatalf("expected sourceIp in alert rawLog, got %#v", raw["sourceIp"])
	}
}
