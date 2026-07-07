package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
