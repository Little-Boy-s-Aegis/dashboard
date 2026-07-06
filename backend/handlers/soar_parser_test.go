package handlers

import (
	"strings"
	"testing"
)

func TestParseSoarDecision_Valid(t *testing.T) {
	mockPayload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-06T11:00:00Z",
		"input_summary": {
			"incident_id": "INC-TEST-1234"
		},
		"verified_case": {
			"threat_confirmed": true,
			"title": "Ransomware - Volume Shadow Copy Deletion",
			"summary": "Shadow copies deleted on Web-Prod-01.",
			"entities": {
				"ips": ["198.51.100.222"],
				"users": ["Administrator"],
				"accounts_masked": ["admin_masked"]
			}
		},
		"scoring": {
			"final_risk_score_0_10": 8.5,
			"priority": "high"
		},
		"decision": {
			"final_decision": "execute",
			"justification": "Threat is verified from logs"
		}
	}`

	dec, info, err := ParseSoarDecision([]byte(mockPayload))
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if dec.InputSummary.IncidentID != "INC-TEST-1234" {
		t.Errorf("Expected incident_id INC-TEST-1234, got %s", dec.InputSummary.IncidentID)
	}

	if info.AttackType != "Ransomware - Volume Shadow Copy Deletion" {
		t.Errorf("Expected AttackType Ransomware - Volume Shadow Copy Deletion, got %s", info.AttackType)
	}

	if info.SourceIP != "198.51.100.222" {
		t.Errorf("Expected SourceIP 198.51.100.222, got %s", info.SourceIP)
	}

	if !strings.Contains(info.AffectedAccount, "admin_masked") || !strings.Contains(info.AffectedAccount, "Administrator") {
		t.Errorf("Expected AffectedAccount to contain both Administrator and admin_masked, got %s", info.AffectedAccount)
	}

	if info.Severity != "high" {
		t.Errorf("Expected severity high, got %s", info.Severity)
	}

	if info.RiskScore != 8.5 {
		t.Errorf("Expected RiskScore 8.5, got %f", info.RiskScore)
	}

	if !info.ThreatConfirmed {
		t.Errorf("Expected ThreatConfirmed to be true")
	}
}

func TestParseSoarDecision_InvalidVersion(t *testing.T) {
	mockPayload := `{
		"schema_version": "invalid_version",
		"timestamp": "2026-07-06T11:00:00Z"
	}`

	_, _, err := ParseSoarDecision([]byte(mockPayload))
	if err == nil {
		t.Fatalf("Expected error for invalid version, got nil")
	}
}

func TestParseSoarDecision_EmptyPriorityFallback(t *testing.T) {
	mockPayload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-06T11:00:00Z",
		"scoring": {
			"final_risk_score_0_10": 9.5
		}
	}`

	_, info, err := ParseSoarDecision([]byte(mockPayload))
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if info.Severity != "critical" {
		t.Errorf("Expected severity critical due to score 9.5, got %s", info.Severity)
	}
}
