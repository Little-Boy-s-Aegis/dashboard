package store

import (
	"testing"
)

func TestSimulateAttack(t *testing.T) {
	// Assert simulating attacks on agent-01
	alertID := DB.SimulateAttack("agent-01", "ransomware")
	if alertID == "Agent not found" || alertID == "" {
		t.Errorf("Expected valid alert ID, got %s", alertID)
	}

	// Verify agent status changed or logs were appended
	DB.Mu.RLock()
	defer DB.Mu.RUnlock()

	foundAlert := false
	for _, a := range DB.Alerts {
		if a.ID == alertID {
			foundAlert = true
			if a.Severity != "critical" {
				t.Errorf("Expected critical severity for ransomware, got %s", a.Severity)
			}
		}
	}
	if !foundAlert {
		t.Error("Expected triggered alert to exist in Alerts store")
	}
}

func TestSimulateAttackInvalidAgent(t *testing.T) {
	res := DB.SimulateAttack("agent-nonexistent", "ransomware")
	if res != "Agent not found" {
		t.Errorf("Expected Agent not found, got %s", res)
	}
}

func TestSimulateAttackUnknownType(t *testing.T) {
	res := DB.SimulateAttack("agent-01", "unknown-type")
	if res != "" {
		t.Errorf("Expected empty response on unknown simulation type, got %s", res)
	}
}
