package store

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestSimulateAttack(t *testing.T) {
	alertID := DB.SimulateAttack("agent-01", "ransomware")
	if alertID == "Agent not found" || alertID == "" {
		t.Errorf("Expected valid alert ID, got %s", alertID)
	}

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

func TestSQLDatabaseOperations(t *testing.T) {
	// Try to connect to postgres
	dbConn, err := sql.Open("postgres", "postgres://postgres:1@localhost:5432/aegis?sslmode=disable")
	if err != nil {
		t.Skip("PostgreSQL driver error, skipping database integration tests")
	}
	defer dbConn.Close()

	err = dbConn.Ping()
	if err != nil {
		t.Skip("PostgreSQL is not running on localhost:5432, skipping database integration tests")
	}

	// Active database mode for testing
	SQL = dbConn
	UsePostgres = true

	// 1. Run migrations and seeding
	InitDB()

	// 2. Test OTP SQL helpers
	err = SaveSQLOTP("10001", "test-otp-token", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Errorf("SaveSQLOTP failed: %v", err)
	}

	otp, _, err := GetSQLOTP("10001")
	if err != nil || otp != "test-otp-token" {
		t.Errorf("GetSQLOTP failed: %v, got %s", err, otp)
	}

	err = DeleteSQLOTP("10001")
	if err != nil {
		t.Errorf("DeleteSQLOTP failed: %v", err)
	}

	// 3. Test Session SQL helpers
	err = SaveSQLSession("test-token", "10001", "admin", "192.168.1.1", time.Now().Add(8*time.Hour))
	if err != nil {
		t.Errorf("SaveSQLSession failed: %v", err)
	}

	uid, username, ip, _, err := GetSQLSession("test-token")
	if err != nil || uid != "10001" || username != "admin" || ip != "192.168.1.1" {
		t.Errorf("GetSQLSession failed: %v", err)
	}

	err = DeleteSQLSession("test-token")
	if err != nil {
		t.Errorf("DeleteSQLSession failed: %v", err)
	}

	CleanExpiredSQLSessions()
}
