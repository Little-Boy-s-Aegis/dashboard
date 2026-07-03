package store

import (
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var (
	SQL         *sql.DB
	UsePostgres bool = false
)

// InitDB: Try to connect to PostgreSQL. If it fails, fall back to in-memory mode.
func InitDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// Fallback to default local postgres credentials
		dsn = "postgres://postgres:1@localhost:5432/aegis?sslmode=disable"
	}

	log.Printf("[DATABASE] Attempting connection to PostgreSQL...")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("[DATABASE WARNING] Failed to initialize PostgreSQL driver: %v. Falling back to In-Memory mode.", err)
		UsePostgres = false
		return
	}

	// Set connection timeouts
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Ping database to verify connection
	err = db.Ping()
	if err != nil {
		log.Printf("[DATABASE WARNING] PostgreSQL is offline or unreachable: %v. Falling back to In-Memory mode.", err)
		UsePostgres = false
		return
	}

	SQL = db
	UsePostgres = true
	log.Printf("[DATABASE] Connected to PostgreSQL successfully! Running migrations...")

	runMigrations()
	seedOperators()
}

func runMigrations() {
	if !UsePostgres {
		return
	}

	// 1. Operators Table
	_, err := SQL.Exec(`
		CREATE TABLE IF NOT EXISTS operators (
			uid VARCHAR(5) PRIMARY KEY,
			username VARCHAR(50) NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (operators): %v", err)
	}

	// 2. OTPs Table
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS otps (
			uid VARCHAR(5) PRIMARY KEY REFERENCES operators(uid) ON DELETE CASCADE,
			token_hash VARCHAR(64) NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (otps): %v", err)
	}

	// 3. Sessions Table (Hardened with Client IP binding to prevent hijacking)
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			session_token VARCHAR(64) PRIMARY KEY,
			uid VARCHAR(5) NOT NULL REFERENCES operators(uid) ON DELETE CASCADE,
			username VARCHAR(50) NOT NULL,
			ip_address VARCHAR(45) NOT NULL DEFAULT '',
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (sessions): %v", err)
	}

	// Dynamic column migration for existing tables
	_, err = SQL.Exec(`
		ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45) NOT NULL DEFAULT ''
	`)
	if err != nil {
		log.Printf("[DATABASE WARNING] Alter table sessions failed (might be ok if using sqlite/older driver): %v", err)
	}

	// 4. Action Logs Table (soc audit log)
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS action_logs (
			id VARCHAR(50) PRIMARY KEY,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			actor VARCHAR(100) NOT NULL,
			action_type VARCHAR(50) NOT NULL,
			target VARCHAR(100) NOT NULL,
			status VARCHAR(20) NOT NULL,
			message TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (action_logs): %v", err)
	}

	log.Printf("[DATABASE] Schema migrations completed successfully.")
}

func seedOperators() {
	if !UsePostgres {
		return
	}

	// Seed operators if table is empty
	var count int
	err := SQL.QueryRow("SELECT COUNT(*) FROM operators").Scan(&count)
	if err != nil {
		log.Printf("[DATABASE ERROR] Failed to check operators count: %v", err)
		return
	}

	if count == 0 {
		log.Printf("[DATABASE] Seeding default operator UIDs...")
		operators := []struct {
			uid      string
			username string
		}{
			{"10001", "admin"},
			{"10002", "sarah"},
			{"10003", "alex"},
		}

		tx, err := SQL.Begin()
		if err != nil {
			log.Printf("[DATABASE ERROR] Failed to begin transaction: %v", err)
			return
		}
		defer tx.Rollback()

		stmt, err := tx.Prepare("INSERT INTO operators(uid, username) VALUES($1, $2)")
		if err != nil {
			log.Printf("[DATABASE ERROR] Failed to prepare statement: %v", err)
			return
		}
		defer stmt.Close()

		for _, op := range operators {
			if _, err := stmt.Exec(op.uid, op.username); err != nil {
				log.Printf("[DATABASE ERROR] Failed to seed operator %s: %v", op.uid, err)
				return
			}
		}

		if err := tx.Commit(); err != nil {
			log.Printf("[DATABASE ERROR] Failed to commit operator seeds: %v", err)
			return
		}
		log.Printf("[DATABASE] Operator seeding completed.")
	}
}

// SQL OTP Store Helpers
func SaveSQLOTP(uid string, token string, expiresAt time.Time) error {
	_, err := SQL.Exec(`
		INSERT INTO otps(uid, token_hash, expires_at) 
		VALUES($1, $2, $3)
		ON CONFLICT (uid) DO UPDATE 
		SET token_hash = EXCLUDED.token_hash, expires_at = EXCLUDED.expires_at
	`, uid, token, expiresAt)
	return err
}

func GetSQLOTP(uid string) (string, time.Time, error) {
	var token string
	var expiresAt time.Time
	err := SQL.QueryRow("SELECT token_hash, expires_at FROM otps WHERE uid = $1", uid).Scan(&token, &expiresAt)
	return token, expiresAt, err
}

func DeleteSQLOTP(uid string) error {
	_, err := SQL.Exec("DELETE FROM otps WHERE uid = $1", uid)
	return err
}

// SQL Session Store Helpers
func SaveSQLSession(sessionToken string, uid string, username string, ipAddress string, expiresAt time.Time) error {
	_, err := SQL.Exec(`
		INSERT INTO sessions(session_token, uid, username, ip_address, expires_at) 
		VALUES($1, $2, $3, $4, $5)
	`, sessionToken, uid, username, ipAddress, expiresAt)
	return err
}

func GetSQLSession(sessionToken string) (string, string, string, time.Time, error) {
	var uid string
	var username string
	var ipAddress string
	var expiresAt time.Time
	err := SQL.QueryRow("SELECT uid, username, ip_address, expires_at FROM sessions WHERE session_token = $1", sessionToken).Scan(&uid, &username, &ipAddress, &expiresAt)
	return uid, username, ipAddress, expiresAt, err
}

func DeleteSQLSession(sessionToken string) error {
	_, err := SQL.Exec("DELETE FROM sessions WHERE session_token = $1", sessionToken)
	return err
}

func CleanExpiredSQLSessions() {
	if !UsePostgres {
		return
	}
	_, err := SQL.Exec("DELETE FROM sessions WHERE expires_at < $1", time.Now())
	if err != nil {
		log.Printf("[DATABASE ERROR] Failed to clean expired sessions: %v", err)
	}
}
