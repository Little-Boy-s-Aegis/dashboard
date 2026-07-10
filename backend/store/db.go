package store

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"time"

	"dashboard/backend/models"
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
		host := os.Getenv("DB_HOST")
		user := os.Getenv("DB_USER")
		pass := os.Getenv("DB_PASSWORD")
		name := os.Getenv("DB_NAME")
		port := os.Getenv("DB_PORT")
		if port == "" {
			port = "5432"
		}
		if host != "" && user != "" && name != "" {
			dsn = "host=" + host + " port=" + port + " user=" + user + " password='" + pass + "' dbname=" + name + " sslmode=require"
		} else {
			// Fallback to default local postgres credentials
			dsn = "host=localhost port=5432 user=postgres password=1 dbname=aegis sslmode=disable"
		}
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
	DB.persistSeed()
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

	// 5. Agents Table
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS agents (
			id VARCHAR(50) PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			ip VARCHAR(45) NOT NULL,
			os VARCHAR(100) NOT NULL,
			status VARCHAR(20) NOT NULL,
			cpu_usage DOUBLE PRECISION NOT NULL,
			ram_usage DOUBLE PRECISION NOT NULL,
			disk_usage DOUBLE PRECISION NOT NULL,
			network_in DOUBLE PRECISION NOT NULL,
			network_out DOUBLE PRECISION NOT NULL,
			threat_score INT NOT NULL DEFAULT 0,
			last_seen TIMESTAMP WITH TIME ZONE NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (agents): %v", err)
	}

	// 6. Log Entries Table (ECS Compliant)
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS log_entries (
			id VARCHAR(50) PRIMARY KEY,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			agent_id VARCHAR(50) NOT NULL,
			agent_name VARCHAR(100) NOT NULL,
			facility VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			message TEXT NOT NULL,
			source_ip VARCHAR(45) NOT NULL,
			status_code INT NOT NULL,
			geo_ip VARCHAR(100) NOT NULL,
			asn VARCHAR(200) NOT NULL,
			asset_critical VARCHAR(20) NOT NULL,
			threat_flagged BOOLEAN NOT NULL DEFAULT FALSE,
			threat_type VARCHAR(100),
			decoded_payload TEXT,
			ecs_timestamp VARCHAR(100),
			ecs_log_level VARCHAR(20),
			ecs_event_dataset VARCHAR(100),
			ecs_event_id VARCHAR(50),
			ecs_source_ip VARCHAR(45),
			ecs_http_status INT,
			ecs_geo_country VARCHAR(100),
			ecs_asn_name VARCHAR(200),
			ecs_service_name VARCHAR(100),
			ecs_url_original TEXT,
			ecs_agent_id VARCHAR(50),
			ecs_agent_name VARCHAR(100),
			ecs_agent_type VARCHAR(50),
			ecs_event_category TEXT,
			ecs_event_kind VARCHAR(50),
			ecs_event_outcome VARCHAR(50)
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (log_entries): %v", err)
	}

	// 7. Alerts Table
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS alerts (
			id VARCHAR(50) PRIMARY KEY,
			rule_id VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			title VARCHAR(200) NOT NULL,
			description TEXT NOT NULL,
			agent_id VARCHAR(50) NOT NULL,
			agent_name VARCHAR(100) NOT NULL,
			mitre_technique VARCHAR(50) NOT NULL,
			mitre_tactics TEXT NOT NULL,
			category VARCHAR(50) NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			raw_log TEXT NOT NULL,
			status VARCHAR(20) NOT NULL,
			assignee VARCHAR(100) NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (alerts): %v", err)
	}

	// 8. FIM Events Table
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS fim_events (
			id VARCHAR(50) PRIMARY KEY,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			agent_id VARCHAR(50) NOT NULL,
			agent_name VARCHAR(100) NOT NULL,
			file_path TEXT NOT NULL,
			event_type VARCHAR(20) NOT NULL,
			size BIGINT NOT NULL,
			md5 VARCHAR(32) NOT NULL,
			sha256 VARCHAR(64) NOT NULL,
			user_name VARCHAR(100) NOT NULL,
			process_name VARCHAR(100) NOT NULL
		)
	`)
	// 9. Database Performance Indexes for Metadata Query Optimization
	_, err = SQL.Exec(`
		-- Indexes for Agents
		CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);

		-- Indexes for Log Entries
		CREATE INDEX IF NOT EXISTS idx_log_entries_agent_id ON log_entries(agent_id);
		CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_log_entries_severity ON log_entries(severity);
		CREATE INDEX IF NOT EXISTS idx_log_entries_threat_flagged ON log_entries(threat_flagged);

		-- Indexes for Alerts
		CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id);
		CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
		CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);

		-- Indexes for FIM Events
		CREATE INDEX IF NOT EXISTS idx_fim_events_agent_id_timestamp ON fim_events(agent_id, timestamp DESC);
	`)
	if err != nil {
		log.Fatalf("Migration failed (indexes): %v", err)
	}

	// 10. System Settings Table
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS system_settings (
			key VARCHAR(100) PRIMARY KEY,
			value VARCHAR(255) NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (system_settings): %v", err)
	}

	// Seed default autopilot setting
	_, err = SQL.Exec(`
		INSERT INTO system_settings (key, value)
		VALUES ('soc_autopilot_enabled', 'false')
		ON CONFLICT (key) DO NOTHING
	`)
	if err != nil {
		log.Printf("[DATABASE WARNING] Failed to seed default system settings: %v", err)
	}

	// 11. Banned IPs Table
	_, err = SQL.Exec(`
		CREATE TABLE IF NOT EXISTS banned_ips (
			ip_address VARCHAR(45) PRIMARY KEY,
			banned_at TIMESTAMP WITH TIME ZONE NOT NULL,
			banned_by VARCHAR(100) NOT NULL,
			status VARCHAR(20) NOT NULL,
			reason TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatalf("Migration failed (banned_ips): %v", err)
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

// SQL Persistence Save Helpers
func SaveSQLAgent(agent *models.Agent) error {
	if !UsePostgres {
		return nil
	}
	_, err := SQL.Exec(`
		INSERT INTO agents(id, name, ip, os, status, cpu_usage, ram_usage, disk_usage, network_in, network_out, threat_score, last_seen)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO UPDATE
		SET name = EXCLUDED.name, ip = EXCLUDED.ip, os = EXCLUDED.os, status = EXCLUDED.status,
			cpu_usage = EXCLUDED.cpu_usage, ram_usage = EXCLUDED.ram_usage, disk_usage = EXCLUDED.disk_usage,
			network_in = EXCLUDED.network_in, network_out = EXCLUDED.network_out, threat_score = EXCLUDED.threat_score,
			last_seen = EXCLUDED.last_seen
	`, agent.ID, agent.Name, agent.IP, agent.OS, agent.Status, agent.CPUUsage, agent.RAMUsage, agent.DiskUsage, agent.NetworkIn, agent.NetworkOut, agent.ThreatScore, agent.LastSeen)
	return err
}

func SaveSQLLogEntry(logEntry *models.LogEntry) error {
	if !UsePostgres {
		return nil
	}
	var catStr string
	if len(logEntry.ECSEventCat) > 0 {
		catStr = strings.Join(logEntry.ECSEventCat, ",")
	}
	_, err := SQL.Exec(`
		INSERT INTO log_entries(id, timestamp, agent_id, agent_name, facility, severity, message, source_ip, status_code, geo_ip, asn, asset_critical, threat_flagged, threat_type, decoded_payload, ecs_timestamp, ecs_log_level, ecs_event_dataset, ecs_event_id, ecs_source_ip, ecs_http_status, ecs_geo_country, ecs_asn_name, ecs_service_name, ecs_url_original, ecs_agent_id, ecs_agent_name, ecs_agent_type, ecs_event_category, ecs_event_kind, ecs_event_outcome)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)
		ON CONFLICT (id) DO NOTHING
	`, logEntry.ID, logEntry.Timestamp, logEntry.AgentID, logEntry.AgentName, logEntry.Facility, logEntry.Severity, logEntry.Message, logEntry.SourceIP, logEntry.StatusCode, logEntry.GeoIP, logEntry.ASN, logEntry.AssetCritical, logEntry.ThreatFlagged, logEntry.ThreatType, logEntry.DecodedPayload, logEntry.ECSTimestamp, logEntry.ECSLogLevel, logEntry.ECSEventDataset, logEntry.ECSEventID, logEntry.ECSSourceIP, logEntry.ECSHTTPStatus, logEntry.ECSGeoCountry, logEntry.ECSASNName, logEntry.ECSServiceName, logEntry.ECSURLOriginal, logEntry.ECSAgentID, logEntry.ECSAgentName, logEntry.ECSAgentType, catStr, logEntry.ECSEventKind, logEntry.ECSEventOutcome)
	return err
}

func SaveSQLAlert(alert *models.Alert) error {
	if !UsePostgres {
		return nil
	}
	tacsStr := strings.Join(alert.MITRETactics, ",")
	_, err := SQL.Exec(`
		INSERT INTO alerts(id, rule_id, severity, title, description, agent_id, agent_name, mitre_technique, mitre_tactics, category, timestamp, raw_log, status, assignee)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE
		SET severity = EXCLUDED.severity,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			mitre_technique = EXCLUDED.mitre_technique,
			mitre_tactics = EXCLUDED.mitre_tactics,
			category = EXCLUDED.category,
			timestamp = EXCLUDED.timestamp,
			raw_log = EXCLUDED.raw_log,
			status = EXCLUDED.status,
			assignee = EXCLUDED.assignee
	`, alert.ID, alert.RuleID, alert.Severity, alert.Title, alert.Description, alert.AgentID, alert.AgentName, alert.MITRETechnique, tacsStr, alert.Category, alert.Timestamp, alert.RawLog, alert.Status, alert.Assignee)
	return err
}

func SaveSQLFIMEvent(fim *models.FIMEvent) error {
	if !UsePostgres {
		return nil
	}
	_, err := SQL.Exec(`
		INSERT INTO fim_events(id, timestamp, agent_id, agent_name, file_path, event_type, size, md5, sha256, user_name, process_name)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO NOTHING
	`, fim.ID, fim.Timestamp, fim.AgentID, fim.AgentName, fim.FilePath, fim.EventType, fim.Size, fim.MD5, fim.SHA256, fim.User, fim.Process)
	return err
}

// SQL Persistence Load Helpers
func LoadSQLAgents() (map[string]*models.Agent, error) {
	rows, err := SQL.Query("SELECT id, name, ip, os, status, cpu_usage, ram_usage, disk_usage, network_in, network_out, threat_score, last_seen FROM agents")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agents := make(map[string]*models.Agent)
	for rows.Next() {
		var a models.Agent
		err := rows.Scan(&a.ID, &a.Name, &a.IP, &a.OS, &a.Status, &a.CPUUsage, &a.RAMUsage, &a.DiskUsage, &a.NetworkIn, &a.NetworkOut, &a.ThreatScore, &a.LastSeen)
		if err != nil {
			return nil, err
		}
		agents[a.ID] = &a
	}
	return agents, nil
}

func LoadSQLAlerts() ([]*models.Alert, error) {
	rows, err := SQL.Query("SELECT id, rule_id, severity, title, description, agent_id, agent_name, mitre_technique, mitre_tactics, category, timestamp, raw_log, status, assignee FROM alerts ORDER BY timestamp ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		var a models.Alert
		var tacsStr string
		err := rows.Scan(&a.ID, &a.RuleID, &a.Severity, &a.Title, &a.Description, &a.AgentID, &a.AgentName, &a.MITRETechnique, &tacsStr, &a.Category, &a.Timestamp, &a.RawLog, &a.Status, &a.Assignee)
		if err != nil {
			return nil, err
		}
		if tacsStr != "" {
			a.MITRETactics = strings.Split(tacsStr, ",")
		} else {
			a.MITRETactics = []string{}
		}
		alerts = append(alerts, &a)
	}
	return alerts, nil
}

func LoadSQLFIMEvents() ([]*models.FIMEvent, error) {
	rows, err := SQL.Query("SELECT id, timestamp, agent_id, agent_name, file_path, event_type, size, md5, sha256, user_name, process_name FROM fim_events ORDER BY timestamp ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.FIMEvent
	for rows.Next() {
		var f models.FIMEvent
		err := rows.Scan(&f.ID, &f.Timestamp, &f.AgentID, &f.AgentName, &f.FilePath, &f.EventType, &f.Size, &f.MD5, &f.SHA256, &f.User, &f.Process)
		if err != nil {
			return nil, err
		}
		events = append(events, &f)
	}
	return events, nil
}

func LoadSQLLogEntries() ([]*models.LogEntry, error) {
	rows, err := SQL.Query("SELECT id, timestamp, agent_id, agent_name, facility, severity, message, source_ip, status_code, geo_ip, asn, asset_critical, threat_flagged, threat_type, decoded_payload, ecs_timestamp, ecs_log_level, ecs_event_dataset, ecs_event_id, ecs_source_ip, ecs_http_status, ecs_geo_country, ecs_asn_name, ecs_service_name, ecs_url_original, ecs_agent_id, ecs_agent_name, ecs_agent_type, ecs_event_category, ecs_event_kind, ecs_event_outcome FROM log_entries ORDER BY timestamp ASC LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*models.LogEntry
	for rows.Next() {
		var l models.LogEntry
		var catStr string
		err := rows.Scan(&l.ID, &l.Timestamp, &l.AgentID, &l.AgentName, &l.Facility, &l.Severity, &l.Message, &l.SourceIP, &l.StatusCode, &l.GeoIP, &l.ASN, &l.AssetCritical, &l.ThreatFlagged, &l.ThreatType, &l.DecodedPayload, &l.ECSTimestamp, &l.ECSLogLevel, &l.ECSEventDataset, &l.ECSEventID, &l.ECSSourceIP, &l.ECSHTTPStatus, &l.ECSGeoCountry, &l.ECSASNName, &l.ECSServiceName, &l.ECSURLOriginal, &l.ECSAgentID, &l.ECSAgentName, &l.ECSAgentType, &catStr, &l.ECSEventKind, &l.ECSEventOutcome)
		if err != nil {
			return nil, err
		}
		if catStr != "" {
			l.ECSEventCat = strings.Split(catStr, ",")
		} else {
			l.ECSEventCat = []string{}
		}
		logs = append(logs, &l)
	}
	return logs, nil
}

func LoadSQLActionLogs() ([]*models.ActionLog, error) {
	rows, err := SQL.Query("SELECT id, timestamp, actor, action_type, target, status, message FROM action_logs ORDER BY timestamp ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*models.ActionLog
	for rows.Next() {
		var l models.ActionLog
		err := rows.Scan(&l.ID, &l.Timestamp, &l.Actor, &l.ActionType, &l.Target, &l.Status, &l.Message)
		if err != nil {
			return nil, err
		}
		logs = append(logs, &l)
	}
	return logs, nil
}

func SaveSQLBannedIP(ip string, actor string, status string, reason string) {
	if !UsePostgres {
		return
	}
	_, err := SQL.Exec(`
		INSERT INTO banned_ips (ip_address, banned_at, banned_by, status, reason)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (ip_address) DO UPDATE
		SET banned_at = EXCLUDED.banned_at, banned_by = EXCLUDED.banned_by, status = EXCLUDED.status, reason = EXCLUDED.reason
	`, ip, time.Now(), actor, status, reason)
	if err != nil {
		log.Printf("[DATABASE ERROR] Failed to save banned IP: %v", err)
	}
}

func GetSQLBannedIPs() ([]*models.BannedIP, error) {
	if !UsePostgres {
		return []*models.BannedIP{}, nil
	}
	rows, err := SQL.Query("SELECT ip_address, banned_at, banned_by, status, reason FROM banned_ips ORDER BY banned_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.BannedIP
	for rows.Next() {
		var b models.BannedIP
		var ts time.Time
		err := rows.Scan(&b.IPAddress, &ts, &b.BannedBy, &b.Status, &b.Reason)
		if err != nil {
			log.Printf("[DATABASE ERROR] Scan banned IP row failed: %v", err)
			continue
		}
		b.BannedAt = ts
		list = append(list, &b)
	}
	return list, nil
}

func GetSQLSetting(key string) (string, error) {
	if !UsePostgres {
		return "false", nil
	}
	var val string
	err := SQL.QueryRow("SELECT value FROM system_settings WHERE key = $1", key).Scan(&val)
	if err != nil {
		return "", err
	}
	return val, nil
}

func SaveSQLSetting(key string, val string) error {
	if !UsePostgres {
		return nil
	}
	_, err := SQL.Exec(`
		INSERT INTO system_settings (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE
		SET value = EXCLUDED.value
	`, key, val)
	return err
}
