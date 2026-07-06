package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"

	"github.com/segmentio/kafka-go"
)

// SecurityEvent represents the Kafka message published by the Banking Backend.
type SecurityEvent struct {
	EventID       string `json:"eventId"`
	Timestamp     string `json:"timestamp"`
	AttackType    string `json:"attackType"`
	Endpoint      string `json:"endpoint"`
	Payload       string `json:"payload"`
	Status        string `json:"status"`
	ClientIP      string `json:"clientIp"`
	Description   string `json:"description"`
	SourceService string `json:"sourceService"`
}

// StartKafkaConsumer launches a goroutine that reads from the
// "aegis.security.events" Kafka topic and converts each message
// into an Alert + LogEntry in the SOC Dashboard's in-memory store.
func StartKafkaConsumer(ctx context.Context) {
	brokers := os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	if brokers == "" {
		brokers = "localhost:9094"
	}

	topic := "aegis.security.events"
	groupID := "aegis-soc-dashboard"

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        strings.Split(brokers, ","),
		Topic:          topic,
		GroupID:        groupID,
		MinBytes:       1,
		MaxBytes:       10e6,
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
	})

	log.Printf("[Kafka Consumer] Connected to brokers=%s topic=%s group=%s", brokers, topic, groupID)

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Println("[Kafka Consumer] Shutting down...")
				reader.Close()
				return
			default:
				msg, err := reader.ReadMessage(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("[Kafka Consumer] Read error (will retry): %v", err)
					time.Sleep(2 * time.Second)
					continue
				}

				var event SecurityEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					log.Printf("[Kafka Consumer] Failed to unmarshal message: %v", err)
					continue
				}

				ingestSecurityEvent(&event)
				log.Printf("[Kafka Consumer] Ingested event [%s] type=%s from %s",
					event.EventID, event.AttackType, event.SourceService)
			}
		}
	}()
}

// ingestSecurityEvent converts a Kafka SecurityEvent into an Alert and LogEntry,
// mirroring the logic from store.syncBankSecurityLogs but driven by Kafka events.
func ingestSecurityEvent(event *SecurityEvent) {
	db := store.DB
	db.Mu.Lock()
	defer db.Mu.Unlock()

	// Map attack type to MITRE ATT&CK
	mitreTech := "T1190"
	mitreTactics := []string{"Initial Access"}
	severity := "high"

	if strings.ToUpper(event.Status) == "ALLOWED" {
		severity = "critical"
	}

	switch strings.ToUpper(event.AttackType) {
	case "SQL_INJECTION":
		mitreTech = "T1190"
		mitreTactics = []string{"Initial Access"}
	case "XSS":
		mitreTech = "T1189"
		mitreTactics = []string{"Initial Access"}
	case "IDOR/BOLA":
		mitreTech = "T1068"
		mitreTactics = []string{"Privilege Escalation"}
	case "PARAMETER_TAMPERING":
		mitreTech = "T1565.002"
		mitreTactics = []string{"Impact"}
	case "BRUTE_FORCE":
		mitreTech = "T1110"
		mitreTactics = []string{"Credential Access"}
	}

	// Create Alert
	db.AlertCounter++
	alertID := fmt.Sprintf("alt-%04d", db.AlertCounter)

	agent := db.Agents["agent-01"]
	if agent != nil {
		agent.Status = "alerting"
		db.SaveAgent(agent)
	}

	db.AddAlert(&models.Alert{
		ID:             alertID,
		RuleID:         fmt.Sprintf("rule-kafka-%s", event.EventID[:8]),
		Severity:       severity,
		Title:          fmt.Sprintf("Aegis Bank - %s Detected", event.AttackType),
		Description:    event.Description,
		AgentID:        "agent-01",
		AgentName:      "Web-Prod-01",
		MITRETechnique: mitreTech,
		MITRETactics:   mitreTactics,
		Category:       "web",
		Timestamp:      time.Now(),
		RawLog:         fmt.Sprintf(`{"eventId":"%s","timestamp":"%s","attack_type":"%s","endpoint":"%s","payload":"%s","status":"%s","client_ip":"%s","description":"%s","source":"%s"}`, event.EventID, event.Timestamp, event.AttackType, event.Endpoint, event.Payload, event.Status, event.ClientIP, event.Description, event.SourceService),
		Status:         "open",
	})

	// Create Log Entry
	db.LogCounter++
	db.AddLog(&models.LogEntry{
		ID:        fmt.Sprintf("log-%05d", db.LogCounter),
		Timestamp: time.Now(),
		AgentID:   "agent-01",
		AgentName: "Web-Prod-01",
		Facility:  "web",
		Severity:  severity,
		Message:   fmt.Sprintf("[KAFKA] BANK SECURITY ALARM: %s payload detected on %s from IP %s. Status: %s. Detail: %s", event.AttackType, event.Endpoint, event.ClientIP, event.Status, event.Description),
		SourceIP:  event.ClientIP,
	})

	// Trim old data
	if len(db.Logs) > 500 {
		db.Logs = db.Logs[len(db.Logs)-500:]
	}
}
