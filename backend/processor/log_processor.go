package processor

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

// StartLogProcessor listens concurrently to the L2 Clean Log topic,
// parses the normalized events, and pushes them to the dashboard store.
func StartLogProcessor(ctx context.Context) {
	brokers := strings.TrimSpace(os.Getenv("KAFKA_BOOTSTRAP_SERVERS"))
	if brokers == "" {
		log.Println("[Log Processor] KAFKA_BOOTSTRAP_SERVERS is not set; L2 clean-log ingestion is disabled.")
		return
	}
	brokerList := strings.Split(brokers, ",")

	go consumeCleanLogs(ctx, brokerList)

	log.Printf("[Log Processor] Ingesting L2 Clean Logs from brokers=%s", brokers)
}

func consumeCleanLogs(ctx context.Context, brokers []string) {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          "l2.verification.clean-log",
		GroupID:        "aegis-clean-log-ingest",
		MinBytes:       1,
		MaxBytes:       10e6,
		CommitInterval: time.Second,
		StartOffset:    kafka.FirstOffset,
	})
	defer reader.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := reader.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(2 * time.Second)
				continue
			}

			var logEntry models.LogEntry
			if err := json.Unmarshal(msg.Value, &logEntry); err != nil {
				log.Printf("[Log Processor ERROR] Failed to unmarshal clean log JSON: %v", err)
				continue
			}

			pushToDashboardStore(&logEntry)
		}
	}
}

func pushToDashboardStore(logEntry *models.LogEntry) {
	db := store.DB
	db.Mu.Lock()
	defer db.Mu.Unlock()

	if !store.ShouldPersistSecurityLog(logEntry) {
		return
	}

	// Append only threat/security log entries. Clean operational logs stay in Kafka/storage,
	// not in the SOC dashboard database.
	db.LogCounter++
	db.AddLog(logEntry)

	// If old data grows, trim it
	if len(db.Logs) > 500 {
		db.Logs = db.Logs[len(db.Logs)-500:]
	}

	// Create SIEM Alert if threat was flagged by L1 Python Parser
	if logEntry.ThreatFlagged {
		db.AlertCounter++
		alertID := fmt.Sprintf("alt-siem-%04d", db.AlertCounter)

		agent := db.Agents[logEntry.AgentID]
		if agent != nil {
			agent.Status = "alerting"
		}

		subID := logEntry.ID
		if len(subID) > 4 {
			subID = subID[len(subID)-4:]
		}

		severity := "critical"
		if logEntry.ThreatType == "JSON_ESCAPING" {
			severity = "low"
		} else {
			switch strings.ToLower(logEntry.Severity) {
			case "alert":
				severity = "critical"
			case "error":
				severity = "high"
			case "warning":
				severity = "medium"
			case "info", "low":
				severity = "low"
			}
		}

		db.AddAlert(&models.Alert{
			ID:             alertID,
			RuleID:         fmt.Sprintf("rule-siem-%s", subID),
			Severity:       severity,
			Title:          fmt.Sprintf("SIEM Filter - %s Detected", logEntry.ThreatType),
			Description:    fmt.Sprintf("An adversarial pattern was detected on service %s from IP %s. Category: %s", logEntry.Facility, logEntry.SourceIP, logEntry.ThreatType),
			AgentID:        logEntry.AgentID,
			AgentName:      logEntry.AgentName,
			MITRETechnique: "T1190",
			MITRETactics:   []string{"Initial Access"},
			Category:       "audit",
			Timestamp:      logEntry.Timestamp,
			RawLog:         logEntry.DecodedPayload,
			Status:         "open",
		})
	}
}
