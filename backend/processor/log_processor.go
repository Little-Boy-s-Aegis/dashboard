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
	brokers := os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	if brokers == "" {
		brokers = "localhost:9094"
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
		StartOffset:    kafka.LastOffset,
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

	// Append log entry
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

		db.Alerts = append(db.Alerts, &models.Alert{
			ID:             alertID,
			RuleID:         fmt.Sprintf("rule-siem-%s", logEntry.ID[len(logEntry.ID)-4:]),
			Severity:       "critical",
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

		// Trim alerts
		if len(db.Alerts) > 100 {
			db.Alerts = db.Alerts[len(db.Alerts)-100:]
		}
	}
}
