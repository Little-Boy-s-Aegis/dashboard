package processor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"

	"github.com/segmentio/kafka-go"
)

var (
	// Regex patterns for threat detection
	chatMLRegex        = regexp.MustCompile(`<\|.*?\|>`)
	llamaTagsRegex     = regexp.MustCompile(`(?i)\[/?INST\]|\[/?SYS\]|<<SYS>>`)
	xmlFramingRegex    = regexp.MustCompile(`(?i)<system>.*?</system>|<system>|sys-prompt`)
	overrideRegex      = regexp.MustCompile(`(?i)\b(ignore|forget|override|reset|clear)\b`)
	hijackRegex        = regexp.MustCompile(`(?i)\b(you\s+are\s+now|act\s+as|simulate|roleplay)\b`)
	forcingRegex       = regexp.MustCompile(`(?i)\b(output\s+only|print\s+only|only\s+respond)\b`)
	deactivateRegex    = regexp.MustCompile(`(?i)\b(threat_detected\s*:\s*false|confidence_score\s*:\s*0)\b`)
	codeBlockRegex     = regexp.MustCompile("(?s)```[a-zA-Z]*\\n.*")
	jsonEscapingRegex  = regexp.MustCompile(`[^\\]"|[^\\]'`)
	jndiLog4jRegex     = regexp.MustCompile(`(?i)\$\{jndi:[a-zA-Z0-9]+://.*?\}|\$\{[a-zA-Z:]+\}`)

	// Deduplication cache
	dedupCache = make(map[string]time.Time)
	dedupMu    sync.Mutex
)

// StartLogProcessor listens concurrently to L0 raw log topics, processes them, enriches them,
// writes to L2 clean topics, and pushes to dashboard memory store.
func StartLogProcessor(ctx context.Context) {
	brokers := os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	if brokers == "" {
		brokers = "localhost:9094"
	}
	brokerList := strings.Split(brokers, ",")

	// Start consumers for each L0 topic
	go consumeTopic(ctx, brokerList, "l0.input.apigw", "apigw")
	go consumeTopic(ctx, brokerList, "l0.input.waf", "waf")
	go consumeTopic(ctx, brokerList, "l0.input.ebanking-app", "app")

	log.Printf("[Log Processor] Active on brokers=%s", brokers)
}

func consumeTopic(ctx context.Context, brokers []string, topic string, facility string) {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		GroupID:        "aegis-log-processor-" + facility,
		MinBytes:       1,
		MaxBytes:       10e6,
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
	})
	defer reader.Close()

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers:  brokers,
		Topic:    "l2.verification.clean-log",
		Balancer: &kafka.LeastBytes{},
	})
	defer writer.Close()

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

			// Process and normalize the record
			normalized := processRawMessage(msg.Value, facility)
			if normalized == nil {
				// Dropped as noise
				continue
			}

			// Forward normalized log to L2 Clean Log topic
			cleanJSON, err := json.Marshal(normalized)
			if err == nil {
				_ = writer.WriteMessages(ctx, kafka.Message{
					Value: cleanJSON,
				})
			}

			// Push to Dashboard Store
			pushToDashboardStore(normalized)
		}
	}
}

func processRawMessage(rawData []byte, facility string) *models.LogEntry {
	// Parse raw input message from Fluent Bit
	var fluentRecord map[string]interface{}
	if err := json.Unmarshal(rawData, &fluentRecord); err != nil {
		return nil
	}

	rawPayload := ""
	clientIP := "127.0.0.1"
	agentName := "NginxGateway"
	agentID := "agent-01"
	statusCode := 0

	if facility == "apigw" || facility == "waf" {
		rawPayload = getString(fluentRecord["path"])
		clientIP = getString(fluentRecord["remote"])
		agentName = "NginxGateway"
		agentID = "agent-gateway"
		statusCode = getInt(fluentRecord["code"])
	} else if facility == "app" {
		rawPayload = getString(fluentRecord["log"])
		clientIP = "127.0.0.1"
		agentName = "Web-Prod-01"
		agentID = "agent-01"
	}

	if rawPayload == "" {
		return nil
	}

	// 1. Noise Filter: Drop static asset requests for Nginx gateway
	if facility == "apigw" {
		pathLower := strings.ToLower(rawPayload)
		if strings.HasSuffix(pathLower, ".css") || strings.HasSuffix(pathLower, ".js") ||
			strings.HasSuffix(pathLower, ".png") || strings.HasSuffix(pathLower, ".jpg") ||
			strings.HasSuffix(pathLower, ".ico") || strings.HasSuffix(pathLower, ".woff") ||
			strings.HasSuffix(pathLower, ".svg") {
			return nil // Drop static asset requests (Noise)
		}
	}

	// Deduplication: Drop repeating log messages within 3 seconds
	if isDuplicate(rawPayload) {
		return nil
	}

	// 2. Decode & Deobfuscate
	decodedPayload := rawPayload
	decodedPayload = tryURLDecode(decodedPayload)
	decodedPayload = tryBase64Decode(decodedPayload)

	// 3. CAP Lines / Truncation (Max 200 characters)
	displayMessage := decodedPayload
	if len(displayMessage) > 200 {
		displayMessage = displayMessage[:197] + "..."
	}

	// 4. Standardize Timestamps to UTC
	utcTime := time.Now().UTC()

	// 5. Context Enrichment: GeoIP & ASN
	geoIP, asn := lookupGeoIP(clientIP)

	// Context: Asset Criticality
	criticality := "LOW"
	if strings.Contains(decodedPayload, "/api/auth") || strings.Contains(decodedPayload, "/api-bank") || strings.Contains(decodedPayload, "/api/transactions") {
		criticality = "HIGH"
	} else if strings.Contains(decodedPayload, "/api/alerts") || strings.Contains(decodedPayload, "/api/fim") {
		criticality = "MEDIUM"
	}

	// Context: Threat checks
	threatFlagged, threatType, _ := scanForThreats(decodedPayload)

	// 6. Build Clean Log Entry
	severity := "info"
	if threatFlagged {
		severity = "alert"
	} else if facility == "waf" || statusCode >= 500 {
		severity = "error"
	} else if statusCode >= 400 {
		severity = "warning"
	}

	logID := fmt.Sprintf("log-%d-%s", time.Now().UnixNano(), agentID[:2])

	return &models.LogEntry{
		ID:             logID,
		Timestamp:      utcTime,
		AgentID:        agentID,
		AgentName:      agentName,
		Facility:       facility,
		Severity:       severity,
		Message:        displayMessage,
		SourceIP:       clientIP,
		StatusCode:     statusCode,
		GeoIP:          geoIP,
		ASN:            asn,
		AssetCritical:  criticality,
		ThreatFlagged:  threatFlagged,
		ThreatType:     threatType,
		DecodedPayload: decodedPayload,
	}
}

func isDuplicate(payload string) bool {
	dedupMu.Lock()
	defer dedupMu.Unlock()

	now := time.Now()
	if lastSeen, found := dedupCache[payload]; found {
		if now.Sub(lastSeen) < 3*time.Second {
			return true
		}
	}
	dedupCache[payload] = now
	return false
}

func tryURLDecode(val string) string {
	decoded, err := url.QueryUnescape(val)
	if err == nil {
		return decoded
	}
	return val
}

func tryBase64Decode(val string) string {
	// Simple scan for Base64-like blocks
	b64Regex := regexp.MustCompile(`[a-zA-Z0-9+/]{8,}=*`)
	return b64Regex.ReplaceAllStringFunc(val, func(m string) string {
		data, err := base64.StdEncoding.DecodeString(m)
		if err == nil {
			// Ensure decoded content is readable ascii text
			isText := true
			for _, b := range data {
				if b < 32 && b != 9 && b != 10 && b != 13 {
					isText = false
					break
				}
			}
			if isText {
				return string(data)
			}
		}
		return m
	})
}

func lookupGeoIP(ip string) (string, string) {
	if ip == "127.0.0.1" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "10.") {
		return "Private Network", "LAN/RFC1918"
	}
	// Mock public GeoIP / ASN mapping
	switch {
	case strings.HasPrefix(ip, "198.51.100."):
		return "US (United States)", "AS15133 MCI Communications Services"
	case strings.HasPrefix(ip, "203.0.113."):
		return "VN (Vietnam)", "AS45899 Viettel Corporation"
	case strings.HasPrefix(ip, "185.190.140."):
		return "RU (Russian Federation)", "AS200593 Russia Broadband"
	default:
		return "US (United States)", "AS16509 Amazon.com, Inc."
	}
}

func scanForThreats(payload string) (bool, string, string) {
	if chatMLRegex.MatchString(payload) {
		return true, "CHATML_TOKEN_INJECTION", "ChatML boundaries detected"
	}
	if llamaTagsRegex.MatchString(payload) {
		return true, "LLM_TAG_INJECTION", "LLM framework syntax detected"
	}
	if xmlFramingRegex.MatchString(payload) {
		return true, "SYSTEM_FRAMING_INJECTION", "System/XML block framing detected"
	}
	if overrideRegex.MatchString(payload) {
		return true, "INSTRUCTION_OVERRIDE", "Adversarial override directive detected"
	}
	if hijackRegex.MatchString(payload) {
		return true, "PERSONA_HIJACKING", "Persona hijack command detected"
	}
	if forcingRegex.MatchString(payload) {
		return true, "OUTPUT_FORCING", "LLM Output formatting constraint detected"
	}
	if deactivateRegex.MatchString(payload) {
		return true, "SYSTEM_DEACTIVATION", "Attempted security bypass detected"
	}
	if codeBlockRegex.MatchString(payload) {
		return true, "MARKDOWN_CODE_BLOCK", "Inline code block injection detected"
	}
	if jsonEscapingRegex.MatchString(payload) {
		return true, "JSON_ESCAPING", "Escape sequences matching parser injection detected"
	}
	if jndiLog4jRegex.MatchString(payload) {
		return true, "JNDI_LOG4J_LOOKUP", "JNDI/Log4j exploit payload detected"
	}
	return false, "", ""
}

func pushToDashboardStore(logEntry *models.LogEntry) {
	db := store.DB
	db.Mu.Lock()
	defer db.Mu.Unlock()

	// Append log entry
	db.LogCounter++
	db.Logs = append(db.Logs, logEntry)

	// If old data grows, trim it
	if len(db.Logs) > 500 {
		db.Logs = db.Logs[len(db.Logs)-500:]
	}

	// Create SIEM Alert if threat was flagged
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

// Helpers
func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func getInt(v interface{}) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	if i, ok := v.(int); ok {
		return i
	}
	return 0
}
