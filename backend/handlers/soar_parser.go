package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SoarDecisionPayload maps the littleboy.soc.layer2.orchestrator_decision.v7 schema
type SoarDecisionPayload struct {
	SchemaVersion string `json:"schema_version"`
	Timestamp     string `json:"timestamp"`
	InputSummary  struct {
		IncidentID string `json:"incident_id"`
	} `json:"input_summary"`
	VerifiedCase struct {
		ThreatConfirmed bool   `json:"threat_confirmed"`
		Title           string `json:"title"`
		Summary         string `json:"summary"`
		Entities        struct {
			Users          []string `json:"users"`
			AccountsMasked []string `json:"accounts_masked"`
			Hosts          []string `json:"hosts"`
			IPs            []string `json:"ips"`
		} `json:"entities"`
	} `json:"verified_case"`
	Scoring struct {
		FinalRiskScore float64 `json:"final_risk_score_0_10"`
		Priority       string  `json:"priority"`
	} `json:"scoring"`
	Decision struct {
		FinalDecision string `json:"final_decision"`
		Justification string `json:"justification"`
	} `json:"decision"`
	Actions []struct {
		ActionID   string `json:"action_id"`
		ActionType string `json:"action_type"`
		Phase      string `json:"phase"`
		Status     string `json:"status"`
		Rationale  string `json:"rationale"`
		Target     struct {
			Type        string `json:"type"`
			ValueMasked string `json:"value_masked"`
		} `json:"target"`
	} `json:"actions"`
}

// ParsedSoarInfo represents the key security details extracted from the L2 payload
type ParsedSoarInfo struct {
	AttackType      string  `json:"attack_type"`
	SourceIP        string  `json:"source_ip"`
	AffectedAccount string  `json:"affected_account"`
	Severity        string  `json:"severity"`
	IncidentID      string  `json:"incident_id"`
	RiskScore       float64 `json:"risk_score"`
	ThreatConfirmed bool    `json:"threat_confirmed"`
}

// ParseSoarDecision decodes the v7 JSON decision payload and extracts key threat indicators safely
func ParseSoarDecision(payload []byte) (*SoarDecisionPayload, *ParsedSoarInfo, error) {
	var dec SoarDecisionPayload
	if err := json.Unmarshal(payload, &dec); err != nil {
		return nil, nil, fmt.Errorf("JSON decoding error: %w", err)
	}

	if dec.SchemaVersion != "littleboy.soc.layer2.orchestrator_decision.v7" && dec.SchemaVersion != "littleboy.soc.layer2.orchestrator_decision.v8" {
		return nil, nil, fmt.Errorf("unsupported schema version: expected v7 or v8, got %s", dec.SchemaVersion)
	}

	info := &ParsedSoarInfo{
		AttackType:      dec.VerifiedCase.Title,
		SourceIP:        "127.0.0.1",
		AffectedAccount: "N/A",
		Severity:        dec.Scoring.Priority,
		IncidentID:      dec.InputSummary.IncidentID,
		RiskScore:       dec.Scoring.FinalRiskScore,
		ThreatConfirmed: dec.VerifiedCase.ThreatConfirmed,
	}

	// 1. Fallback for AttackType if empty
	if info.AttackType == "" {
		info.AttackType = "Unknown SOAR Security Threat"
	}

	// 2. Extract Source IP from Entities
	if len(dec.VerifiedCase.Entities.IPs) > 0 {
		info.SourceIP = dec.VerifiedCase.Entities.IPs[0]
	}

	// 3. Extract Affected Account from Entities
	var accounts []string
	if len(dec.VerifiedCase.Entities.AccountsMasked) > 0 {
		accounts = append(accounts, dec.VerifiedCase.Entities.AccountsMasked...)
	}
	if len(dec.VerifiedCase.Entities.Users) > 0 {
		accounts = append(accounts, dec.VerifiedCase.Entities.Users...)
	}
	if len(accounts) > 0 {
		info.AffectedAccount = strings.Join(accounts, ", ")
	}

	// 4. Normalize Severity
	if info.Severity == "" {
		if info.RiskScore >= 9.0 {
			info.Severity = "critical"
		} else if info.RiskScore >= 7.0 {
			info.Severity = "high"
		} else if info.RiskScore >= 4.0 {
			info.Severity = "medium"
		} else {
			info.Severity = "low"
		}
	} else {
		info.Severity = strings.ToLower(info.Severity)
		// Ensure it conforms to standard low/medium/high/critical
		if info.Severity == "severe" {
			info.Severity = "critical"
		} else if info.Severity == "elevated" {
			info.Severity = "high"
		}
	}

	return &dec, info, nil
}
