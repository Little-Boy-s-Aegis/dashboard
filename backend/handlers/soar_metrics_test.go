package handlers

import (
	"testing"
	"time"

	"dashboard/backend/models"
)

func TestComputeSoarResponseTimesUsesOnlyMeasuredIncidentPairs(t *testing.T) {
	base := time.Date(2026, time.August, 12, 4, 0, 0, 0, time.UTC)
	alerts := []*models.Alert{
		{ID: "alt-1001", Timestamp: base},
		{ID: "alt-1002", Timestamp: base.Add(10 * time.Second)},
	}
	actions := []*models.ActionLog{
		{
			ID:        "act-measured-fast",
			Timestamp: base.Add(12340 * time.Millisecond),
			Message:   "Containment complete. (Incident: alert-alt-1001)",
		},
		{
			ID:        "act-unmatched",
			Timestamp: base.Add(2 * time.Second),
			Message:   "Standalone fast-path action without an incident reference",
		},
		{
			ID:        "act-negative-duration",
			Timestamp: base.Add(5 * time.Second),
			Message:   "Containment complete. (Incident: alert-alt-1002)",
		},
		{
			ID:        "act-measured-violation",
			Timestamp: base.Add(55 * time.Second),
			Message:   "Containment complete. (Incident: alert-alt-1002)",
		},
	}

	got := computeSoarResponseTimes(alerts, actions)
	if len(got) != 2 {
		t.Fatalf("expected 2 measured samples, got %d (%v)", len(got), got)
	}
	if got[0] != 12.3 || got[1] != 45.0 {
		t.Fatalf("unexpected measured response times: %v", got)
	}
}

func TestComputeSLAPercentagesUsesExclusiveDistributionBuckets(t *testing.T) {
	under15, between15And30, under30, over30 := computeSLAPercentages([]float64{5, 20, 45})

	if under15 != 33.3 {
		t.Fatalf("expected <15s bucket to be 33.3%%, got %.1f%%", under15)
	}
	if between15And30 != 33.3 {
		t.Fatalf("expected 15-30s bucket to be 33.3%%, got %.1f%%", between15And30)
	}
	if under30 != 66.7 {
		t.Fatalf("expected cumulative <=30s compliance to be 66.7%%, got %.1f%%", under30)
	}
	if over30 != 33.3 {
		t.Fatalf("expected >30s bucket to be 33.3%%, got %.1f%%", over30)
	}
}

func TestComputeSLAPercentagesHasNoSyntheticNoDataCompliance(t *testing.T) {
	under15, between15And30, under30, over30 := computeSLAPercentages(nil)
	if under15 != 0 || between15And30 != 0 || under30 != 0 || over30 != 0 {
		t.Fatalf("expected zero percentages without measured samples, got %.1f %.1f %.1f %.1f",
			under15, between15And30, under30, over30)
	}
}
