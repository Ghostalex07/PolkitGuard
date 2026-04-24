package models

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected string
	}{
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if tt.sev.String() != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.sev.String())
		}
	}
}

func TestSeverityCompare(t *testing.T) {
	if SeverityCritical <= SeverityHigh {
		t.Error("CRITICAL should be > HIGH")
	}
	if SeverityHigh <= SeverityMedium {
		t.Error("HIGH should be > MEDIUM")
	}
}

func TestNewScanResult(t *testing.T) {
	r := NewScanResult()
	if r.Findings == nil {
		t.Error("Expected initialized Findings")
	}
}

func TestAddFinding(t *testing.T) {
	r := NewScanResult()
	f := Finding{Severity: SeverityHigh, File: "/test"}
	r.AddFinding(f)
	if len(r.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(r.Findings))
	}
}

func TestHasCritical(t *testing.T) {
	r := NewScanResult()
	r.AddFinding(Finding{Severity: SeverityCritical})
	if !r.HasCritical() {
		t.Error("Should have critical")
	}
}

func TestHasHigh(t *testing.T) {
	r := NewScanResult()
	r.AddFinding(Finding{Severity: SeverityHigh})
	if !r.HasHigh() {
		t.Error("Should have high")
	}
}

func TestHasMedium(t *testing.T) {
	r := NewScanResult()
	r.AddFinding(Finding{Severity: SeverityMedium})
	if !r.HasMedium() {
		t.Error("Should have medium")
	}
}

func TestGetFindingsByMinSeverity(t *testing.T) {
	r := NewScanResult()
	r.AddFinding(Finding{Severity: SeverityLow})
	r.AddFinding(Finding{Severity: SeverityHigh})
	r.AddFinding(Finding{Severity: SeverityCritical})

	high := r.GetFindingsByMinSeverity(SeverityHigh)
	if len(high) != 2 {
		t.Errorf("Expected 2, got %d", len(high))
	}

	crit := r.GetFindingsByMinSeverity(SeverityCritical)
	if len(crit) != 1 {
		t.Errorf("Expected 1, got %d", len(crit))
	}
}

func TestFindingCalculateScore(t *testing.T) {
	f := Finding{Severity: SeverityCritical, Impact: "test"}
	score := f.CalculateScore()
	if score == 0 {
		t.Error("Expected non-zero score")
	}
}

func TestFindingString(t *testing.T) {
	f := Finding{Severity: SeverityHigh, File: "/test", Message: "msg"}
	s := f.String()
	if s == "" {
		t.Error("Expected non-empty string")
	}
}
