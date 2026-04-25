package report

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestCalculateStatsMultipleSeverities(t *testing.T) {
	result := models.NewScanResult()
	for i := 0; i < 5; i++ {
		result.AddFinding(models.Finding{Severity: models.SeverityCritical})
	}
	for i := 0; i < 3; i++ {
		result.AddFinding(models.Finding{Severity: models.SeverityHigh})
	}
	for i := 0; i < 2; i++ {
		result.AddFinding(models.Finding{Severity: models.SeverityMedium})
	}
	result.AddFinding(models.Finding{Severity: models.SeverityLow})

	r := NewReporter(models.SeverityLow)
	stats := r.CalculateStats(*result)

	if stats.Critical != 5 {
		t.Errorf("expected 5 critical, got %d", stats.Critical)
	}
	if stats.High != 3 {
		t.Errorf("expected 3 high, got %d", stats.High)
	}
	if stats.Medium != 2 {
		t.Errorf("expected 2 medium, got %d", stats.Medium)
	}
	if stats.Low != 1 {
		t.Errorf("expected 1 low, got %d", stats.Low)
	}
	if stats.Total != 11 {
		t.Errorf("expected 11 total, got %d", stats.Total)
	}
}

func TestNewReporterEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		severity models.Severity
	}{
		{"critical", models.SeverityCritical},
		{"high", models.SeverityHigh},
		{"medium", models.SeverityMedium},
		{"low", models.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReporter(tt.severity)
			if r.minSeverity != tt.severity {
				t.Errorf("expected %v, got %v", tt.severity, r.minSeverity)
			}
		})
	}
}

func TestCalculateStatsZeroValues(t *testing.T) {
	result := models.NewScanResult()
	r := NewReporter(models.SeverityMedium)
	stats := r.CalculateStats(*result)

	if stats.Critical != 0 || stats.High != 0 || stats.Medium != 0 || stats.Low != 0 {
		t.Errorf("all values should be 0")
	}
	if stats.Total != 0 {
		t.Errorf("total should be 0")
	}
}

func TestCalculateStatsLarge(t *testing.T) {
	result := models.NewScanResult()
	for i := 0; i < 100; i++ {
		result.AddFinding(models.Finding{
			Severity: models.Severity(i % 4),
			File:     "/test/policy.rules",
		})
	}

	r := NewReporter(models.SeverityLow)
	stats := r.CalculateStats(*result)

	if stats.Total != 100 {
		t.Errorf("expected 100, got %d", stats.Total)
	}
}

func TestGetFindingsByMinSeverityMultiple(t *testing.T) {
	result := models.NewScanResult()
	result.AddFinding(models.Finding{Severity: models.SeverityLow})
	result.AddFinding(models.Finding{Severity: models.SeverityMedium})
	result.AddFinding(models.Finding{Severity: models.SeverityHigh})
	result.AddFinding(models.Finding{Severity: models.SeverityCritical})

	tests := []struct {
		min      models.Severity
		expected int
	}{
		{models.SeverityLow, 4},
		{models.SeverityMedium, 3},
		{models.SeverityHigh, 2},
		{models.SeverityCritical, 1},
	}

	for _, tt := range tests {
		findings := result.GetFindingsByMinSeverity(tt.min)
		if len(findings) != tt.expected {
			t.Errorf("for %v expected %d, got %d", tt.min, tt.expected, len(findings))
		}
	}
}
