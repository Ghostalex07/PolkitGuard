package report

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestCalculateStats(t *testing.T) {
	result := models.ScanResult{
		FilesScanned: 5,
		RulesFound:  20,
		Findings: []models.Finding{
			{Severity: models.SeverityCritical},
			{Severity: models.SeverityCritical},
			{Severity: models.SeverityHigh},
			{Severity: models.SeverityMedium},
			{Severity: models.SeverityMedium},
			{Severity: models.SeverityLow},
		},
	}

	r := NewReporter(models.SeverityLow)
	stats := r.CalculateStats(result)

	if stats.FilesScanned != 5 {
		t.Errorf("Expected 5 files scanned, got %d", stats.FilesScanned)
	}
	if stats.RulesFound != 20 {
		t.Errorf("Expected 20 rules, got %d", stats.RulesFound)
	}
	if stats.Critical != 2 {
		t.Errorf("Expected 2 critical, got %d", stats.Critical)
	}
	if stats.High != 1 {
		t.Errorf("Expected 1 high, got %d", stats.High)
	}
	if stats.Medium != 2 {
		t.Errorf("Expected 2 medium, got %d", stats.Medium)
	}
	if stats.Low != 1 {
		t.Errorf("Expected 1 low, got %d", stats.Low)
	}
	if stats.Total != 6 {
		t.Errorf("Expected 6 total, got %d", stats.Total)
	}
}

func TestOutputNoFindings(t *testing.T) {
	result := models.ScanResult{
		FilesScanned: 0,
		RulesFound:  0,
		Findings:   []models.Finding{},
	}

	r := NewReporter(models.SeverityLow)
	stats := r.CalculateStats(result)

	if stats.Total != 0 {
		t.Errorf("Expected 0 findings, got %d", stats.Total)
	}
}