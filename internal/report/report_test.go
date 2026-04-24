package report

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestNewReporter(t *testing.T) {
	r := NewReporter(models.SeverityHigh)
	if r.minSeverity != models.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", r.minSeverity)
	}
}

func TestCalculateStats(t *testing.T) {
	result := models.NewScanResult()
	result.AddFinding(models.Finding{
		Severity: models.SeverityCritical,
	})
	result.AddFinding(models.Finding{
		Severity: models.SeverityHigh,
	})
	result.AddFinding(models.Finding{
		Severity: models.SeverityMedium,
	})
	result.AddFinding(models.Finding{
		Severity: models.SeverityLow,
	})
	result.FilesScanned = 5
	result.RulesFound = 10

	r := NewReporter(models.SeverityLow)
	stats := r.CalculateStats(*result)

	if stats.FilesScanned != 5 {
		t.Errorf("expected 5, got %d", stats.FilesScanned)
	}
	if stats.RulesFound != 10 {
		t.Errorf("expected 10, got %d", stats.RulesFound)
	}
	if stats.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", stats.Critical)
	}
	if stats.High != 1 {
		t.Errorf("expected 1 high, got %d", stats.High)
	}
	if stats.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", stats.Medium)
	}
	if stats.Low != 1 {
		t.Errorf("expected 1 low, got %d", stats.Low)
	}
	if stats.Total != 4 {
		t.Errorf("expected 4 total, got %d", stats.Total)
	}
}

func TestCalculateStatsEmpty(t *testing.T) {
	result := models.NewScanResult()
	r := NewReporter(models.SeverityLow)
	stats := r.CalculateStats(*result)

	if stats.Total != 0 {
		t.Errorf("expected 0, got %d", stats.Total)
	}
	if stats.Critical != 0 {
		t.Errorf("expected 0 critical, got %d", stats.Critical)
	}
}

func TestNewReporterDefault(t *testing.T) {
	r := NewReporter(models.SeverityLow)
	if r.minSeverity != models.SeverityLow {
		t.Errorf("expected SeverityLow, got %v", r.minSeverity)
	}
	r = NewReporter(models.SeverityHigh)
	if r.minSeverity != models.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", r.minSeverity)
	}
}
