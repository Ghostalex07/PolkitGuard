package trend

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestAnalyzeTrends(t *testing.T) {
	history := []models.ScanResult{
		{
			Findings: []models.Finding{
				{Severity: models.SeverityHigh},
				{Severity: models.SeverityLow},
			},
		},
		{
			Findings: []models.Finding{
				{Severity: models.SeverityMedium},
			},
		},
	}

	analysis := AnalyzeTrends(history)

	if analysis.Scans != 2 {
		t.Errorf("Expected 2 scans, got %d", analysis.Scans)
	}

	if len(analysis.DataPoints) != 2 {
		t.Errorf("Expected 2 data points, got %d", len(analysis.DataPoints))
	}
}

func TestAnalyzeTrendsEmpty(t *testing.T) {
	analysis := AnalyzeTrends([]models.ScanResult{})

	if analysis.Scans != 0 {
		t.Errorf("Expected 0 scans, got %d", analysis.Scans)
	}

	if analysis.Trajectory != "" {
		t.Errorf("Expected empty trajectory, got %s", analysis.Trajectory)
	}
}

func TestAnalyzeTrendsManyPoints(t *testing.T) {
	var history []models.ScanResult
	for i := 0; i < 10; i++ {
		history = append(history, models.ScanResult{
			Findings: []models.Finding{
				{Severity: models.SeverityHigh},
				{Severity: models.SeverityLow},
			},
		})
	}

	analysis := AnalyzeTrends(history)

	if len(analysis.Predictions) == 0 {
		t.Error("Expected predictions with sufficient history")
	}
}

func TestCalculateTrajectory(t *testing.T) {
	points := []TrendPoint{
		{ Findings: 10 },
		{ Findings: 8 },
		{ Findings: 6 },
		{ Findings: 4 },
	}

	trajectory := calculateTrajectory(points)
	if trajectory != "decreasing" {
		t.Errorf("Expected decreasing, got %s", trajectory)
	}
}

func TestDetectAnomalies(t *testing.T) {
	points := []TrendPoint{
		{ Findings: 5 },
		{ Findings: 100 }, // anomaly
		{ Findings: 6 },
	}

	anomalies := detectAnomalies(points)
	if len(anomalies) == 0 {
		t.Error("Expected at least one anomaly detected")
	}
}