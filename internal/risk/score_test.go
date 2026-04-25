package risk

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestCalculateRiskScore(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical, Rule: &models.PolkitRule{Action: "test.action"}},
		{Severity: models.SeverityHigh, Rule: &models.PolkitRule{Action: "test.action"}},
		{Severity: models.SeverityMedium, Rule: &models.PolkitRule{Action: "test.action"}},
		{Severity: models.SeverityLow, Rule: &models.PolkitRule{Action: "test.action"}},
	}

	score := CalculateRiskScore(findings, nil)

	if score.Overall <= 0 {
		t.Error("Expected positive overall score")
	}

	if score.Trend != "" {
		t.Errorf("Expected empty trend with no history, got %s", score.Trend)
	}
}

func TestRiskScoreLevel(t *testing.T) {
	tests := []struct {
		score    RiskScore
		expected string
	}{
		{ RiskScore{Overall: 9}, "CRITICAL" },
		{ RiskScore{Overall: 7}, "HIGH" },
		{ RiskScore{Overall: 5}, "MEDIUM" },
		{ RiskScore{Overall: 3}, "LOW" },
		{ RiskScore{Overall: 1}, "MINIMAL" },
	}

	for _, tt := range tests {
		if got := tt.score.Level(); got != tt.expected {
			t.Errorf("Expected %s for score %v, got %s", tt.expected, tt.score.Overall, got)
		}
	}
}

func TestRiskScoreColor(t *testing.T) {
	score := RiskScore{Overall: 9}
	color := score.Color()
	if color != "red" {
		t.Errorf("Expected red for critical, got %s", color)
	}
}

func TestNewRiskConfig(t *testing.T) {
	cfg := NewRiskConfig()
	if cfg.TimeWindow == 0 {
		t.Error("Expected non-zero time window")
	}
	if cfg.Weights.Critical <= 0 {
		t.Error("Expected positive critical weight")
	}
}

func TestCalculateRiskScoreEmpty(t *testing.T) {
	score := CalculateRiskScore([]models.Finding{}, nil)
	if score.Overall != 0 {
		t.Errorf("Expected 0 for empty findings, got %f", score.Overall)
	}
}

func TestCalculateRiskScoreWithHistory(t *testing.T) {
	current := []models.Finding{
		{Severity: models.SeverityCritical, Rule: &models.PolkitRule{Action: "test"}},
	}
	history := []models.Finding{
		{Severity: models.SeverityLow, Rule: &models.PolkitRule{Action: "test"}},
	}

	score := CalculateRiskScore(current, history)
	if score.Trend == "" {
		t.Error("Expected trend to be set with history")
	}
}