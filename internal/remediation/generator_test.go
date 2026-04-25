package remediation

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestGenerateRemediationPlan(t *testing.T) {
	findings := []models.Finding{
		{
			Severity: models.SeverityCritical,
			RuleID: "CRIT-001",
			Title: "Test finding",
			Rule: &models.PolkitRule{
				Action:    "org.test.action",
				Identity:  "unix-user:*",
				ResultAny: "yes",
			},
		},
	}

	plan := GenerateRemediationPlan(findings)

	if plan == nil {
		t.Fatal("Expected non-nil plan")
	}

	if len(plan.Steps) == 0 {
		t.Error("Expected at least one step")
	}

	if plan.Risk == "" {
		t.Error("Expected risk level to be set")
	}
}

func TestGenerateRemediationPlanEmpty(t *testing.T) {
	plan := GenerateRemediationPlan([]models.Finding{})

	if plan == nil {
		t.Fatal("Expected non-nil plan")
	}

	if len(plan.Steps) == 0 {
		t.Error("Expected backup step at minimum")
	}
}

func TestGenerateRemediationPlanAllSeverities(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical, RuleID: "CRIT-001", Rule: &models.PolkitRule{Action: "test", Identity: "unix-user:*", ResultAny: "yes"}},
		{Severity: models.SeverityHigh, RuleID: "HIGH-001", Rule: &models.PolkitRule{Action: "test", Identity: "unix-user:*", ResultAny: "yes"}},
		{Severity: models.SeverityMedium, RuleID: "MED-001", Rule: &models.PolkitRule{Action: "test", Identity: "unix-user:*", ResultAny: "yes"}},
	}

	plan := GenerateRemediationPlan(findings)
	if len(plan.Steps) < 4 { // 1 backup + 3 findings
		t.Errorf("Expected at least 4 steps, got %d", len(plan.Steps))
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityMedium},
	}

	critical := filterBySeverity(findings, models.SeverityCritical)
	if len(critical) != 2 {
		t.Errorf("Expected 2 critical, got %d", len(critical))
	}

	high := filterBySeverity(findings, models.SeverityHigh)
	if len(high) != 1 {
		t.Errorf("Expected 1 high, got %d", len(high))
	}
}

func TestRemediationPlanToMarkdown(t *testing.T) {
	plan := &RemediationPlan{
		Title:       "Test Plan",
		Description: "Test description",
		Risk:        "MEDIUM",
		Estimated:   "1 hour",
		Steps: []RemediationStep{
			{
				Order:       1,
				Action:      "backup",
				Description: "Backup config",
				Command:     "cp /etc/polkit-1 /backup",
			},
		},
	}

	markdown := plan.ToMarkdown()
	if len(markdown) == 0 {
		t.Error("Expected non-empty markdown")
	}
}

func TestEstimateTime(t *testing.T) {
	tests := []struct {
		findings int
		expected string
	}{
		{25, "2-4 hours"},
		{15, "1-2 hours"},
		{7, "30-60 minutes"},
		{3, "15-30 minutes"},
	}

	for _, tt := range tests {
		if got := estimateTime(tt.findings); got != tt.expected {
			t.Errorf("estimateTime(%d) = %s, want %s", tt.findings, got, tt.expected)
		}
	}
}

func TestAssessRemediationRisk(t *testing.T) {
	critical := []models.Finding{
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityCritical},
	}

	risk := assessRemediationRisk(critical)
	if risk == "" {
		t.Error("Expected risk to be set")
	}
}