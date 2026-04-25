package report

import (
	"strings"
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestGenerateMarkdownReport(t *testing.T) {
	result := &models.ScanResult{
		FilesScanned: 5,
		RulesFound:   10,
		Findings: []models.Finding{
			{
				Severity:  models.SeverityCritical,
				RuleID:    "CRIT-001",
				Title:     "Test critical",
				Rule:      &models.PolkitRule{Action: "test.action", Identity: "unix-user:*", ResultAny: "yes"},
			},
			{
				Severity:  models.SeverityHigh,
				RuleID:    "HIGH-001",
				Title:     "Test high",
				Rule:      &models.PolkitRule{Action: "test.action2", Identity: "unix-group:all", ResultAny: "yes"},
			},
		},
	}

	report := GenerateMarkdownReport(result, "Test Report")

	if len(report) == 0 {
		t.Error("Expected non-empty report")
	}

	if !contains(report, "Test Report") {
		t.Error("Expected title in report")
	}

	if !contains(report, "Files Scanned") {
		t.Error("Expected summary section")
	}

	if !contains(report, "Critical Findings") {
		t.Error("Expected findings section")
	}
}

func TestGenerateMarkdownReportNoFindings(t *testing.T) {
	result := &models.ScanResult{
		FilesScanned: 5,
		RulesFound:   10,
		Findings:     []models.Finding{},
	}

	report := GenerateMarkdownReport(result, "Clean Report")

	if !contains(report, "No Findings") {
		t.Error("Expected no findings message")
	}
}

func TestGenerateMarkdownReportWithRule(t *testing.T) {
	result := &models.ScanResult{
		Findings: []models.Finding{
			{
				Severity:    models.SeverityCritical,
				RuleID:      "CRIT-001",
				Title:       "Test",
				Description: "Test description",
				Message:     "Test message",
				Rule: &models.PolkitRule{
					Action:       "org.test.action",
					Identity:     "unix-user:admin",
					ResultAny:    "yes",
					ResultActive: "yes",
				},
			},
		},
	}

report := GenerateMarkdownReport(result, "Test")

	if !strings.Contains(report, "unix-user:admin") {
		t.Error("Expected identity in report")
	}
}

func TestFilterFindings(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityMedium},
		{Severity: models.SeverityLow},
	}

	tests := []struct {
		severity models.Severity
		expected int
	}{
		{models.SeverityCritical, 2},
		{models.SeverityHigh, 1},
		{models.SeverityMedium, 1},
		{models.SeverityLow, 1},
	}

	for _, tt := range tests {
		filtered := filterFindings(findings, tt.severity)
		if len(filtered) != tt.expected {
			t.Errorf("filterFindings(%v) = %d, want %d", tt.severity, len(filtered), tt.expected)
		}
	}
}

func TestWriteFinding(t *testing.T) {
	finding := models.Finding{
		Severity:    models.SeverityHigh,
		RuleID:      "HIGH-001",
		Title:       "Test Finding",
		Description: "Test Description",
		Rule: &models.PolkitRule{
			Action:    "org.test.action",
			Identity:  "unix-user:test",
			ResultAny: "yes",
		},
	}

	var sb strings.Builder
	writeFinding(&sb, finding)
	output := sb.String()

	if !strings.Contains(output, "HIGH-001") {
		t.Error("Expected rule ID")
	}

	if !strings.Contains(output, "unix-user:test") {
		t.Error("Expected identity in report")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}