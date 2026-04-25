package report

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestGenerateXMLReport(t *testing.T) {
	result := &models.ScanResult{
		FilesScanned: 5,
		RulesFound:   10,
		Findings: []models.Finding{
			{
				Severity:    models.SeverityCritical,
				RuleID:      "CRIT-001",
				Title:       "Test critical",
				Description: "Test description",
				Message:     "Test message",
				Rule: &models.PolkitRule{
					Action:   "test.action",
					Identity: "unix-user:*",
				},
			},
		},
	}

	report := GenerateXMLReport(result)

	if len(report) == 0 {
		t.Error("Expected non-empty report")
	}

	if !contains(report, "PolkitGuardReport") {
		t.Error("Expected XML root element")
	}

	if !contains(report, "1.18.0") {
		t.Error("Expected version")
	}
}

func TestGenerateExcelXML(t *testing.T) {
	result := &models.ScanResult{
		FilesScanned: 5,
		RulesFound:   10,
		Findings: []models.Finding{
			{
				Severity:  models.SeverityCritical,
				RuleID:    "CRIT-001",
				Title:     "Test",
				Rule:      &models.PolkitRule{Action: "test.action", Identity: "admin"},
			},
		},
	}

	report := GenerateExcelXML(result)

	if len(report) == 0 {
		t.Error("Expected non-empty report")
	}

	if !contains(report, "Summary") {
		t.Error("Expected Summary sheet")
	}

	if !contains(report, "Findings") {
		t.Error("Expected Findings sheet")
	}
}

func TestGenerateXMLReportEmpty(t *testing.T) {
	result := &models.ScanResult{
		FilesScanned: 0,
		RulesFound:   0,
		Findings:     []models.Finding{},
	}

	report := GenerateXMLReport(result)

	if !contains(report, "<total_findings>0</total_findings>") {
		t.Error("Expected 0 findings in summary")
	}
}