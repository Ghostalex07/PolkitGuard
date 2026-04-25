package api

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestAPIServerCreation(t *testing.T) {
	s := NewServer(8080)
	if s == nil {
		t.Fatal("Expected non-nil server")
	}
	if s.port != 8080 {
		t.Errorf("Expected port 8080, got %d", s.port)
	}
}

func TestComparePolicies(t *testing.T) {
	oldRules := []models.PolkitRule{
		{Action: "test.action", Identity: "admin", ResultAny: "yes"},
	}
	newRules := []models.PolkitRule{
		{Action: "test.action", Identity: "admin", ResultAny: "auth_admin"},
		{Action: "new.action", Identity: "admin", ResultAny: "yes"},
	}

	result := comparePolicies(oldRules, newRules)

	if result.Changed != 1 {
		t.Errorf("Expected 1 changed, got %d", result.Changed)
	}
	if result.Added != 1 {
		t.Errorf("Expected 1 added, got %d", result.Added)
	}
}

func TestGetTemplates(t *testing.T) {
	templates := getTemplates()
	if len(templates) == 0 {
		t.Error("Expected templates")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected models.Severity
	}{
		{"critical", models.SeverityCritical},
		{"HIGH", models.SeverityHigh},
		{"Medium", models.SeverityMedium},
		{"unknown", models.SeverityLow},
	}

	for _, tt := range tests {
		if got := parseSeverity(tt.input); got != tt.expected {
			t.Errorf("parseSeverity(%s) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	response := APIResponse{
		Success: true,
		Data:    map[string]string{"test": "value"},
	}

	if response.Success != true {
		t.Error("Expected success to be true")
	}
}