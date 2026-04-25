package cmd

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("Expected non-nil validator")
	}
	if v.strictMode {
		t.Error("Expected strictMode to be false by default")
	}
}

func TestValidateConfig(t *testing.T) {
	v := NewValidator()

	validJSON := []byte(`{
		"severity_filter": "high",
		"output_format": "json",
		"custom_paths": ["/etc/polkit-1"]
	}`)

	if err := v.ValidateConfig(validJSON); err != nil {
		t.Errorf("Expected valid config, got error: %v", err)
	}
}

func TestValidateConfigInvalidSeverity(t *testing.T) {
	v := NewValidator()

	invalidJSON := []byte(`{
		"severity_filter": "invalid"
	}`)

	if err := v.ValidateConfig(invalidJSON); err == nil {
		t.Error("Expected error for invalid severity")
	}
}

func TestValidateConfigInvalidFormat(t *testing.T) {
	v := NewValidator()

	invalidJSON := []byte(`{
		"output_format": "invalid"
	}`)

	if err := v.ValidateConfig(invalidJSON); err == nil {
		t.Error("Expected error for invalid format")
	}
}

func TestValidateConfigEmpty(t *testing.T) {
	v := NewValidator()

	emptyJSON := []byte(`{}`)

	if err := v.ValidateConfig(emptyJSON); err != nil {
		t.Errorf("Expected valid empty config, got error: %v", err)
	}
}

func TestValidatePolicyFileNotFound(t *testing.T) {
	v := NewValidator()

	_, err := v.ValidatePolicyFile("/nonexistent/file.rules")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestValidateRules(t *testing.T) {
	rules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	errors := ValidateRules(rules)
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors for valid rules, got %d", len(errors))
	}
}

func TestValidateRulesMissingAction(t *testing.T) {
	rules := []models.PolkitRule{
		{Action: "", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	errors := ValidateRules(rules)
	found := false
	for _, e := range errors {
		if e.RuleID == "POL-005" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected POL-005 error for missing action")
	}
}

func TestValidateRulesMissingIdentity(t *testing.T) {
	rules := []models.PolkitRule{
		{Action: "test.action", Identity: "", ResultAny: "auth_admin"},
	}

	errors := ValidateRules(rules)
	found := false
	for _, e := range errors {
		if e.RuleID == "POL-006" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected POL-006 error for missing identity")
	}
}

func TestValidateRulesNoResult(t *testing.T) {
	rules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin"},
	}

	errors := ValidateRules(rules)
	found := false
	for _, e := range errors {
		if e.RuleID == "POL-007" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected POL-007 error for missing result")
	}
}

func TestValidationErrorString(t *testing.T) {
	err := ValidationError{
		RuleID:   "TEST-001",
		Message:  "Test message",
		Severity: "HIGH",
	}

	if err.String() != "[HIGH] TEST-001: Test message" {
		t.Errorf("Unexpected string: %s", err.String())
	}
}