package detector

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/config"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("Expected non-nil detector")
	}
	if len(d.rules) == 0 {
		t.Error("Expected rules")
	}
}

func TestNewDetectorWithCustom(t *testing.T) {
	cfg := &config.Config{
		CustomRules: []config.CustomRule{
			{ID: "TEST-001", Severity: "high", Description: "Test", Pattern: "test"},
		},
	}
	d := NewDetectorWithCustom(cfg)
	if len(d.rules) <= 0 {
		t.Error("Expected custom rules")
	}
}

func TestSuppressRule(t *testing.T) {
	d := NewDetector()
	d.SuppressRule("CRIT-001")
	if !d.IsSuppressed("CRIT-001") {
		t.Error("Expected CRIT-001 to be suppressed")
	}
	if d.IsSuppressed("CRIT-002") {
		t.Error("CRIT-002 should not be suppressed")
	}
}

func TestDetectRule(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "*",
		Action:   "org.test",
		ResultAny: "yes",
	}
	findings := d.Detect(rule)
	if len(findings) == 0 {
		t.Error("Expected findings")
	}
}

func TestDetectAllRules(t *testing.T) {
	d := NewDetector()
	rules := []models.PolkitRule{
		{ResultAny: "yes"},
		{Identity: "unix-user:*"},
		{Action: "org.freedesktop.*"},
	}
	result := d.DetectAll(rules)
	if result.RulesFound != len(rules) {
		t.Errorf("Expected %d rules, got %d", len(rules), result.RulesFound)
	}
}

func TestDetectCRIT001(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{ResultAny: "yes"}
	findings := d.Detect(rule)
	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestDetectNoAuthRequired(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "unix-user:admin",
		Action:   "org.test.action",
		ResultAny: "auth_admin",
	}
	findings := d.Detect(rule)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for auth_admin, got %d", len(findings))
	}
}

func TestDetectCRIT002UnixUser(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{Identity: "unix-user:*", Action: "org.test.action"}
	findings := d.Detect(rule)
	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestDetectHIGH001GroupAll(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{Identity: "unix-group:all", Action: "org.test.action"}
	findings := d.Detect(rule)
	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestDetectSafeRule(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:       "unix-user:admin",
		Action:        "org.freedesktop.login1",
		ResultAny:     "auth_admin",
		ResultActive:  "auth_admin",
		ResultInactive: "auth_admin",
	}
	findings := d.Detect(rule)
	_ = findings
}

func TestDetectMultiple(t *testing.T) {
	d := NewDetector()
	rules := []models.PolkitRule{
		{Identity: "unix-user:*", Action: "org.test", ResultAny: "yes"},
		{Identity: "unix-group:all", Action: "org.test"},
	}
	result := d.DetectAll(rules)
	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(result.Findings))
	}
}

func TestAddCustomRule(t *testing.T) {
	d := NewDetector()
	initialCount := len(d.rules)
	cr := config.CustomRule{
		ID:          "TEST-001",
		Severity:    "high",
		Description: "Test rule",
		Pattern:     "test-pattern",
	}
	d.AddCustomRule(cr)
	if len(d.rules) != initialCount+1 {
		t.Errorf("expected %d rules, got %d", initialCount+1, len(d.rules))
	}
}