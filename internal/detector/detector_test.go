package detector

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/config"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestDetectCRIT001(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		ResultAny: "yes",
	}

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
	rule := models.PolkitRule{
		Identity: "unix-user:*",
		Action:  "org.test.action",
	}

	findings := d.Detect(rule)
	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestDetectHIGH001GroupAll(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "unix-group:all",
		Action:  "org.test.action",
	}

	findings := d.Detect(rule)
	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestDetectHIGH003(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "unix-user:admin",
		Action:  "org.freedesktop.system*",
	}

	findings := d.Detect(rule)
	found := false
	for _, f := range findings {
		if f.Severity == models.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding")
	}
}

func TestDetectMED001Ambiguous(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "",
		Action:  "org.test.action",
		Raw:     "some content",
	}

	findings := d.Detect(rule)
	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestDetectLOW001Inconsistent(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Action:         "org.test.action",
		ResultActive:   "yes",
		ResultInactive: "auth_admin",
	}

	findings := d.Detect(rule)
	if len(findings) < 1 {
		t.Errorf("expected at least 1 finding, got %d", len(findings))
	}
}

func TestDetectAllSafeRule(t *testing.T) {
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

func TestDetectAll(t *testing.T) {
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
		Message:    "Test",
		Impact:     "Test impact",
	}
	d.AddCustomRule(cr)

	if len(d.rules) != initialCount+1 {
		t.Errorf("expected %d rules, got %d", initialCount+1, len(d.rules))
	}
}