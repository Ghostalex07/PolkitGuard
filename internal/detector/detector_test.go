package detector

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestDetectCRIT001(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "unix-user:admin",
		Action:   "org.test.action",
		ResultAny: "yes",
	}

	findings := d.Detect(rule)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
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
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unix-user:*, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

func TestDetectHIGH001GroupAll(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "unix-group:all",
		Action:  "org.test.action",
	}

	findings := d.Detect(rule)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unix-group:all, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestDetectHIGH002Wildcard(t *testing.T) {
	d := NewDetector()
	tests := []struct {
		action   string
		expected int
	}{
		{"org.freedesktop.system*", 1},
		{"org.test", 0},
		{"abc", 0},
		{"*", 0},
	}

	for _, tt := range tests {
		rule := models.PolkitRule{
			Identity: "unix-user:admin",
			Action:  tt.action,
		}
		findings := d.Detect(rule)
		if len(findings) != tt.expected {
			t.Errorf("Detect(%q) = %d findings, want %d", tt.action, len(findings), tt.expected)
		}
	}
}

func TestDetectHIGH003OrgFreedesktop(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "unix-user:admin",
		Action:  "org.freedesktop.login",
	}

	findings := d.Detect(rule)
	found := false
	for _, f := range findings {
		if f.Severity == models.SeverityHigh && f.Message == "Action matching any org.freedesktop operation" {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding for org.freedesktop.* action")
	}
}

func TestDetectMED001Ambiguous(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "",
		Action:  "org.test.action",
		Raw:     "some raw content",
	}

	findings := d.Detect(rule)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ambiguous identity, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestDetectLOW001Inconsistent(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		ResultActive:   "yes",
		ResultInactive: "no",
	}

	findings := d.Detect(rule)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for inconsistent results, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
}

func TestDetectAllSafeRule(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "unix-user:admin",
		Action:   "org.freedesktop.login1",
		ResultAny: "auth_admin",
	}

	findings := d.Detect(rule)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe rule, got %d", len(findings))
	}
}

func TestDetectAll(t *testing.T) {
	d := NewDetector()
	rules := []models.PolkitRule{
		{ResultAny: "yes"},
		{Identity: "unix-user:*"},
		{Identity: "unix-group:wheel", Action: "org.test"},
	}

	result := d.DetectAll(rules)
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.RulesFound != 3 {
		t.Errorf("expected 3 rules found, got %d", result.RulesFound)
	}
}

var _ = models.SeverityCritical // suppress unused