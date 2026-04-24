package detector

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if len(d.rules) == 0 {
		t.Error("Expected detection rules")
	}
}

func TestDetectorSuppressRule(t *testing.T) {
	d := NewDetector()
	d.SuppressRule("CRIT-001")
	if len(d.suppressedRules) != 1 {
		t.Errorf("Expected 1 suppressed rule, got %d", len(d.suppressedRules))
	}
}

func TestDetectorDetect(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "unix-user:*",
		Action:    "org.test.action",
		ResultAny: "yes",
	}
	findings := d.Detect(rule)
	if len(findings) == 0 {
		t.Error("Expected to find issues")
	}
}

func TestDetectorDetectNoIssues(t *testing.T) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "unix-user:admin",
		Action:    "org.freedesktop.systemd1",
		ResultAny: "auth_admin",
	}
	findings := d.Detect(rule)
	if len(findings) > 1 {
		t.Logf("Expected minimal issues for restricted rule, got %d", len(findings))
	}
}

func TestDetectorDetectAll(t *testing.T) {
	d := NewDetector()
	rules := []models.PolkitRule{
		{Identity: "unix-user:*", Action: "test", ResultAny: "yes"},
		{Identity: "unix-user:admin", Action: "test", ResultAny: "auth_admin"},
	}
	result := d.DetectAll(rules)
	if len(result.Findings) == 0 {
		t.Error("Expected findings")
	}
}

func BenchmarkNewDetector(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewDetector()
	}
}

func BenchmarkDetect(b *testing.B) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "unix-user:*",
		Action:    "org.test.action",
		ResultAny: "yes",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(rule)
	}
}

func BenchmarkDetectAll(b *testing.B) {
	d := NewDetector()
	rules := []models.PolkitRule{
		{Identity: "unix-user:*", Action: "test", ResultAny: "yes"},
		{Identity: "unix-group:sudo", Action: "org.freedesktop.systemd1", ResultAny: "auth_admin"},
		{Identity: "unix-user:alice", Action: "org.freedesktop.login1", ResultInactive: "yes"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.DetectAll(rules)
	}
}

func BenchmarkDetectWithManyRules(b *testing.B) {
	d := NewDetector()
	rules := make([]models.PolkitRule, 100)
	for i := range rules {
		rules[i] = models.PolkitRule{
			Identity:  "unix-user:*",
			Action:    "org.test.action",
			ResultAny: "yes",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.DetectAll(rules)
	}
}
