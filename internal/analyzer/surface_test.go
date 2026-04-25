package analyzer

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestAnalyzeAttackSurface(t *testing.T) {
	findings := []models.Finding{
		{
			Severity: models.SeverityCritical,
			RuleID: "TEST-001",
			Rule: &models.PolkitRule{
				Action: "org.freedesktop.systemd1.manage-units",
				Identity: "unix-user:*",
				ResultAny: "yes",
			},
		},
		{
			Severity: models.SeverityHigh,
			RuleID: "TEST-002",
			Rule: &models.PolkitRule{
				Action: "org.freedesktop.NetworkManager.*",
				Identity: "unix-group:all",
				ResultAny: "yes",
			},
		},
	}

	surface := AnalyzeAttackSurface(findings)

	if surface.TotalActions != 2 {
		t.Errorf("Expected 2 total actions, got %d", surface.TotalActions)
	}

	if surface.Score <= 0 {
		t.Error("Expected positive score")
	}

	if surface.RiskLevel == "" {
		t.Error("Expected risk level to be set")
	}
}

func TestAnalyzeAttackSurfaceEmpty(t *testing.T) {
	surface := AnalyzeAttackSurface([]models.Finding{})

	if surface.TotalActions != 0 {
		t.Errorf("Expected 0 for empty, got %d", surface.TotalActions)
	}

	if surface.Score != 0 {
		t.Errorf("Expected 0 score, got %f", surface.Score)
	}
}

func TestIsNetworkAction(t *testing.T) {
	tests := []struct {
		action string
		expect bool
	}{
		{"org.freedesktop.NetworkManager.settings", true},
		{"org.freedesktop.systemd1.unit", false},
		{"custom.network.action", true},
		{"user.password", false},
	}

	for _, tt := range tests {
		if got := isNetworkAction(tt.action); got != tt.expect {
			t.Errorf("isNetworkAction(%s) = %v, want %v", tt.action, got, tt.expect)
		}
	}
}

func TestIsSystemCritical(t *testing.T) {
	tests := []struct {
		action string
		expect bool
	}{
		{"org.freedesktop.systemd1.manage-units", true},
		{"org.freedesktop.login1.reboot", true},
		{"org.freedesktop.device", false},
	}

	for _, tt := range tests {
		if got := isSystemCritical(tt.action); got != tt.expect {
			t.Errorf("isSystemCritical(%s) = %v, want %v", tt.action, got, tt.expect)
		}
	}
}

func TestGetRiskLevel(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{85, "CRITICAL"},
		{70, "HIGH"},
		{50, "MEDIUM"},
		{25, "LOW"},
		{10, "MINIMAL"},
	}

	for _, tt := range tests {
		if got := getRiskLevel(tt.score); got != tt.expected {
			t.Errorf("getRiskLevel(%f) = %s, want %s", tt.score, got, tt.expected)
		}
	}
}