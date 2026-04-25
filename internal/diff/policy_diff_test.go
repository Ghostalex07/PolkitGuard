package diff

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestComparePolicies(t *testing.T) {
	oldRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}
	newRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	result := ComparePolicies(oldRules, newRules)

	if len(result.Changed) != 1 {
		t.Errorf("Expected 1 changed, got %d", len(result.Changed))
	}

	if result.Same != 0 {
		t.Errorf("Expected 0 same, got %d", result.Same)
	}
}

func TestComparePoliciesAddedRemoved(t *testing.T) {
	oldRules := []models.PolkitRule{
		{Action: "old.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}
	newRules := []models.PolkitRule{
		{Action: "new.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}

	result := ComparePolicies(oldRules, newRules)

	if len(result.Added) != 1 {
		t.Errorf("Expected 1 added, got %d", len(result.Added))
	}

	if len(result.Removed) != 1 {
		t.Errorf("Expected 1 removed, got %d", len(result.Removed))
	}
}

func TestComparePoliciesEmpty(t *testing.T) {
	result := ComparePolicies([]models.PolkitRule{}, []models.PolkitRule{})

	if result.Same != 0 {
		t.Errorf("Expected 0 same, got %d", result.Same)
	}
}

func TestComparePoliciesIdentical(t *testing.T) {
	rules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	result := ComparePolicies(rules, rules)

	if result.Same != 1 {
		t.Errorf("Expected 1 same, got %d", result.Same)
	}
}

func TestDiffResultSummary(t *testing.T) {
	result := DiffResult{
		Added:   []PolicyDiff{{Action: "add.action"}},
		Removed: []PolicyDiff{{Action: "rem.action"}},
		Changed: []PolicyDiff{{Action: "mod.action"}},
		Same:    5,
	}

	summary := result.Summary()
	if len(summary) == 0 {
		t.Error("Expected non-empty summary")
	}
}

func TestDiffResultHasBreakingChanges(t *testing.T) {
	tests := []struct {
		result   DiffResult
		expected bool
	}{
		{DiffResult{Removed: []PolicyDiff{{Action: "org.freedesktop.systemd1.system"}}}, true},
		{DiffResult{Removed: []PolicyDiff{{Action: "org.freedesktop.device"}}}, false},
		{DiffResult{}, false},
	}

	for i, tt := range tests {
		if got := tt.result.HasBreakingChanges(); got != tt.expected {
			t.Errorf("test %d: HasBreakingChanges() = %v, want %v", i, got, tt.expected)
		}
	}
}

func TestDiffResultToUnifiedDiff(t *testing.T) {
	result := DiffResult{
		Added:   []PolicyDiff{{Action: "add.action", NewIdentity: "unix-user:admin", NewResult: "yes"}},
		Removed: []PolicyDiff{{Action: "rem.action", OldIdentity: "unix-user:*", OldResult: "yes"}},
		Changed: []PolicyDiff{{Action: "mod.action", OldResult: "yes", NewResult: "auth_admin"}},
	}

	diff := result.ToUnifiedDiff()
	if len(diff) == 0 {
		t.Error("Expected non-empty unified diff")
	}
}

func TestMergePoliciesOverlay(t *testing.T) {
	base := []models.PolkitRule{
		{Action: "base.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}
	overlay := []models.PolkitRule{
		{Action: "base.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
		{Action: "new.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}

	result := MergePolicies(base, overlay, "overlay")

	if len(result) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(result))
	}

	if result[0].ResultAny != "auth_admin" {
		t.Errorf("Expected overlay to replace, got %s", result[0].ResultAny)
	}
}

func TestMergePoliciesKeep(t *testing.T) {
	base := []models.PolkitRule{
		{Action: "base.action", Identity: "unix-user:admin", ResultAny: "yes"},
		{Action: "keep.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}
	overlay := []models.PolkitRule{
		{Action: "base.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	result := MergePolicies(base, overlay, "keep")

	if len(result) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(result))
	}
}