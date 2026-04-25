package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestTakeSnapshot(t *testing.T) {
	rules := []models.PolkitRule{
		{Action: "test.action1", Identity: "unix-user:admin", ResultAny: "auth_admin"},
		{Action: "test.action2", Identity: "unix-group:wheel", ResultAny: "auth_admin_keep"},
	}

	snapshot := TakeSnapshot(rules)

	if len(snapshot.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(snapshot.Rules))
	}

	if snapshot.Version != "1.18.0" {
		t.Errorf("Expected version 1.18.0, got %s", snapshot.Version)
	}
}

func TestSnapshotSaveAndLoad(t *testing.T) {
	rules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	snapshot := TakeSnapshot(rules)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "snapshot.json")

	if err := snapshot.Save(path); err != nil {
		t.Fatalf("Failed to save snapshot: %v", err)
	}

	loaded, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("Failed to load snapshot: %v", err)
	}

	if len(loaded.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(loaded.Rules))
	}
}

func TestLoadSnapshotNotFound(t *testing.T) {
	_, err := LoadSnapshot("/nonexistent/path/snapshot.json")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestCompareSnapshots(t *testing.T) {
	oldRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}
	newRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
		{Action: "new.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}

	oldS := TakeSnapshot(oldRules)
	newS := TakeSnapshot(newRules)

	result := CompareSnapshots(oldS, newS)

	if len(result.Modified) != 1 {
		t.Errorf("Expected 1 modified, got %d", len(result.Modified))
	}

	if len(result.Added) != 1 {
		t.Errorf("Expected 1 added, got %d", len(result.Added))
	}
}

func TestCompareSnapshotsRemoved(t *testing.T) {
	oldRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "yes"},
		{Action: "removed.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}
	newRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	oldS := TakeSnapshot(oldRules)
	newS := TakeSnapshot(newRules)

	result := CompareSnapshots(oldS, newS)

	if len(result.Removed) != 1 {
		t.Errorf("Expected 1 removed, got %d", len(result.Removed))
	}
}

func TestComparisonResultSummary(t *testing.T) {
	result := ComparisonResult{
		Added:   []RuleChange{{}},
		Removed: []RuleChange{{}},
		Modified: []RuleChange{{}, {}},
		Same:    5,
	}

	summary := result.Summary()
	if len(summary) == 0 {
		t.Error("Expected non-empty summary")
	}
}

func TestComparisonResultHasSignificantChanges(t *testing.T) {
	tests := []struct {
		result   ComparisonResult
		expected bool
	}{
		{ComparisonResult{Removed: []RuleChange{{}}}, true},
		{ComparisonResult{Modified: []RuleChange{{}, {}, {}, {}}}, true},
		{ComparisonResult{Modified: []RuleChange{{}}}, false},
		{ComparisonResult{}, false},
	}

	for _, tt := range tests {
		if got := tt.result.HasSignificantChanges(); got != tt.expected {
			t.Errorf("HasSignificantChanges() = %v, want %v", got, tt.expected)
		}
	}
}

func TestSaveComparison(t *testing.T) {
	oldRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "yes"},
	}
	newRules := []models.PolkitRule{
		{Action: "test.action", Identity: "unix-user:admin", ResultAny: "auth_admin"},
	}

	tmpDir := t.TempDir()
	oldPath := filepath.Join(tmpDir, "old.json")
	newPath := filepath.Join(tmpDir, "new.json")
	outPath := filepath.Join(tmpDir, "comparison.json")

	oldSnapshot := TakeSnapshot(oldRules)
	oldSnapshot.Save(oldPath)
	newSnapshot := TakeSnapshot(newRules)
	newSnapshot.Save(newPath)

	err := SaveComparison(oldPath, newPath, outPath)
	if err != nil {
		t.Fatalf("Failed to save comparison: %v", err)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Error("Expected output file to exist")
	}
}