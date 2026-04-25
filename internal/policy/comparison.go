package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type ComparisonResult struct {
	Added   []RuleChange `json:"added"`
	Removed []RuleChange `json:"removed"`
	Modified []RuleChange `json:"modified"`
	Same     int          `json:"same"`
	Timestamp time.Time   `json:"timestamp"`
	Version   string      `json:"version"`
}

type RuleChange struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Action      string `json:"action"`
	Identity    string `json:"identity"`
	ResultAny   string `json:"result_any"`
	ChangeType  string `json:"change_type"`
}

type PolicySnapshot struct {
	Timestamp time.Time `json:"timestamp"`
	Rules     []PolicyRule `json:"rules"`
	Version   string      `json:"version"`
}

type PolicyRule struct {
	Action     string `json:"action"`
	Identity    string `json:"identity"`
	ResultAny  string `json:"result_any,omitempty"`
	ResultActive string `json:"result_active,omitempty"`
	ResultInactive string `json:"result_inactive,omitempty"`
}

func TakeSnapshot(rules []models.PolkitRule) PolicySnapshot {
	snapshot := PolicySnapshot{
		Timestamp: time.Now(),
		Version:  "1.18.0",
		Rules:    make([]PolicyRule, len(rules)),
	}

	for i, r := range rules {
		snapshot.Rules[i] = PolicyRule{
			Action:     r.Action,
			Identity:  r.Identity,
			ResultAny: r.ResultAny,
			ResultActive: r.ResultActive,
			ResultInactive: r.ResultInactive,
		}
	}

	return snapshot
}

func (s PolicySnapshot) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadSnapshot(path string) (*PolicySnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var snapshot PolicySnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}

	return &snapshot, nil
}

func CompareSnapshots(oldS, newS PolicySnapshot) ComparisonResult {
	result := ComparisonResult{
		Timestamp: time.Now(),
		Version:   "1.18.0",
	}

	oldMap := map[string]PolicyRule{}
	for _, r := range oldS.Rules {
		key := r.Action + "|" + r.Identity
		oldMap[key] = r
	}

	newMap := map[string]PolicyRule{}
	for _, r := range newS.Rules {
		key := r.Action + "|" + r.Identity
		newMap[key] = r
	}

	for key, newRule := range newMap {
		if oldRule, exists := oldMap[key]; exists {
			if oldRule.ResultAny != newRule.ResultAny {
				result.Modified = append(result.Modified, RuleChange{
					RuleID:     key,
					RuleName:   newRule.Action,
					Action:     newRule.Action,
					Identity:   newRule.Identity,
					ResultAny:  newRule.ResultAny,
					ChangeType: "modified",
				})
			} else {
				result.Same++
			}
		} else {
			result.Added = append(result.Added, RuleChange{
				RuleID:     key,
				RuleName:   newRule.Action,
				Action:    newRule.Action,
				Identity:  newRule.Identity,
				ResultAny: newRule.ResultAny,
				ChangeType: "added",
			})
		}
	}

	for key, oldRule := range oldMap {
		if _, exists := newMap[key]; !exists {
			result.Removed = append(result.Removed, RuleChange{
				RuleID:     key,
				RuleName:   oldRule.Action,
				Action:    oldRule.Action,
				Identity:  oldRule.Identity,
				ResultAny: oldRule.ResultAny,
				ChangeType: "removed",
			})
		}
	}

	return result
}

func (c *ComparisonResult) Summary() string {
	return fmt.Sprintf(`Policy Comparison Summary
==========================
Added:     %d
Removed:   %d
Modified: %d
Unchanged: %d
Total:     %d`,
		len(c.Added),
		len(c.Removed),
		len(c.Modified),
		c.Same,
		len(c.Added)+len(c.Removed)+len(c.Modified)+c.Same,
	)
}

func (c *ComparisonResult) HasSignificantChanges() bool {
	return len(c.Removed) > 0 || len(c.Modified) > 3
}

func SaveComparison(oldPath, newPath, outputPath string) error {
	oldS, err := LoadSnapshot(oldPath)
	if err != nil {
		return fmt.Errorf("cannot load old snapshot: %w", err)
	}

	newS, err := LoadSnapshot(newPath)
	if err != nil {
		return fmt.Errorf("cannot load new snapshot: %w", err)
	}

	result := CompareSnapshots(*oldS, *newS)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}