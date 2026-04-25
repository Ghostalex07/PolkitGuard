package diff

import (
	"fmt"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type DiffResult struct {
	Added   []PolicyDiff `json:"added"`
	Removed []PolicyDiff `json:"removed"`
	Changed []PolicyDiff `json:"changed"`
	Same    int           `json:"same"`
}

type PolicyDiff struct {
	Action      string `json:"action"`
	OldIdentity string `json:"old_identity,omitempty"`
	NewIdentity string `json:"new_identity,omitempty"`
	OldResult   string `json:"old_result,omitempty"`
	NewResult   string `json:"new_result,omitempty"`
	DiffType    string `json:"diff_type"`
}

func ComparePolicies(oldRules, newRules []models.PolkitRule) DiffResult {
	result := DiffResult{}

	oldMap := buildRuleMap(oldRules)
	newMap := buildRuleMap(newRules)

	for action, newRule := range newMap {
		if oldRule, exists := oldMap[action]; exists {
			if !rulesEqual(oldRule, newRule) {
				result.Changed = append(result.Changed, PolicyDiff{
					Action:      action,
					OldIdentity: oldRule.Identity,
					NewIdentity: newRule.Identity,
					OldResult:   oldRule.ResultAny,
					NewResult:   newRule.ResultAny,
					DiffType:    "modified",
				})
			} else {
				result.Same++
			}
		} else {
			result.Added = append(result.Added, PolicyDiff{
				Action:      action,
				NewIdentity: newRule.Identity,
				NewResult:   newRule.ResultAny,
				DiffType:    "added",
			})
		}
	}

	for action, oldRule := range oldMap {
		if _, exists := newMap[action]; !exists {
			result.Removed = append(result.Removed, PolicyDiff{
				Action:      action,
				OldIdentity: oldRule.Identity,
				OldResult:   oldRule.ResultAny,
				DiffType:    "removed",
			})
		}
	}

	return result
}

func buildRuleMap(rules []models.PolkitRule) map[string]models.PolkitRule {
	m := make(map[string]models.PolkitRule)
	for _, r := range rules {
		key := r.Action
		if r.Identity != "" {
			key = r.Action + ":" + r.Identity
		}
		m[key] = r
	}
	return m
}

func rulesEqual(a, b models.PolkitRule) bool {
	return a.Action == b.Action &&
		a.Identity == b.Identity &&
		a.ResultAny == b.ResultAny &&
		a.ResultActive == b.ResultActive &&
		a.ResultInactive == b.ResultInactive
}

func (d *DiffResult) Summary() string {
	return fmt.Sprintf(`Policy Diff Summary
====================
Added:   %d
Removed: %d
Changed: %d
Same:    %d
Total:   %d`,
		len(d.Added),
		len(d.Removed),
		len(d.Changed),
		d.Same,
		len(d.Added)+len(d.Removed)+len(d.Changed)+d.Same,
	)
}

func (d *DiffResult) HasBreakingChanges() bool {
	for _, c := range d.Removed {
		if strings.Contains(c.Action, "system") ||
			strings.Contains(c.Action, "auth") ||
			strings.Contains(c.Action, "admin") {
			return true
		}
	}
	return len(d.Removed) > 3
}

func (d *DiffResult) ToUnifiedDiff() string {
	var lines []string

	lines = append(lines, "--- old/policy.rules")
	lines = append(lines, "+++ new/policy.rules")

	for _, r := range d.Removed {
		lines = append(lines, fmt.Sprintf("-%s [identity=%s] -> %s",
			r.Action, r.OldIdentity, r.OldResult))
	}

	for _, a := range d.Added {
		lines = append(lines, fmt.Sprintf("+%s [identity=%s] -> %s",
			a.Action, a.NewIdentity, a.NewResult))
	}

	for _, c := range d.Changed {
		lines = append(lines, fmt.Sprintf("~%s [%s -> %s] -> [%s -> %s]",
			c.Action, c.OldIdentity, c.NewIdentity, c.OldResult, c.NewResult))
	}

	return strings.Join(lines, "\n")
}

func MergePolicies(base, overlay []models.PolkitRule, strategy string) []models.PolkitRule {
	switch strategy {
	case "overlay":
		return mergeOverlay(base, overlay)
	case "replace":
		return overlay
	case "keep":
		return mergeKeep(base, overlay)
	default:
		return mergeOverlay(base, overlay)
	}
}

func mergeOverlay(base, overlay []models.PolkitRule) []models.PolkitRule {
	result := base
	added := false

	for _, o := range overlay {
		found := false
		for i, b := range result {
			if b.Action == o.Action {
				result[i] = o
				found = true
				break
			}
		}
		if !found {
			result = append(result, o)
			added = true
		}
	}

	if added {
		return result
	}
	return result
}

func mergeKeep(base, overlay []models.PolkitRule) []models.PolkitRule {
	seen := make(map[string]bool)

	var result []models.PolkitRule

	for _, b := range base {
		key := b.Action + ":" + b.Identity
		seen[key] = true
		result = append(result, b)
	}

	for _, o := range overlay {
		key := o.Action + ":" + o.Identity
		if !seen[key] {
			result = append(result, o)
		}
	}

	return result
}