package analyzer

import (
	"fmt"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type AttackSurface struct {
	TotalActions          int            `json:"total_actions"`
	HighRiskActions       []string       `json:"high_risk_actions"`
	AnonymouslyAccessible int            `json:"anonymously_accessible"`
	WildcardPatterns      int            `json:"wildcard_patterns"`
	NoAuthRequired        int            `json:"no_auth_required"`
	NetworkExposed        []SurfaceEntry `json:"network_exposed"`
	SystemCritical        []SurfaceEntry `json:"system_critical"`
	UserData              []SurfaceEntry `json:"user_data"`
	PrivilegeEscalation   []SurfaceEntry `json:"privilege_escalation"`
	Score                 float64        `json:"score"`
	RiskLevel             string         `json:"risk_level"`
}

type SurfaceEntry struct {
	Action  string `json:"action"`
	RuleID  string `json:"rule_id"`
	Risk    string `json:"risk"`
}

func AnalyzeAttackSurface(findings []models.Finding) AttackSurface {
	surface := AttackSurface{}

	for _, f := range findings {
		if f.Rule != nil {
			action := f.Rule.Action
			surface.TotalActions++

			if action == "*" || strings.Contains(action, "*") {
				surface.WildcardPatterns++
			}

			if f.Rule.ResultAny == "yes" && (f.Rule.Identity == "unix-user:*" || f.Rule.Identity == "unix-group:all") {
				surface.AnonymouslyAccessible++
			}

			if !strings.Contains(f.Rule.ResultAny, "auth") && !strings.Contains(f.Rule.ResultAny, "no") {
				surface.NoAuthRequired++
			}

			if isNetworkAction(action) {
				surface.NetworkExposed = append(surface.NetworkExposed, SurfaceEntry{
					Action: action,
					RuleID: f.RuleID,
					Risk:   "HIGH",
				})
			}

			if isSystemCritical(action) {
				surface.SystemCritical = append(surface.SystemCritical, SurfaceEntry{
					Action: action,
					RuleID: f.RuleID,
					Risk:   "CRITICAL",
				})
			}

			if isUserDataAction(action) {
				surface.UserData = append(surface.UserData, SurfaceEntry{
					Action: action,
					RuleID: f.RuleID,
					Risk:   "MEDIUM",
				})
			}

			if isPrivilegeEscalation(action) {
				surface.PrivilegeEscalation = append(surface.PrivilegeEscalation, SurfaceEntry{
					Action: action,
					RuleID: f.RuleID,
					Risk:   "HIGH",
				})
			}
		}
	}

	surface.HighRiskActions = getHighRiskActions(surface)
	surface.Score = calculateSurfaceScore(surface)
	surface.RiskLevel = getRiskLevel(surface.Score)

	return surface
}

func isNetworkAction(action string) bool {
	networkPatterns := []string{
		"network", "nm", "connect", "wifi", "ethernet",
		"firewall", "iptables", "dns", "dhcp",
	}
	for _, pattern := range networkPatterns {
		if strings.Contains(strings.ToLower(action), pattern) {
			return true
		}
	}
	return false
}

func isSystemCritical(action string) bool {
	criticalPatterns := []string{
		"systemd", "reboot", "shutdown", "boot", "init",
		"kernel", "module", "service", "manage-units",
	}
	for _, pattern := range criticalPatterns {
		if strings.Contains(strings.ToLower(action), pattern) {
			return true
		}
	}
	return false
}

func isUserDataAction(action string) bool {
	dataPatterns := []string{
		"user", "account", "password", "credential",
		"sudo", "polkit", "login", "session",
	}
	for _, pattern := range dataPatterns {
		if strings.Contains(strings.ToLower(action), pattern) {
			return true
		}
	}
	return false
}

func isPrivilegeEscalation(action string) bool {
	escalationPatterns := []string{
		"pkexec", "polkit", "sudo", "doas",
		"admin", "root", "elevate",
	}
	for _, pattern := range escalationPatterns {
		if strings.Contains(strings.ToLower(action), pattern) {
			return true
		}
	}
	return false
}

func getHighRiskActions(surface AttackSurface) []string {
	seen := make(map[string]bool)
	var actions []string

	for _, entry := range surface.NetworkExposed {
		if !seen[entry.Action] {
			actions = append(actions, entry.Action)
			seen[entry.Action] = true
		}
	}

	for _, entry := range surface.SystemCritical {
		if !seen[entry.Action] {
			actions = append(actions, entry.Action)
			seen[entry.Action] = true
		}
	}

	for _, entry := range surface.PrivilegeEscalation {
		if !seen[entry.Action] {
			actions = append(actions, entry.Action)
			seen[entry.Action] = true
		}
	}

	return actions
}

func calculateSurfaceScore(surface AttackSurface) float64 {
	var score float64

	score += float64(surface.AnonymouslyAccessible) * 10
	score += float64(surface.WildcardPatterns) * 5
	score += float64(surface.NoAuthRequired) * 8
	score += float64(len(surface.NetworkExposed)) * 7
	score += float64(len(surface.SystemCritical)) * 10
	score += float64(len(surface.PrivilegeEscalation)) * 8
	score += float64(len(surface.UserData)) * 5

	if surface.TotalActions > 0 {
		score = score / float64(surface.TotalActions) * 10
	}

	if score > 100 {
		return 100
	}

	return score
}

func getRiskLevel(score float64) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func (a *AttackSurface) Summary() string {
	return fmt.Sprintf(`Attack Surface Analysis
=======================
Risk Level: %s
Score: %.1f

Exposures:
  - Anonymously Accessible: %d
  - Wildcard Patterns: %d
  - No Auth Required: %d
  - Network Exposed: %d
  - System Critical: %d
  - Privilege Escalation: %d
`,
		a.RiskLevel,
		a.Score,
		a.AnonymouslyAccessible,
		a.WildcardPatterns,
		a.NoAuthRequired,
		len(a.NetworkExposed),
		len(a.SystemCritical),
		len(a.PrivilegeEscalation),
	)
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.1f", f)
}