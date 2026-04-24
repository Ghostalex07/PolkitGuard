package detector

import (
	"regexp"

	"github.com/Ghostalex07/PolkitGuard/internal/config"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
	"strings"
)

type Detector struct {
	rules           []DetectionRule
	suppressedRules []string
}

type DetectionRule struct {
	ID             string
	Severity        models.Severity
	Description    string
	Impact         string
	Recommendation string
	CVE           string
	Check         func(rule models.PolkitRule) bool
}

func NewDetector() *Detector {
	d := &Detector{
		rules:           getDetectionRules(),
		suppressedRules: []string{},
	}
	return d
}

func NewDetectorWithCustom(cfg *config.Config) *Detector {
	d := NewDetector()
	for _, cr := range cfg.CustomRules {
		d.AddCustomRule(cr)
	}
	return d
}

func (d *Detector) AddCustomRule(cr config.CustomRule) {
	sev := models.SeverityLow
	switch cr.Severity {
	case "critical":
		sev = models.SeverityCritical
	case "high":
		sev = models.SeverityHigh
	case "medium":
		sev = models.SeverityMedium
	}

	pattern := cr.Pattern
	d.rules = append(d.rules, DetectionRule{
		ID:          cr.ID,
		Severity:     sev,
		Description: cr.Description,
		Impact:     cr.Impact,
		Recommendation: cr.Recommendation,
		Check: func(rule models.PolkitRule) bool {
			re := regexp.MustCompile(pattern)
			return re.MatchString(rule.Raw) || re.MatchString(rule.Action)
		},
	})
}

func (d *Detector) SuppressRule(ruleID string) {
	d.suppressedRules = append(d.suppressedRules, ruleID)
}

func (d *Detector) IsSuppressed(ruleID string) bool {
	for _, id := range d.suppressedRules {
		if id == ruleID {
			return true
		}
	}
	return false
}

func getDetectionRules() []DetectionRule {
	return []DetectionRule{
		// === CRITICAL ===
		{
			ID:             "CRIT-001",
			Severity:       models.SeverityCritical,
			Description:    "Access granted without authentication",
			Impact:         "Any user on the system can perform privileged actions",
			Recommendation: "Require authentication for this action",
			Check: func(rule models.PolkitRule) bool {
				return rule.ResultAny == "yes"
			},
		},
		{
			ID:             "CRIT-002",
			Severity:       models.SeverityCritical,
			Description:    "Access granted to unix-user:* (any user)",
			Impact:         "All users can perform this action without restrictions",
			Recommendation: "Restrict to specific users or require authentication",
			Check: func(rule models.PolkitRule) bool {
				return rule.Identity == "unix-user:*" || rule.Identity == "user:*"
			},
		},
		{
			ID:             "CRIT-003",
			Severity:       models.SeverityCritical,
			Description:    "Service escalation pattern detected",
			Impact:         "Potential privilege escalation via service accounts",
			Recommendation: "Restrict access to service accounts",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Identity, "unix-user:") &&
					(strings.Contains(rule.Action, "service") ||
						strings.Contains(rule.Action, "systemd"))
			},
		},
		{
			ID:             "CRIT-004",
			Severity:       models.SeverityCritical,
			Description:    "Network-related dangerous action",
			Impact:         "Unrestricted network access pose security risk",
			Recommendation: "Restrict network-related actions to specific users",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "network") ||
					strings.Contains(rule.Action, "firewall") ||
					strings.Contains(rule.Action, "connect")
			},
		},
		{
			ID:             "CRIT-005",
			Severity:       models.SeverityCritical,
			Description:    "Root user (euid=0) unrestricted access",
			Impact:         "Root can perform any action without restrictions",
			Recommendation: "Use proper authentication even for root",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Raw, "euid") &&
					strings.Contains(rule.Raw, "== 0")
			},
		},
		{
			ID:             "CRIT-006",
			Severity:       models.SeverityCritical,
			Description:    "Authentication completely disabled",
			Impact:         "No authentication required for this action",
			Recommendation: "Enable authentication immediately",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Raw, "result_any=null") ||
					strings.Contains(rule.Raw, "result_any=no")
			},
		},
		// === HIGH ===
		{
			ID:             "HIGH-001",
			Severity:       models.SeverityHigh,
			Description:    "Permissions granted to unix-group:all",
			Impact:         "All users in the system inherit these privileges",
			Recommendation: "Restrict to specific groups that need this access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Identity, "unix-group:all") ||
					strings.Contains(rule.Identity, "group:all")
			},
		},
		{
			ID:             "HIGH-002",
			Severity:       models.SeverityHigh,
			Description:    "Overly broad action pattern with wildcards",
			Impact:         "Action matches more systems than intended",
			Recommendation: "Use specific action patterns instead of wildcards",
			Check: func(rule models.PolkitRule) bool {
				return len(rule.Action) >= 5 &&
					strings.Contains(rule.Action, "*") &&
					!strings.HasPrefix(rule.Action, "org.freedesktop.")
			},
		},
		{
			ID:             "HIGH-003",
			Severity:       models.SeverityHigh,
			Description:    "Action matching any org.freedesktop operation",
			Impact:         "Broad access to system operations",
			Recommendation: "Specify exact actions needed",
			Check: func(rule models.PolkitRule) bool {
				action := rule.Action
				return strings.HasPrefix(action, "org.freedesktop.") && strings.Contains(action, "*")
			},
		},
		{
			ID:             "HIGH-004",
			Severity:       models.SeverityHigh,
			Description:    "Overly permissive session check",
			Impact:         "Session validation can be bypassed",
			Recommendation: "Implement proper session validation",
			Check: func(rule models.PolkitRule) bool {
				hasInactive := strings.Contains(rule.Raw, "inactive")
				hasActive := strings.Contains(rule.Raw, "active")
				return strings.Contains(rule.Raw, "result_any=auth_admin_keep") &&
					!hasInactive && !hasActive
			},
		},
		{
			ID:             "HIGH-005",
			Severity:       models.SeverityHigh,
			Description:    "Disk/Storage mounting permission",
			Impact:         "Users can mount/unmount storage devices",
			Recommendation: "Restrict to specific users or admin only",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "mount") ||
					strings.Contains(rule.Action, "umount") ||
					strings.Contains(rule.Action, "storage")
			},
		},
		{
			ID:             "HIGH-006",
			Severity:       models.SeverityHigh,
			Description:    "Systemd service management",
			Impact:         "Users can start/stop system services",
			Recommendation: "Restrict service management to admins",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "systemd") &&
					(strings.Contains(rule.Action, "start") ||
						strings.Contains(rule.Action, "stop") ||
						strings.Contains(rule.Action, "restart"))
			},
		},
		{
			ID:             "HIGH-007",
			Severity:       models.SeverityHigh,
			Description:    "Power management access",
			Impact:         "Users can shutdown/reboot system",
			Recommendation: "Restrict power actions to admins only",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "reboot") ||
					strings.Contains(rule.Action, "shutdown") ||
					strings.Contains(rule.Action, "poweroff") ||
					strings.Contains(rule.Action, "suspend")
			},
		},
		{
			ID:             "HIGH-008",
			Severity:       models.SeverityHigh,
			Description:    "KDE/Gnome session actions",
			Impact:         "Users can affect desktop session",
			Recommendation: "Restrict session modifications",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "session") ||
					strings.Contains(rule.Action, " kde") ||
					strings.Contains(rule.Action, "gnome")
			},
		},
		// === MEDIUM ===
		{
			ID:             "MED-001",
			Severity:       models.SeverityMedium,
			Description:    "Ambiguous identity condition",
			Impact:         "Unclear who is granted access",
			Recommendation: "Use explicit identity checks",
			Check: func(rule models.PolkitRule) bool {
				hasAuth := strings.Contains(rule.Raw, "auth_admin") || strings.Contains(rule.Raw, "auth_any")
				return rule.Identity == "" && rule.Raw != "" && !hasAuth
			},
		},
		{
			ID:             "MED-002",
			Severity:       models.SeverityMedium,
			Description:    "Redundant rule configuration",
			Impact:         "Multiple rules may conflict or duplicate",
			Recommendation: "Consolidate or remove redundant rules",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Raw, "result_any") &&
					strings.Count(rule.Raw, "result_any") > 1
			},
		},
		{
			ID:             "MED-003",
			Severity:       models.SeverityMedium,
			Description:    "Potentially contradictory rule",
			Impact:         "Conflicting authorization results",
			Recommendation: "Review rule for consistency",
			Check: func(rule models.PolkitRule) bool {
				return (rule.ResultActive == "yes" && rule.ResultInactive == "auth_admin") ||
					(rule.ResultActive == "auth_admin" && rule.ResultInactive == "yes")
			},
		},
		{
			ID:             "MED-004",
			Severity:       models.SeverityMedium,
			Description:    "Authentication via authentication agent",
			Impact:         "May be bypassed via auth agent",
			Recommendation: "Use direct authentication methods",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.ResultAny, "auth_admin_keep_always")
			},
		},
		// === LOW ===
		{
			ID:             "LOW-001",
			Severity:       models.SeverityLow,
			Description:    "ResultInactive differs from ResultActive",
			Impact:         "Inconsistent behavior between active and inactive sessions",
			Recommendation: "Review if this difference is intentional",
			Check: func(rule models.PolkitRule) bool {
				return rule.ResultActive != "" && rule.ResultInactive != "" &&
					rule.ResultActive != rule.ResultInactive
			},
		},
		{
			ID:             "LOW-002",
			Severity:       models.SeverityLow,
			Description:    "Poorly named rule file",
			Impact:         "Difficult to identify rule purpose",
			Recommendation: "Use descriptive file names",
Check: func(rule models.PolkitRule) bool {
				return rule.ResultActive != "" && rule.ResultInactive != "" &&
					rule.ResultActive != rule.ResultInactive
			},
		},
		{
			ID:             "CRIT-005",
			Severity:       models.SeverityCritical,
			Description:    "Authentication completely disabled",
			Impact:         "Any user can perform privileged operations",
			Recommendation: "Enable authentication",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.ResultAny, "yes") && !strings.Contains(rule.ResultAny, "auth")
			},
		},
		{
			ID:             "CRIT-006",
			Severity:       models.SeverityCritical,
			Description:    "Root user (euid=0) unrestricted",
			Impact:         "Root can bypass all restrictions",
			Recommendation: "Restrict root access explicitly",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Identity, "unix-user:0") ||
					strings.Contains(rule.Identity, "unix-user:root")
			},
		},
		{
			ID:             "HIGH-005",
			Severity:       models.SeverityHigh,
			Description:    "Systemd service management",
			Impact:         "Can modify systemd services",
			Recommendation: "Restrict to admins only",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "systemd")
			},
		},
		{
			ID:             "HIGH-006",
			Severity:       models.SeverityHigh,
			Description:    "Device/Storage mounting",
			Impact:         "Can mount devices",
			Recommendation: "Restrict device mounting",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "mount") ||
					strings.Contains(rule.Action, "umount")
			},
		},
		{
			ID:             "HIGH-007",
			Severity:       models.SeverityHigh,
			Description:    "Hardware management",
			Impact:         "Can modify hardware settings",
			Recommendation: "Restrict hardware access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "hardware")
			},
		},
		{
			ID:             "HIGH-008",
			Severity:       models.SeverityHigh,
			Description:    "Network connection management",
			Impact:         "Can modify network settings",
			Recommendation: "Restrict network access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "network") ||
					strings.Contains(rule.Action, "wifi") ||
					strings.Contains(rule.Action, "ethernet")
			},
		},
		{
			ID:             "MED-004",
			Severity:       models.SeverityMedium,
			Description:    "Inconsistent authentication",
			Impact:         "Different auth levels in different states",
			Recommendation: "Standardize authentication",
			Check: func(rule models.PolkitRule) bool {
				return rule.ResultActive == "auth_admin" && rule.ResultInactive == "yes"
			},
		},
		{
			ID:             "LOW-003",
			Severity:       models.SeverityLow,
			Description:    "No comments in rule",
			Impact:         "Hard to understand rule purpose",
			Recommendation: "Add explanatory comments",
			Check: func(rule models.PolkitRule) bool {
				return rule.Raw != "" && !strings.Contains(rule.Raw, "#")
			},
		},
		{
			ID:             "LOW-004",
			Severity:       models.SeverityLow,
			Description:    "Very short action name",
			Impact:         "May conflict with future actions",
			Recommendation: "Use descriptive action names",
			Check: func(rule models.PolkitRule) bool {
				return len(rule.Action) < 10
			},
		},
	}
}

func (d *Detector) Detect(rule models.PolkitRule) []models.Finding {
	var findings []models.Finding

	for _, detectionRule := range d.rules {
		if d.IsSuppressed(detectionRule.ID) {
			continue
		}
		if detectionRule.Check(rule) {
			finding := models.Finding{
				Severity:        detectionRule.Severity,
				File:           rule.File,
				RuleName:       rule.RuleName,
				Message:        detectionRule.Description,
				Impact:         detectionRule.Impact,
				Recommendation: detectionRule.Recommendation,
				CVE:           detectionRule.CVE,
			}
			finding.CalculateScore()
			findings = append(findings, finding)
		}
	}

	return findings
}

func (d *Detector) DetectAll(rules []models.PolkitRule) models.ScanResult {
	result := models.NewScanResult()

	for _, rule := range rules {
		findings := d.Detect(rule)
		for _, f := range findings {
			result.AddFinding(f)
		}
	}

	result.FilesScanned = 0
	result.RulesFound = len(rules)

	return *result
}