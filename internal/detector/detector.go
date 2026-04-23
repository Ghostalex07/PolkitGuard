package detector

import (
	"github.com/Ghostalex07/PolkitGuard/internal/models"
	"strings"
)

type Detector struct {
	rules []DetectionRule
}

type DetectionRule struct {
	ID          string
	Severity    models.Severity
	Description string
	Impact      string
	Recommendation string
	Check       func(rule models.PolkitRule) bool
}

func NewDetector() *Detector {
	d := &Detector{
		rules: getDetectionRules(),
	}
	return d
}

func getDetectionRules() []DetectionRule {
	return []DetectionRule{
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
				return len(rule.Action) > 3 &&
					strings.Contains(rule.Action, "*") &&
					!strings.Contains(rule.Action, "org.freedesktop.")
			},
		},
		{
			ID:             "HIGH-003",
			Severity:       models.SeverityHigh,
			Description:    "Action matching any org.freedesktop operation",
			Impact:         "Broad access to system operations",
			Recommendation: "Specify exact actions needed",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "org.freedesktop.")
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
			ID:             "MED-001",
			Severity:       models.SeverityMedium,
			Description:    "Ambiguous identity condition",
			Impact:         "Unclear who is granted access",
			Recommendation: "Use explicit identity checks",
			Check: func(rule models.PolkitRule) bool {
				return rule.Identity == "" && rule.Raw != ""
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
					strings.Contains(rule.Raw, "result_any")
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
				name := rule.File
				return len(name) > 0 && len(name) < 10
			},
		},
		{
			ID:             "LOW-003",
			Severity:       models.SeverityLow,
			Description:    "Rule file without comments",
			Impact:         "Missing documentation for maintenance",
			Recommendation: "Add comments explaining rule purpose",
			Check: func(rule models.PolkitRule) bool {
				return rule.Raw != "" &&
					!strings.Contains(rule.Raw, "#") &&
					rule.Identity != ""
			},
		},
	}
}

func (d *Detector) Detect(rule models.PolkitRule) []models.Finding {
	var findings []models.Finding

	for _, detectionRule := range d.rules {
		if detectionRule.Check(rule) {
			findings = append(findings, models.Finding{
				Severity:       detectionRule.Severity,
				File:           rule.File,
				Rule:           rule.RuleName,
				Message:        detectionRule.Description,
				Impact:         detectionRule.Impact,
				Recommendation: detectionRule.Recommendation,
			})
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