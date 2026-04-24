package cis

import "github.com/Ghostalex07/PolkitGuard/internal/models"

type CISCheck struct {
	ID          string
	Name        string
	Description string
	Severity    models.Severity
	Reference   string
	Check       func(models.PolkitRule) bool
}

var CISBenchmarks = []CISCheck{
	{
		ID:          "CIS-1.1.1",
		Name:        "No Unauthenticated Access",
		Description: "Ensure no polkit rules grant unauthenticated access",
		Severity:    models.SeverityCritical,
		Reference:   "CIS Linux Benchmark 5.3.1",
		Check: func(rule models.PolkitRule) bool {
			return rule.ResultAny == "yes"
		},
	},
	{
		ID:          "CIS-1.1.2",
		Name:        "Restrict to Specific Users",
		Description: "Ensure actions are restricted to specific users",
		Severity:    models.SeverityHigh,
		Reference:   "CIS Linux Benchmark 5.3.2",
		Check: func(rule models.PolkitRule) bool {
			return rule.Identity == "unix-user:*" || rule.Identity == "unix-group:all"
		},
	},
	{
		ID:          "CIS-1.1.3",
		Name:        "Require Authentication",
		Description: "Ensure administrative actions require authentication",
		Severity:    models.SeverityHigh,
		Reference:   "CIS Linux Benchmark 5.3.3",
		Check: func(rule models.PolkitRule) bool {
			return rule.ResultAny != "" && rule.ResultAny != "auth_admin" && rule.ResultAny != "auth_admin_keep" && rule.ResultAny != "auth_admin_keep_always"
		},
	},
}

func RunCISChecks(rules []models.PolkitRule) []models.Finding {
	var findings []models.Finding

	for _, rule := range rules {
		for _, check := range CISBenchmarks {
			if check.Check(rule) {
				finding := models.Finding{
					Severity:       check.Severity,
					File:           rule.File,
					RuleName:       check.ID,
					Message:        check.Name + ": " + check.Description,
					Impact:         check.Reference,
					Recommendation: "Review and remediate per CIS benchmark",
				}
				finding.CalculateScore()
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func GetCISCheckIDs() []string {
	ids := make([]string, len(CISBenchmarks))
	for i, check := range CISBenchmarks {
		ids[i] = check.ID
	}
	return ids
}
