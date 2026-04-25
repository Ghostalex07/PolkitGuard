package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func GenerateMarkdownReport(result *models.ScanResult, title string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s\n\n", title))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", time.Now().Format(time.RFC822)))
	sb.WriteString(fmt.Sprintf("**PolkitGuard Version:** %s  \n", "1.18.0"))

	sb.WriteString("\n---\n\n")

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Value |\n"))
	sb.WriteString(fmt.Sprintf("|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| Files Scanned | %d |\n", result.FilesScanned))
	sb.WriteString(fmt.Sprintf("| Rules Found | %d |\n", result.RulesFound))
	sb.WriteString(fmt.Sprintf("| Total Findings | %d |\n", len(result.Findings)))
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", len(result.GetFindingsByMinSeverity(models.SeverityCritical))))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", len(result.GetFindingsByMinSeverity(models.SeverityHigh))))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", len(result.GetFindingsByMinSeverity(models.SeverityMedium))))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n", len(result.GetFindingsByMinSeverity(models.SeverityLow))))

	if len(result.Findings) == 0 {
		sb.WriteString("\n---\n\n")
		sb.WriteString("## No Findings\n\n")
		sb.WriteString("No security issues detected in Polkit configurations.\n")
		return sb.String()
	}

	if result.HasCritical() {
		sb.WriteString("\n> **WARNING:** Critical security issues detected! Immediate action required.\n")
	}

	sb.WriteString("\n---\n\n")

	critical := filterFindings(result.Findings, models.SeverityCritical)
	high := filterFindings(result.Findings, models.SeverityHigh)
	medium := filterFindings(result.Findings, models.SeverityMedium)
	low := filterFindings(result.Findings, models.SeverityLow)

	if len(critical) > 0 {
		sb.WriteString("## Critical Findings\n\n")
		for _, f := range critical {
			writeFinding(&sb, f)
		}
	}

	if len(high) > 0 {
		sb.WriteString("## High Findings\n\n")
		for _, f := range high {
			writeFinding(&sb, f)
		}
	}

	if len(medium) > 0 {
		sb.WriteString("## Medium Findings\n\n")
		for _, f := range medium {
			writeFinding(&sb, f)
		}
	}

	if len(low) > 0 {
		sb.WriteString("## Low Findings\n\n")
		for _, f := range low {
			writeFinding(&sb, f)
		}
	}

	sb.WriteString("\n---\n\n")
	sb.WriteString("## Remediation Recommendations\n\n")

	if result.HasCritical() {
		sb.WriteString("### Immediate Actions (Critical)\n\n")
		sb.WriteString("1. Review all `result_any=yes` rules\n")
		sb.WriteString("2. Restrict `unix-user:*` access\n")
		sb.WriteString("3. Add authentication requirements\n")
		sb.WriteString("4. Test changes in non-production first\n\n")
	}

	if result.HasHigh() {
		sb.WriteString("### Priority Actions (High)\n\n")
		sb.WriteString("1. Limit `unix-group:all` permissions\n")
		sb.WriteString("2. Use specific users/groups instead of wildcards\n")
		sb.WriteString("3. Consider `auth_admin` for sensitive actions\n\n")
	}

	sb.WriteString("### General Best Practices\n\n")
	sb.WriteString("- Follow principle of least privilege\n")
	sb.WriteString("- Regularly audit admin group memberships\n")
	sb.WriteString("- Use `auth_admin_keep` for persistent actions\n")
	sb.WriteString("- Document all custom polkit rules\n")

	return sb.String()
}

func filterFindings(findings []models.Finding, severity models.Severity) []models.Finding {
	var filtered []models.Finding
	for _, f := range findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func writeFinding(sb *strings.Builder, f models.Finding) {
	sb.WriteString(fmt.Sprintf("### %s\n\n", f.RuleID))
	sb.WriteString(fmt.Sprintf("**Severity:** %s  \n", f.Severity))
	sb.WriteString(fmt.Sprintf("**Title:** %s\n\n", f.Title))
	sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", f.Description))

	if f.Rule != nil {
		sb.WriteString("**Affected Rule:**\n\n")
		sb.WriteString("```\n")
		sb.WriteString(fmt.Sprintf("[%s]\n", f.Rule.Identity))
		sb.WriteString(fmt.Sprintf("ResultAny=%s\n", f.Rule.ResultAny))
		if f.Rule.ResultActive != "" {
			sb.WriteString(fmt.Sprintf("ResultActive=%s\n", f.Rule.ResultActive))
		}
		if f.Rule.ResultInactive != "" {
			sb.WriteString(fmt.Sprintf("ResultInactive=%s\n", f.Rule.ResultInactive))
		}
		sb.WriteString("```\n\n")
	}

	sb.WriteString("---\n\n")
}