package remediation

import (
	"fmt"
	"strings"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type RemediationPlan struct {
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Steps       []RemediationStep  `json:"steps"`
	BackupPath  string             `json:"backup_path"`
	Estimated   string             `json:"estimated_time"`
	Risk        string             `json:"risk_level"`
}

type RemediationStep struct {
	Order       int    `json:"order"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	Content     string `json:"content,omitempty"`
	Validate    string `json:"validation,omitempty"`
	Rollback    string `json:"rollback,omitempty"`
}

func GenerateRemediationPlan(findings []models.Finding) *RemediationPlan {
	plan := &RemediationPlan{
		Title:       "Polkit Security Remediation Plan",
		Description: "Generated remediation plan for Polkit policy findings",
		Steps:       []RemediationStep{},
		Estimated:   estimateTime(len(findings)),
		Risk:        assessRemediationRisk(findings),
	}

	criticalFindings := filterBySeverity(findings, models.SeverityCritical)
	highFindings := filterBySeverity(findings, models.SeverityHigh)
	mediumFindings := filterBySeverity(findings, models.SeverityMedium)

	plan.Steps = append(plan.Steps, RemediationStep{
		Order:       1,
		Action:      "backup",
		Description: "Create backup of current polkit configuration",
		Command:     "cp -r /etc/polkit-1 /var/backups/polkit-1.bak.$(date +%Y%m%d)",
		Validate:    "ls -la /var/backups/polkit-1.bak.*",
	})

	order := 2

	for _, f := range criticalFindings {
		plan.Steps = append(plan.Steps, generateRemediationStep(f, order))
		order++
	}

	for _, f := range highFindings {
		plan.Steps = append(plan.Steps, generateRemediationStep(f, order))
		order++
	}

	for _, f := range mediumFindings {
		plan.Steps = append(plan.Steps, generateRemediationStep(f, order))
		order++
	}

	plan.Steps = append(plan.Steps, RemediationStep{
		Order:       order,
		Action:      "verify",
		Description: "Verify remediation with PolkitGuard scan",
		Command:     "polkitguard --path /etc/polkit-1 --severity low",
		Validate:    "Exit code should be 0 or only LOW findings",
	})

	return plan
}

func filterBySeverity(findings []models.Finding, severity models.Severity) []models.Finding {
	var filtered []models.Finding
	for _, f := range findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func generateRemediationStep(finding models.Finding, order int) RemediationStep {
	step := RemediationStep{
		Order:       order,
		Description: fmt.Sprintf("Fix %s: %s", finding.RuleID, finding.Title),
	}

	if finding.Rule != nil {
		action := finding.Rule.Action
		identity := finding.Rule.Identity

		if strings.Contains(action, "*") || identity == "unix-user:*" {
			step.Action = "restrict"
			step.Description += " - Remove overly permissive wildcards"
			step.Content = generateRestrictedRule(finding.Rule)
			step.Rollback = "# Rollback: restore from backup"
		} else if strings.Contains(finding.Rule.ResultAny, "yes") {
			step.Action = "require_auth"
			step.Description += " - Require authentication"
			step.Content = generateAuthRequiredRule(finding.Rule)
			step.Rollback = "# Rollback: restore from backup"
		} else {
			step.Action = "review"
			step.Description += " - Manual review required"
		}
	}

	return step
}

func generateRestrictedRule(rule *models.PolkitRule) string {
	var sb strings.Builder
	sb.WriteString("# Recommended secure rule for: ")
	sb.WriteString(rule.Action)
	sb.WriteString("\n[")
	if strings.Contains(rule.Identity, "unix-user:") {
		sb.WriteString("unix-user:admin]\n")
	} else if strings.Contains(rule.Identity, "unix-group:") {
		sb.WriteString("unix-group:wheel]\n")
	} else {
		sb.WriteString(rule.Identity)
		sb.WriteString("]\n")
	}
	sb.WriteString("ResultAny=auth_admin\n")
	sb.WriteString("ResultActive=auth_admin\n")
	sb.WriteString("ResultInactive=auth_admin_keep\n")
	return sb.String()
}

func generateAuthRequiredRule(rule *models.PolkitRule) string {
	var sb strings.Builder
	sb.WriteString("# Auth required rule for: ")
	sb.WriteString(rule.Action)
	sb.WriteString("\n[")
	sb.WriteString(rule.Identity)
	sb.WriteString("]\n")

	if strings.Contains(rule.Action, "system") || strings.Contains(rule.Action, "service") {
		sb.WriteString("ResultAny=auth_admin_keep\n")
	} else {
		sb.WriteString("ResultAny=auth_admin\n")
	}

	return sb.String()
}

func estimateTime(findings int) string {
	switch {
	case findings > 20:
		return "2-4 hours"
	case findings > 10:
		return "1-2 hours"
	case findings > 5:
		return "30-60 minutes"
	default:
		return "15-30 minutes"
	}
}

func assessRemediationRisk(findings []models.Finding) string {
	criticalCount := len(filterBySeverity(findings, models.SeverityCritical))

	switch {
	case criticalCount > 5:
		return "HIGH - Many critical issues, test in dev first"
	case criticalCount > 0:
		return "MEDIUM - Contains critical fixes"
	default:
		return "LOW - Routine remediation"
	}
}

func (p *RemediationPlan) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# Polkit Security Remediation Plan\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format(time.RFC822)))
	sb.WriteString(fmt.Sprintf("**Risk Level:** %s\n\n", p.Risk))
	sb.WriteString(fmt.Sprintf("**Estimated Time:** %s\n\n", p.Estimated))
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- Total Steps: %d\n", len(p.Steps)))
	sb.WriteString(fmt.Sprintf("- Critical Fixes: %d\n", countActions(p.Steps, "require_auth")))
	sb.WriteString(fmt.Sprintf("- Restriction Fixes: %d\n", countActions(p.Steps, "restrict")))

	sb.WriteString("\n## Steps\n\n")
	for _, step := range p.Steps {
		sb.WriteString(fmt.Sprintf("### %d. %s\n\n", step.Order, step.Description))
		if step.Command != "" {
			sb.WriteString("```bash\n")
			sb.WriteString(step.Command)
			sb.WriteString("\n```\n\n")
		}
		if step.Content != "" {
			sb.WriteString("**Recommended Content:**\n\n")
			sb.WriteString("```\n")
			sb.WriteString(step.Content)
			sb.WriteString("\n```\n\n")
		}
		if step.Rollback != "" {
			sb.WriteString("**Rollback:**\n")
			sb.WriteString(step.Rollback)
			sb.WriteString("\n\n")
		}
	}

	return sb.String()
}

func countActions(steps []RemediationStep, action string) int {
	count := 0
	for _, s := range steps {
		if s.Action == action {
			count++
		}
	}
	return count
}