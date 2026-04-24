package remediation

import (
	"fmt"
	"os"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type Remediation struct {
	RuleID    string
	FixScript string
	Original  string
}

var remediationMap = map[string]Remediation{
	"CRIT-001": {
		RuleID:    "CRIT-001",
		FixScript: "sed -i 's/result_any=yes/result_any=auth_admin_keep/' $FILE",
		Original:  "result_any=yes",
	},
	"CRIT-002": {
		RuleID:    "CRIT-002",
		FixScript: "sed -i 's/unix-user:\\*/unix-user:admin/' $FILE",
		Original:  "unix-user:*",
	},
	"CRIT-005": {
		RuleID:    "CRIT-005",
		FixScript: "sed -i 's/result_any=yes/result_any=auth_admin/' $FILE",
		Original:  "result_any=yes",
	},
	"HIGH-001": {
		RuleID:    "HIGH-001",
		FixScript: "sed -i 's/unix-group:all/unix-group:wheel/' $FILE",
		Original:  "unix-group:all",
	},
	"HIGH-002": {
		RuleID:    "HIGH-002",
		FixScript: "sed -i 's/\\*/specific-action/' $FILE",
		Original:  "*",
	},
	"HIGH-003": {
		RuleID:    "HIGH-003",
		FixScript: "sed -i 's/\\*/specific-action/' $FILE",
		Original:  "*",
	},
	"CRIT-006": {
		RuleID:    "CRIT-006",
		FixScript: "sed -i 's/unix-user:0/unix-user:admin/' $FILE",
		Original:  "unix-user:0",
	},
}

func GetRemediation(finding models.Finding) *Remediation {
	if rem, ok := remediationMap[finding.RuleName]; ok {
		return &rem
	}

	return &Remediation{
		RuleID:    finding.RuleName,
		FixScript: "# Manual review required for: " + finding.RuleName,
		Original:  finding.Message,
	}
}

func GenerateFixScript(findings []models.Finding) string {
	var script strings.Builder

	script.WriteString("#!/bin/bash\n")
	script.WriteString("# PolkitGuard Auto-Remediation Script\n")
	script.WriteString("# Run as root or with sudo\n\n")

	script.WriteString("set -e\n\n")

	script.WriteString("BACKUP_DIR=\"/var/backups/polkitguard-$(date +%Y%m%d-%H%M%S)\"\n")
	script.WriteString("mkdir -p \"$BACKUP_DIR\"\n\n")

	for i, f := range findings {
		rem := GetRemediation(f)
		script.WriteString(fmt.Sprintf("# Fix %d: %s\n", i+1, f.RuleName))
		script.WriteString(fmt.Sprintf("# %s\n", f.Message))

		if strings.Contains(rem.FixScript, "$FILE") {
			script.WriteString(fmt.Sprintf("FILE=\"/etc/polkit-1/local.d/%s.rules\"\n", f.RuleName))
		}

		script.WriteString(rem.FixScript + "\n")
		script.WriteString(fmt.Sprintf("cp $FILE \"$BACKUP_DIR/\" 2>/dev/null || true\n\n"))
	}

	script.WriteString("echo \"Remediation complete. Review changes and restart polkit:\"\n")
	script.WriteString("# systemctl restart polkit\n\n")

	return script.String()
}

func (r *Remediation) Apply(content string) string {
	replacer := strings.NewReplacer(r.Original, "", r.Original, "")
	return replacer.Replace(content)
}

func (r *Remediation) ApplyToFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	content := string(data)
	content = r.Apply(content)
	return os.WriteFile(filePath, []byte(content), 0644)
}

type FixConfig struct {
	AutoApply bool
	Backup    bool
	DryRun    bool
}

func NewFixConfig() *FixConfig {
	return &FixConfig{
		AutoApply: false,
		Backup:    true,
		DryRun:    false,
	}
}

func GetDescription(ruleID string) string {
	descriptions := map[string]string{
		"CRIT-001": "Change 'result_any=yes' to 'result_any=auth_admin_keep'",
		"CRIT-002": "Replace 'unix-user:*' with specific user",
		"CRIT-005": "Change 'result_any=yes' to 'result_any=auth_admin'",
		"CRIT-006": "Replace 'unix-user:0' with admin user",
		"HIGH-001": "Replace 'unix-group:all' with specific group",
		"HIGH-002": "Remove wildcards from action patterns",
		"HIGH-005": "Restrict systemd access to admins only",
		"MED-001":  "Add explicit identity check",
		"LOW-001":  "Review ResultInactive vs ResultActive",
	}

	if desc, ok := descriptions[ruleID]; ok {
		return desc
	}
	return "Manual review required"
}
