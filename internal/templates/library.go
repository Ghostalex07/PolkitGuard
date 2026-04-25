package templates

import (
	"fmt"
	"strings"
)

type PolicyTemplate struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Rules       []string `json:"rules"`
	Severity    string   `json:"severity"`
	Actions     []string `json:"actions"`
}

var Library = []PolicyTemplate{
	{
		Name:        "Admin Only",
		Description: "Restrict system administration to designated admins only",
		Category:    "System Administration",
		Severity:    "HIGH",
		Actions:     []string{"org.freedesktop.systemd1.*"},
		Rules: []string{
			"[unix-group:wheel]",
			"ResultAny=auth_admin_keep",
			"ResultActive=auth_admin_keep",
			"ResultInactive=auth_admin_keep",
		},
	},
	{
		Name:        "Service Management",
		Description: "Control systemd service management permissions",
		Category:    "Services",
		Severity:    "HIGH",
		Actions:     []string{"org.freedesktop.systemd1.manage-units"},
		Rules: []string{
			"[unix-user:systemd-network]",
			"ResultAny=no",
		},
	},
	{
		Name:        "Network Configuration",
		Description: "Restrict network configuration changes",
		Category:    "Network",
		Severity:    "HIGH",
		Actions:     []string{"org.freedesktop.network1.*", "org.freedesktop.NetworkManager.*"},
		Rules: []string{
			"[unix-group:netadmin]",
			"ResultAny=auth_admin",
			"[unix-user:*]",
			"ResultAny=no",
		},
	},
	{
		Name:        "Package Management",
		Description: "Control package installation and removal",
		Category:    "Packages",
		Severity:    "CRITICAL",
		Actions:     []string{"org.archlinux.pkexec.*", "org.debian.pkexec.*"},
		Rules: []string{
			"[unix-group:wheel]",
			"ResultAny=auth_admin_keep",
			"[unix-user:*]",
			"ResultAny=no",
		},
	},
	{
		Name:        "Device Management",
		Description: "Control hardware device access",
		Category:    "Hardware",
		Severity:    "MEDIUM",
		Actions:     []string{"org.freedesktop.udisks2.*"},
		Rules: []string{
			"[unix-group:plugdev]",
			"ResultAny=yes",
			"[unix-user:*]",
			"ResultActive=yes",
			"ResultInactive=auth_admin",
		},
	},
	{
		Name:        "Printing",
		Description: "Control printer access",
		Category:    "Hardware",
		Severity:    "LOW",
		Actions:     []string{"org.freedesktop.cups.*"},
		Rules: []string{
			"[unix-user:*]",
			"ResultAny=auth_self",
			"[unix-group:lpadmin]",
			"ResultAny=yes",
		},
	},
	{
		Name:        "Power Management",
		Description: "Control system shutdown and suspend",
		Category:    "System",
		Severity:    "MEDIUM",
		Actions:     []string{"org.freedesktop.login1.*", "org.gnome.settings-daemon.*"},
		Rules: []string{
			"[unix-user:*]",
			"ResultActive=yes",
			"ResultInactive=auth_admin",
		},
	},
	{
		Name:        "User Management",
		Description: "Control user account modifications",
		Category:    "Users",
		Severity:    "CRITICAL",
		Actions:     []string{"org.freedesktopAccounts.*"},
		Rules: []string{
			"[unix-group:wheel]",
			"ResultAny=auth_admin_keep",
			"[unix-user:root]",
			"ResultAny=auth_admin",
		},
	},
	{
		Name:        "Read-Only Monitor",
		Description: "Allow read-only monitoring without authentication",
		Category:    "Monitoring",
		Severity:    "LOW",
		Actions:     []string{"org.freedesktop.systemd1.get-unit-properties"},
		Rules: []string{
			"[unix-user:*]",
			"ResultAny=yes",
			"ResultActive=yes",
			"ResultInactive=yes",
		},
	},
	{
		Name:        "Session Management",
		Description: "Control session creation and termination",
		Category:    "Sessions",
		Severity:    "MEDIUM",
		Actions:     []string{"org.freedesktop.login1.*"},
		Rules: []string{
			"[unix-user:*]",
			"ResultActive=yes",
			"ResultInactive=auth_admin",
		},
	},
}

func GetTemplatesByCategory(category string) []PolicyTemplate {
	var templates []PolicyTemplate
	for _, t := range Library {
		if strings.EqualFold(t.Category, category) {
			templates = append(templates, t)
		}
	}
	return templates
}

func GetTemplatesBySeverity(severity string) []PolicyTemplate {
	var templates []PolicyTemplate
	for _, t := range Library {
		if strings.EqualFold(t.Severity, severity) {
			templates = append(templates, t)
		}
	}
	return templates
}

func SearchTemplates(query string) []PolicyTemplate {
	var templates []PolicyTemplate
	queryLower := strings.ToLower(query)
	for _, t := range Library {
		if strings.Contains(strings.ToLower(t.Name), queryLower) ||
			strings.Contains(strings.ToLower(t.Description), queryLower) ||
			strings.Contains(strings.ToLower(t.Category), queryLower) {
			templates = append(templates, t)
		}
	}
	return templates
}

func (t *PolicyTemplate) GenerateRulesFile() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s\n", t.Name))
	sb.WriteString(fmt.Sprintf("# %s\n", t.Description))
	sb.WriteString(fmt.Sprintf("# Category: %s\n", t.Category))
	sb.WriteString("#\n\n")

	for i := 0; i < len(t.Rules); i += 4 {
		for j := i; j < i+4 && j < len(t.Rules); j++ {
			sb.WriteString(t.Rules[j])
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func ListCategories() []string {
	seen := make(map[string]bool)
	var categories []string
	for _, t := range Library {
		if !seen[t.Category] {
			categories = append(categories, t.Category)
			seen[t.Category] = true
		}
	}
	return categories
}