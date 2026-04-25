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
	Severity       models.Severity
	Description    string
	Impact         string
	Recommendation string
	CVE            string
	Check          func(rule models.PolkitRule) bool
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
		ID:             cr.ID,
		Severity:       sev,
		Description:    cr.Description,
		Impact:         cr.Impact,
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
		{
			ID:             "LOW-005",
			Severity:       models.SeverityLow,
			Description:    "No ResultAny specified",
			Impact:         "Undefined fallback behavior",
			Recommendation: "Specify explicit ResultAny",
			Check: func(rule models.PolkitRule) bool {
				return rule.ResultAny == "" && rule.ResultActive == "" && rule.ResultInactive == ""
			},
		},
		{
			ID:             "MED-005",
			Severity:       models.SeverityMedium,
			Description:    "Multiple rules for same action",
			Impact:         "Potential conflicts in authorization",
			Recommendation: "Consolidate rules for same action",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "org.freedesktop.login1") &&
					strings.Contains(rule.Raw, "result_")
			},
		},
		{
			ID:             "HIGH-009",
			Severity:       models.SeverityHigh,
			Description:    "Power management actions",
			Impact:         "Can power off or reboot system",
			Recommendation: "Restrict power actions to admins",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "power") ||
					strings.Contains(rule.Action, "reboot") ||
					strings.Contains(rule.Action, "suspend")
			},
		},
		{
			ID:             "CRIT-007",
			Severity:       models.SeverityCritical,
			Description:    "Console kit unrestricted",
			Impact:         "Can access console without auth",
			Recommendation: "Require admin auth for console",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "consolekit") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "CRIT-008",
			Severity:       models.SeverityCritical,
			Description:    "GDM (GNOME Display Manager) unrestricted",
			Impact:         "Can control display manager without auth",
			Recommendation: "Restrict GDM access to admins",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "gdm") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "HIGH-010",
			Severity:       models.SeverityHigh,
			Description:    "Package management actions",
			Impact:         "Can install/remove packages",
			Recommendation: "Restrict package management",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "package") ||
					strings.Contains(rule.Action, "apt") ||
					strings.Contains(rule.Action, "dnf") ||
					strings.Contains(rule.Action, "yum")
			},
		},
		{
			ID:             "MED-006",
			Severity:       models.SeverityMedium,
			Description:    "Timer/Job scheduling",
			Impact:         "Can schedule jobs",
			Recommendation: "Restrict scheduling to admins",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "timer") ||
					strings.Contains(rule.Action, "job")
			},
		},
		{
			ID:             "LOW-006",
			Severity:       models.SeverityLow,
			Description:    "Session cookie access",
			Impact:         "Can read session cookies",
			Recommendation: "Restrict session access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "session") &&
					rule.ResultAny != "auth_admin"
			},
		},
		{
			ID:             "LOW-007",
			Severity:       models.SeverityLow,
			Description:    "Undefined ResultAny fallback",
			Impact:         "May cause unexpected behavior",
			Recommendation: "Explicit ResultAny recommended",
			Check: func(rule models.PolkitRule) bool {
				return rule.ResultAny == "" &&
					(rule.ResultActive != "" || rule.ResultInactive != "")
			},
		},
		{
			ID:             "LOW-008",
			Severity:       models.SeverityLow,
			Description:    "Very broad action prefix",
			Impact:         "May match unintended actions",
			Recommendation: "Use specific action prefixes",
			Check: func(rule models.PolkitRule) bool {
				return len(rule.Action) > 5 &&
					strings.HasPrefix(rule.Action, "org.")
			},
		},
		{
			ID:             "MED-007",
			Severity:       models.SeverityMedium,
			Description:    "Conflicting authentication modes",
			Impact:         "May bypass security checks",
			Recommendation: "Use consistent auth modes",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.ResultAny, "auth_admin") &&
					rule.ResultActive == "yes"
			},
		},
		{
			ID:             "MED-008",
			Severity:       models.SeverityMedium,
			Description:    "Missing Identity in explicit rule",
			Impact:         "Rule may not apply correctly",
			Recommendation: "Define explicit identity",
			Check: func(rule models.PolkitRule) bool {
				return rule.Identity == "" && rule.Raw != "" &&
					!strings.Contains(rule.Raw, "return")
			},
		},
		{
			ID:             "HIGH-011",
			Severity:       models.SeverityHigh,
			Description:    "Logind session management",
			Impact:         "Can manage user sessions",
			Recommendation: "Restrict to admins",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "logind") ||
					strings.Contains(rule.Action, "login1")
			},
		},
		{
			ID:             "HIGH-012",
			Severity:       models.SeverityHigh,
			Description:    "DeviceKit storage management",
			Impact:         "Can access/modify storage",
			Recommendation: "Restrict storage access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "devicekit") ||
					strings.Contains(rule.Action, "udisks")
			},
		},
		{
			ID:             "CRIT-009",
			Severity:       models.SeverityCritical,
			Description:    "PolicyKit genie unrestricted",
			Impact:         "Full system access via genie",
			Recommendation: "Restrict genie access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "polkit-genie") ||
					strings.Contains(rule.Action, "genie")
			},
		},
		{
			ID:             "CRIT-010",
			Severity:       models.SeverityCritical,
			Description:    "KDE kscreensaver unrestricted",
			Impact:         "Can bypass screen lock",
			Recommendation: "Require auth for screen unlock",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "kscreensaver") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "CRIT-011",
			Severity:       models.SeverityCritical,
			Description:    "SUSE security policy bypass",
			Impact:         "Can bypass SUSE security",
			Recommendation: "Restrict SUSE policies",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "suse") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "CRIT-012",
			Severity:       models.SeverityCritical,
			Description:    "Alpine container root access",
			Impact:         "Full container access",
			Recommendation: "Restrict container access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "apparmor") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "HIGH-013",
			Severity:       models.SeverityHigh,
			Description:    "VirtualBox management",
			Impact:         "Can control VirtualBox VMs",
			Recommendation: "Restrict VM management",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "virtualbox") ||
					strings.Contains(rule.Action, "vbox")
			},
		},
		{
			ID:             "HIGH-014",
			Severity:       models.SeverityHigh,
			Description:    "VMware management",
			Impact:         "Can control VMware VMs",
			Recommendation: "Restrict VM management",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "vmware") ||
					strings.Contains(rule.Action, "vmtools")
			},
		},
		{
			ID:             "HIGH-015",
			Severity:       models.SeverityHigh,
			Description:    "Docker container management",
			Impact:         "Can manage containers",
			Recommendation: "Restrict container mgmt",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "docker") &&
					!strings.Contains(rule.Action, "org.freedesktop")
			},
		},
		{
			ID:             "MED-009",
			Severity:       models.SeverityMedium,
			Description:    "CUPS printer management",
			Impact:         "Can manage printers",
			Recommendation: "Restrict printer access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "cups") ||
					strings.Contains(rule.Action, "printer")
			},
		},
		{
			ID:             "MED-010",
			Severity:       models.SeverityMedium,
			Description:    "NetworkManager privileges",
			Impact:         "Can modify network",
			Recommendation: "Restrict network changes",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "NetworkManager") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "LOW-009",
			Severity:       models.SeverityLow,
			Description:    "Legacy action reference",
			Impact:         "Using deprecated action",
			Recommendation: "Update to current actions",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "deprecated") ||
					strings.Contains(rule.Action, ".obsolete")
			},
		},
		{
			ID:             "LOW-010",
			Severity:       models.SeverityLow,
			Description:    "Admin group without explicit result",
			Impact:         "May allow admin group",
			Recommendation: "Use explicit auth result",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Identity, "unix-group:wheel") &&
					rule.ResultAny == ""
			},
		},
		{
			ID:             "LOW-011",
			Severity:       models.SeverityLow,
			Description:    "Missing action in rule",
			Impact:         "Rules may not apply",
			Recommendation: "Define action explicitly",
			Check: func(rule models.PolkitRule) bool {
				return rule.Action == ""
			},
		},
		{
			ID:             "MED-011",
			Severity:       models.SeverityMedium,
			Description:    "ModemManager access",
			Impact:         "Can control network modems",
			Recommendation: "Restrict modem access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "modemmanager") ||
					strings.Contains(rule.Action, "ModemManager")
			},
		},
		{
			ID:             "CRIT-013",
			Severity:       models.SeverityCritical,
			Description:    "PolicyKit local privilege escalation",
			Impact:         "Full root access",
			Recommendation: "Require strong auth",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "polkit") &&
					strings.Contains(rule.Action, "local") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "HIGH-016",
			Severity:       models.SeverityHigh,
			Description:    "PackageKit access",
			Impact:         "Can install packages",
			Recommendation: "Restrict package installation",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "packagekit") ||
					strings.Contains(rule.Action, "PackageKit")
			},
		},
		{
			ID:             "CRIT-014",
			Severity:       models.SeverityCritical,
			Description:    "AWS EC2 instance connect",
			Impact:         "Can access EC2 instances",
			Recommendation: "Restrict EC2 access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "aws") &&
					strings.Contains(rule.Action, "ec2")
			},
		},
		{
			ID:             "CRIT-015",
			Severity:       models.SeverityCritical,
			Description:    "Kubernetes kubelet access",
			Impact:         "Can control Kubernetes nodes",
			Recommendation: "Restrict kubelet access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "kubelet") ||
					strings.Contains(rule.Action, "kubernetes")
			},
		},
		{
			ID:             "HIGH-017",
			Severity:       models.SeverityHigh,
			Description:    "Docker container escalated privileges",
			Impact:         "Can escalate container privileges",
			Recommendation: "Restrict container privs",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "docker") &&
					strings.Contains(rule.ResultAny, "yes")
			},
		},
		{
			ID:             "HIGH-018",
			Severity:       models.SeverityHigh,
			Description:    "Podman container access",
			Impact:         "Can manage containers",
			Recommendation: "Restrict podman access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "podman")
			},
		},
		{
			ID:             "MED-012",
			Severity:       models.SeverityMedium,
			Description:    "BlueZ Bluetooth access",
			Impact:         "Can control Bluetooth",
			Recommendation: "Restrict Bluetooth",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "bluez") ||
					strings.Contains(rule.Action, "bluetooth")
			},
		},
		{
			ID:             "MED-013",
			Severity:       models.SeverityMedium,
			Description:    "NetworkManager WiFi control",
			Impact:         "Can control WiFi",
			Recommendation: "Restrict WiFi access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "Wifi") ||
					strings.Contains(rule.Action, "wifi")
			},
		},
		{
			ID:             "LOW-012",
			Severity:       models.SeverityLow,
			Description:    "Undefined return statement",
			Impact:         "Rule may not behave as expected",
			Recommendation: "Add return statement",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Raw, "return")
			},
		},
		{
			ID:             "LOW-013",
			Severity:       models.SeverityLow,
			Description:    "Very permissive group match",
			Impact:         "Matches many groups",
			Recommendation: "Use specific groups",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Identity, "unix-group:*")
			},
		},
		{
			ID:             "CRIT-016",
			Severity:       models.SeverityCritical,
			Description:    "GCP Compute Engine access",
			Impact:         "Can access GCP instances",
			Recommendation: "Restrict GCP access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "gcp") &&
					strings.Contains(rule.Action, "compute")
			},
		},
		{
			ID:             "CRIT-017",
			Severity:       models.SeverityCritical,
			Description:    "Azure VM access",
			Impact:         "Can access Azure VMs",
			Recommendation: "Restrict Azure access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "azure") &&
					strings.Contains(rule.Action, "vm")
			},
		},
		{
			ID:             "HIGH-019",
			Severity:       models.SeverityHigh,
			Description:    "Containerd privileged",
			Impact:         "Can run privileged containers",
			Recommendation: "Restrict containerd",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "containerd") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "HIGH-020",
			Severity:       models.SeverityHigh,
			Description:    "CRI-O container access",
			Impact:         "Can manage CRI-O containers",
			Recommendation: "Restrict CRI-O",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "cri-o") ||
					strings.Contains(rule.Action, "crio")
			},
		},
		{
			ID:             "HIGH-021",
			Severity:       models.SeverityHigh,
			Description:    "AWS ECS container access",
			Impact:         "Can manage ECS tasks",
			Recommendation: "Restrict ECS",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "ecs") &&
					strings.Contains(rule.Action, "aws")
			},
		},
		{
			ID:             "MED-014",
			Severity:       models.SeverityMedium,
			Description:    "systemd-swamp daemon",
			Impact:         "Can manage systemd services",
			Recommendation: "Restrict systemd",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "systemd-") &&
					!strings.Contains(rule.Action, "org.freedesktop")
			},
		},
		{
			ID:             "MED-015",
			Severity:       models.SeverityMedium,
			Description:    "DBus activation",
			Impact:         "Can activate DBus services",
			Recommendation: "Restrict DBus",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "dbus") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "LOW-014",
			Severity:       models.SeverityLow,
			Description:    "Unused action field",
			Impact:         "Redundant rule",
			Recommendation: "Remove unused rules",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "unused") ||
					strings.Contains(rule.Action, "obsolete")
			},
		},
		{
			ID:             "LOW-015",
			Severity:       models.SeverityLow,
			Description:    "Incomplete rule",
			Impact:         "Rule incomplete",
			Recommendation: "Complete the rule",
			Check: func(rule models.PolkitRule) bool {
				return rule.Action != "" && rule.Identity == "" && rule.ResultAny == ""
			},
		},
		{
			ID:             "CRIT-018",
			Severity:       models.SeverityCritical,
			Description:    "OpenShift privileged pod",
			Impact:         "Can create privileged pods in OpenShift",
			Recommendation: "Restrict privileged pods",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "openshift") &&
					strings.Contains(rule.Action, "privileged")
			},
		},
		{
			ID:             "CRIT-019",
			Severity:       models.SeverityCritical,
			Description:    "Kubernetes hostPath mount",
			Impact:         "Can mount host filesystem",
			Recommendation: "Restrict hostPath mounts",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "hostpath") ||
					strings.Contains(rule.Action, "hostPath")
			},
		},
		{
			ID:             "CRIT-020",
			Severity:       models.SeverityCritical,
			Description:    "AWS Lambda function access",
			Impact:         "Can manage Lambda functions",
			Recommendation: "Restrict Lambda access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "lambda") &&
					strings.Contains(rule.Action, "aws")
			},
		},
		{
			ID:             "HIGH-022",
			Severity:       models.SeverityHigh,
			Description:    "runc container access",
			Impact:         "Can control container runc",
			Recommendation: "Restrict runc",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "runc")
			},
		},
		{
			ID:             "HIGH-023",
			Severity:       models.SeverityHigh,
			Description:    "systemd-coredump",
			Impact:         "Can access coredumps",
			Recommendation: "Restrict coredump access",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "coredump")
			},
		},
		{
			ID:             "HIGH-024",
			Severity:       models.SeverityHigh,
			Description:    "GCP Cloud Functions",
			Impact:         "Can manage Cloud Functions",
			Recommendation: "Restrict Cloud Functions",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "cloudfunctions") &&
					strings.Contains(rule.Action, "gcp")
			},
		},
		{
			ID:             "MED-016",
			Severity:       models.SeverityMedium,
			Description:    "NetworkManager dispatcher",
			Impact:         "Can run network scripts",
			Recommendation: "Restrict NM dispatcher",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "NetworkManager") &&
					strings.Contains(rule.Action, "dispatcher")
			},
		},
		{
			ID:             "MED-017",
			Severity:       models.SeverityMedium,
			Description:    "AccountsService access",
			Impact:         "Can manage user accounts",
			Recommendation: "Restrict accounts",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "accounts-daemon")
			},
		},
		{
			ID:             "MED-018",
			Severity:       models.SeverityMedium,
			Description:    "udisks2 full access",
			Impact:         "Can mount any disk",
			Recommendation: "Restrict udisks",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "udisks2") &&
					rule.ResultAny == "yes"
			},
		},
		{
			ID:             "LOW-016",
			Severity:       models.SeverityLow,
			Description:    "Unused polkit action",
			Impact:         "Action never called",
			Recommendation: "Remove unused actions",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "/internal/")
			},
		},
		{
			ID:             "LOW-017",
			Severity:       models.SeverityLow,
			Description:    "Debug polkit action",
			Impact:         "Debug action exposed",
			Recommendation: "Remove debug actions",
			Check: func(rule models.PolkitRule) bool {
				return strings.Contains(rule.Action, "debug") ||
					strings.Contains(rule.Action, ".debug")
			},
		},
		{
			ID:             "LOW-018",
			Severity:       models.SeverityLow,
			Description:    "Empty identity match",
			Impact:         "Matches no one",
			Recommendation: "Define explicit identity",
			Check: func(rule models.PolkitRule) bool {
				return rule.Identity == "unix-user:"
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
				Severity:       detectionRule.Severity,
				File:           rule.File,
				RuleName:       rule.RuleName,
				Message:        detectionRule.Description,
				Impact:         detectionRule.Impact,
				Recommendation: detectionRule.Recommendation,
				CVE:            detectionRule.CVE,
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
