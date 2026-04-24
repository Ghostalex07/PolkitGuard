package openscap

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type ScanResult struct {
	XMLName    xml.Name   `xml:"xccdf-results"`
	TestResult TestResult `xml:"test-result"`
}

type TestResult struct {
	RuleResults []RuleResult `xml:"rule-result"`
}

type RuleResult struct {
	RuleID   string `xml:"idref"`
	Result   string `xml:"result"`
	Severity string `xml:"severity,omitempty"`
	Message  string `xml:"message,omitempty"`
}

type Runner struct {
	oscapPath string
}

func NewRunner() (*Runner, error) {
	path, err := exec.LookPath("oscap")
	if err != nil {
		return nil, fmt.Errorf("oscap not found: %w", err)
	}
	return &Runner{oscapPath: path}, nil
}

func (r *Runner) Scan() (*ScanResult, error) {
	cmd := exec.Command(r.oscapPath, "xccdf", "eval", "--profile", "standard", "/usr/share/xml/scap/ssg/content/ssg-linux-ds.xml")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("oscap scan failed: %w", err)
	}

	var result ScanResult
	if err := xml.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse oscap output: %w", err)
	}

	return &result, nil
}

func (r *Runner) GetPolkitFindings() []string {
	var findings []string

	result, err := r.Scan()
	if err != nil {
		findings = append(findings, fmt.Sprintf("OpenSCAP scan failed: %v", err))
		return findings
	}

	for _, rule := range result.TestResult.RuleResults {
		if strings.Contains(rule.RuleID, "polkit") && rule.Result == "fail" {
			msg := fmt.Sprintf("[%s] %s", rule.Result, rule.RuleID)
			if rule.Severity != "" {
				msg += fmt.Sprintf(" (%s)", rule.Severity)
			}
			findings = append(findings, msg)
		}
	}

	return findings
}

func (r *Runner) ExportPolkitXCCDF(outputPath string) error {
	cmd := exec.Command(r.oscapPath, "xccdf", "generate", "fix", "--template", "bash", "--profile", "standard", "--fix-type", "bash", "/usr/share/xml/scap/ssg/content/ssg-linux-ds.xml")
	data, err := cmd.Output()
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0755)
}

func CheckPolkitCompliance() ([]string, error) {
	runner, err := NewRunner()
	if err != nil {
		return nil, err
	}
	return runner.GetPolkitFindings(), nil
}

type Report struct {
	XMLName    xml.Name `xml:"xccdf-results"`
	Platform   string   `xml:"platform,attr"`
	TestSystem string   `xml:"test-system"`
	Version    string   `xml:"version"`
	Stats      Stats    `xml:"statistics"`
	Rules      []Rule   `xml:"rule-result"`
}

type Stats struct {
	Pass          int `xml:"pass"`
	Fail          int `xml:"fail"`
	Error         int `xml:"error"`
	NotApplicable int `xml:"not-applicable"`
	NotChecked    int `xml:"not-checked"`
	Fixed         int `xml:"fixed"`
}

type Rule struct {
	ID       string `xml:"idref"`
	Time     string `xml:"time"`
	Result   string `xml:"result"`
	Severity string `xml:"severity,omitempty"`
	Message  string `xml:"message,omitempty"`
	Detail   string `xml:"detail,omitempty"`
}

func GenerateReport(results []string) Report {
	report := Report{
		Platform:   "linux",
		TestSystem: "polkitguard",
		Version:    "1.14.0",
	}

	for _, r := range results {
		rule := Rule{
			Result: "fail",
		}
		if strings.Contains(r, "CRITICAL") {
			rule.Severity = "high"
			rule.ID = "polkit:critical"
			report.Stats.Fail++
		} else if strings.Contains(r, "HIGH") {
			rule.Severity = "medium"
			rule.ID = "polkit:high"
			report.Stats.Fail++
		} else {
			rule.ID = "polkit:low"
			report.Stats.NotApplicable++
		}
		rule.Message = r
		report.Rules = append(report.Rules, rule)
	}

	if len(results) == 0 {
		report.Stats.Pass = 1
	}

	return report
}
