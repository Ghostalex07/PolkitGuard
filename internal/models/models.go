package models

import "fmt"

type Severity int

const (
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) Color() string {
	switch s {
	case SeverityLow:
		return "\033[34m"
	case SeverityMedium:
		return "\033[33m"
	case SeverityHigh:
		return "\033[35m"
	case SeverityCritical:
		return "\033[31m"
	default:
		return "\033[0m"
	}
}

type Finding struct {
	Severity        Severity
	File            string
	Rule            string
	Message         string
	Impact          string
	Recommendation  string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s\n  Rule: %s\n  Message: %s\n  Impact: %s\n  Recommendation: %s\n",
		f.Severity.String(), f.File, f.Rule, f.Message, f.Impact, f.Recommendation)
}

type PolkitRule struct {
	Identity      string
	Action        string
	ResultAny     string
	ResultActive  string
	ResultInactive string
	Raw           string
	File          string
	LineNumber    int
}

type ScanResult struct {
	Findings []Finding
	FilesScanned int
	RulesFound   int
}

func NewScanResult() *ScanResult {
	return &ScanResult{
		Findings: []Finding{},
	}
}

func (sr *ScanResult) AddFinding(f Finding) {
	sr.Findings = append(sr.Findings, f)
}

func (sr *ScanResult) GetFindingsByMinSeverity(min Severity) []Finding {
	var filtered []Finding
	for _, f := range sr.Findings {
		if f.Severity >= min {
			filtered = append(filtered, f)
		}
	}
	return filtered
}