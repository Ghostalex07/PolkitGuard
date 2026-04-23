package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Ghostalex07/Polkit-Security-Scanner/internal/models"
)

type Reporter struct {
	minSeverity models.Severity
}

func NewReporter(minSeverity models.Severity) *Reporter {
	return &Reporter{minSeverity: minSeverity}
}

func (r *Reporter) Output(result models.ScanResult, format string) {
	findings := result.GetFindingsByMinSeverity(r.minSeverity)

	if len(findings) == 0 {
		fmt.Println("No security issues detected.")
		return
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			return findings[i].File < findings[j].File
		}
		return findings[i].Severity > findings[j].Severity
	})

	if format == "json" {
		r.outputJSON(findings)
	} else {
		r.outputText(findings)
	}
}

func (r *Reporter) outputText(findings []models.Finding) {
	reset := "\033[0m"
	bold := "\033[1m"

	fmt.Println(bold + "\n=== PolkitGuard Security Scan Results ===" + reset)
	fmt.Printf("\nFiles scanned: %d\n", len(findings))
	fmt.Printf("Issues found: %d\n\n", len(findings))

	for _, f := range findings {
		color := getSeverityColor(f.Severity)
		fmt.Printf("%s[%s] %s%s\n", color, f.Severity.String(), f.File, reset)
		fmt.Printf("  → %s\n", f.Message)
		fmt.Printf("  Impact: %s\n", f.Impact)
		fmt.Printf("  Recommendation: %s\n\n", f.Recommendation)
	}
}

func (r *Reporter) outputJSON(findings []models.Finding) {
	output := map[string]interface{}{
		"scanner":    "PolkitGuard",
		"findings":   findings,
		"total":      len(findings),
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

func getSeverityColor(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "\033[1;31m"
	case models.SeverityHigh:
		return "\033[35m"
	case models.SeverityMedium:
		return "\033[33m"
	case models.SeverityLow:
		return "\033[34m"
	default:
		return ""
	}
}