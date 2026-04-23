package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type Reporter struct {
	minSeverity models.Severity
}

type ReportStats struct {
	FilesScanned int
	RulesFound  int
	Critical  int
	High      int
	Medium    int
	Low       int
	Total     int
}

func NewReporter(minSeverity models.Severity) *Reporter {
	return &Reporter{minSeverity: minSeverity}
}

func (r *Reporter) CalculateStats(result models.ScanResult) ReportStats {
	findings := result.Findings
	stats := ReportStats{
		FilesScanned: result.FilesScanned,
		RulesFound:  result.RulesFound,
		Total:     len(findings),
	}
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			stats.Critical++
		case models.SeverityHigh:
			stats.High++
		case models.SeverityMedium:
			stats.Medium++
		case models.SeverityLow:
			stats.Low++
		}
	}
	return stats
}

func (r *Reporter) Output(result models.ScanResult, format string) {
	findings := result.GetFindingsByMinSeverity(r.minSeverity)

	if len(findings) == 0 {
		fmt.Println("No security issues detected.")
		return
	}

	stats := r.CalculateStats(result)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			return findings[i].File < findings[j].File
		}
		return findings[i].Severity > findings[j].Severity
	})

	if format == "json" {
		r.outputJSON(findings, stats)
	} else if format == "html" {
		r.outputHTML(findings, stats)
	} else {
		r.outputText(findings, stats)
	}
}

func (r *Reporter) outputText(findings []models.Finding, stats ReportStats) {
	reset := "\033[0m"
	bold := "\033[1m"

	fmt.Println(bold + "=== PolkitGuard Security Scan Results ===" + reset)
	fmt.Printf("\nFiles scanned: %d\n", stats.FilesScanned)
	fmt.Printf("Rules analyzed: %d\n", stats.RulesFound)
	fmt.Printf("Total issues: %d\n", stats.Total)
	fmt.Println("-----------------------------------")
	fmt.Printf("  Critical: %d\n", stats.Critical)
	fmt.Printf("  High: %d\n", stats.High)
	fmt.Printf("  Medium: %d\n", stats.Medium)
	fmt.Printf("  Low: %d\n\n", stats.Low)

	for _, f := range findings {
		color := getSeverityColor(f.Severity)
		fmt.Printf("%s[%s] %s%s\n", color, f.Severity.String(), f.File, reset)
		fmt.Printf("  → %s\n", f.Message)
		fmt.Printf("  Impact: %s\n", f.Impact)
		fmt.Printf("  Recommendation: %s\n\n", f.Recommendation)
	}
}

func (r *Reporter) outputJSON(findings []models.Finding, stats ReportStats) {
	output := map[string]interface{}{
		"scanner":    "PolkitGuard",
		"findings":   findings,
		"stats": map[string]int{
			"files_scanned": stats.FilesScanned,
			"rules_found":  stats.RulesFound,
			"total":      stats.Total,
			"critical":   stats.Critical,
			"high":       stats.High,
			"medium":    stats.Medium,
			"low":       stats.Low,
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

func (r *Reporter) outputHTML(findings []models.Finding, stats ReportStats) {
	html := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>PolkitGuard Scan Results</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
		.container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
		h1 { color: #333; }
		.stats { display: flex; gap: 15px; margin: 20px 0; }
		.stat { padding: 15px 25px; border-radius: 5px; text-align: center; color: white; font-weight: bold; }
		.critical { background: #dc3545; }
		.high { background: #6f42c1; }
		.medium { background: #ffc107; color: #333; }
		.low { background: #17a2b8; }
		.finding { margin: 15px 0; padding: 15px; border-left: 4px solid #ccc; background: #f9f9f9; }
		.finding.critical { border-color: #dc3545; }
		.finding.high { border-color: #6f42c1; }
		.finding.medium { border-color: #ffc107; }
		.finding.low { border-color: #17a2b8; }
		.impact { color: #666; margin-top: 5px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>🛡️ PolkitGuard Security Scan Results</h1>
		<div class="stats">
			<div class="stat critical">Critical: ` + fmt.Sprint(stats.Critical) + `</div>
			<div class="stat high">High: ` + fmt.Sprint(stats.High) + `</div>
			<div class="stat medium">Medium: ` + fmt.Sprint(stats.Medium) + `</div>
			<div class="stat low">Low: ` + fmt.Sprint(stats.Low) + `</div>
		</div>
		<p>Files scanned: ` + fmt.Sprint(stats.FilesScanned) + ` | Rules analyzed: ` + fmt.Sprint(stats.RulesFound) + `</p>
`

	for _, f := range findings {
		severityClass := strings.ToLower(f.Severity.String())
		html += fmt.Sprintf(`		<div class="finding %s">
			<strong>[%s] %s</strong><br>
			<span>%s</span>
			<div class="impact">Impact: %s</div>
			<div>Recommendation: %s</div>
		</div>
`, severityClass, f.Severity.String(), f.File, f.Message, f.Impact, f.Recommendation)
	}

	html += `	</div>
</body>
</html>`

	fmt.Println(html)
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