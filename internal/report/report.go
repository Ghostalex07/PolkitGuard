package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

var version = "1.18.0"

type Reporter struct {
	minSeverity models.Severity
}

type ReportStats struct {
	FilesScanned int
	RulesFound   int
	Critical     int
	High         int
	Medium       int
	Low          int
	Total        int
}

func NewReporter(minSeverity models.Severity) *Reporter {
	return &Reporter{minSeverity: minSeverity}
}

func (r *Reporter) CalculateStats(result models.ScanResult) ReportStats {
	findings := result.Findings
	stats := ReportStats{
		FilesScanned: result.FilesScanned,
		RulesFound:   result.RulesFound,
		Total:        len(findings),
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

	r.outputByFormat(findings, stats, format)
}

func (r *Reporter) outputByFormat(findings []models.Finding, stats ReportStats, format string) {
	switch format {
	case "json":
		r.outputJSON(findings, stats)
	case "html":
		r.outputHTML(findings, stats)
	case "sarif":
		r.outputSARIF(findings, stats)
	case "csv":
		r.outputCSV(findings, stats)
	case "pdf":
		r.outputPDF(findings, stats)
	case "junit":
		r.outputJUnit(findings, stats)
	default:
		r.outputText(findings, stats)
	}
}

func (r *Reporter) outputJUnit(findings []models.Finding, stats ReportStats) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="PolkitGuard" tests="` + fmt.Sprint(stats.Total) + `" failures="` + fmt.Sprint(stats.Critical+stats.High) + `" errors="0" skip="0" time="0.000">
`
	for _, f := range findings {
		status := "passed"
		if f.Severity >= models.SeverityMedium {
			status = "failed"
		}
		xml += "\t<testcase name=\""
		xml += escapeXML(f.RuleName) + "\" classname=\"PolkitGuard\">\n"
		if status == "failed" {
			xml += "\t\t<failure message=\""
			xml += escapeXML(f.Message) + "\" type=\""
			xml += f.Severity.String() + "\">"
			xml += escapeXML(f.Impact) + "</failure>\n"
		}
		xml += "\t</testcase>\n"
	}
	xml += "</testsuite>"
	fmt.Println(xml)
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func (r *Reporter) outputPDF(findings []models.Finding, stats ReportStats) {
	html := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>PolkitGuard Security Scan Report</title>
	<style>
		@page { size: A4; margin: 2cm; }
		body { font-family: Arial, sans-serif; font-size: 12pt; }
		h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
		.summary { background: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 5px; }
		.stats { display: flex; gap: 15px; margin: 15px 0; }
		.stat { padding: 10px 20px; border-radius: 3px; text-align: center; color: white; }
		.critical { background: #dc3545; }
		.high { background: #6f42c1; }
		.medium { background: #ffc107; color: #333; }
		.low { background: #17a2b8; }
		.finding { margin: 15px 0; padding: 10px; border-left: 3px solid #ccc; background: #fafafa; }
		.finding.critical { border-color: #dc3545; }
		.finding.high { border-color: #6f42c1; }
		.finding.medium { border-color: #ffc107; }
		.finding.low { border-color: #17a2b8; }
		.meta { color: #666; font-size: 10pt; margin-top: 30px; }
	</style>
</head>
<body>
	<h1>PolkitGuard Security Scan Report</h1>
	<div class="summary">
		<h2>Summary</h2>
		<p>Files scanned: ` + fmt.Sprint(stats.FilesScanned) + ` | Rules analyzed: ` + fmt.Sprint(stats.RulesFound) + `</p>
		<div class="stats">
			<div class="stat critical">Critical: ` + fmt.Sprint(stats.Critical) + `</div>
			<div class="stat high">High: ` + fmt.Sprint(stats.High) + `</div>
			<div class="stat medium">Medium: ` + fmt.Sprint(stats.Medium) + `</div>
			<div class="stat low">Low: ` + fmt.Sprint(stats.Low) + `</div>
		</div>
	</div>
	<h2>Findings</h2>`

	for _, f := range findings {
		sev := f.Severity.String()
		html += "\n\t<div class=\"finding " + strings.ToLower(sev) + "\">"
		html += "\n\t\t<strong>[" + sev + "] " + f.File + "</strong>"
		html += "\n\t\t<p>" + f.Message + "</p>"
		if f.Impact != "" {
			html += "\n\t\t<p>Impact: " + f.Impact + "</p>"
		}
		if f.Recommendation != "" {
			html += "\n\t\t<p>Recommendation: " + f.Recommendation + "</p>"
		}
		html += "\n\t</div>"
	}

	html += `
	<div class="meta">
		<p>Generated by PolkitGuard v` + version + ` on ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
	</div>
</body>
</html>`

	fmt.Println(html)
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
		"scanner":  "PolkitGuard",
		"version":  version,
		"findings": findings,
		"stats": map[string]int{
			"files_scanned": stats.FilesScanned,
			"rules_found":   stats.RulesFound,
			"total":         stats.Total,
			"critical":      stats.Critical,
			"high":          stats.High,
			"medium":        stats.Medium,
			"low":           stats.Low,
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

func (r *Reporter) outputSARIF(findings []models.Finding, stats ReportStats) {
	rules := []map[string]interface{}{}
	results := []map[string]interface{}{}
	ruleMap := map[string]bool{}

	for i, f := range findings {
		ruleID := fmt.Sprintf("RULE%d", i+1)
		if !ruleMap[ruleID] {
			rules = append(rules, map[string]interface{}{
				"id":               ruleID,
				"name":             f.Message,
				"shortDescription": map[string]string{"text": f.Message},
				"helpUri":          "https://github.com/Ghostalex07/PolkitGuard",
				"defaultConfiguration": map[string]interface{}{
					"level": getSARIFLevel(f.Severity),
				},
			})
			ruleMap[ruleID] = true
		}

		results = append(results, map[string]interface{}{
			"ruleId":  ruleID,
			"level":   getSARIFLevel(f.Severity),
			"message": map[string]string{"text": f.Message},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": f.File,
						},
					},
				},
			},
		})
	}

	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "PolkitGuard",
						"version":        version,
						"informationUri": "https://github.com/Ghostalex07/PolkitGuard",
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(sarif)
}

func (r *Reporter) outputCSV(findings []models.Finding, stats ReportStats) {
	fmt.Println("Severity,File,Rule,Message,Impact,Recommendation")
	for _, f := range findings {
		severity := f.Severity.String()
		file := escapeCSV(f.File)
		rule := escapeCSV(f.RuleName)
		msg := escapeCSV(f.Message)
		impact := escapeCSV(f.Impact)
		rec := escapeCSV(f.Recommendation)
		fmt.Printf("%s,%s,%s,%s,%s,%s\n", severity, file, rule, msg, impact, rec)
	}
}

func escapeCSV(s string) string {
	s = strings.ReplaceAll(s, "\"", "\"\"")
	if strings.Contains(s, ",") || strings.Contains(s, "\"") || strings.Contains(s, "\n") {
		return "\"" + s + "\""
	}
	return s
}

func getSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
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
