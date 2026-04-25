package audit

import (
	"fmt"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type ComplianceReport struct {
	Generated       time.Time        `json:"generated"`
	Version         string           `json:"version"`
	ScanID          string           `json:"scan_id"`
	Policy          string           `json:"policy"`
	Findings        FindingSummary   `json:"findings"`
	Compliance      ComplianceStatus `json:"compliance"`
	Recommendations []string         `json:"recommendations"`
}

type FindingSummary struct {
	Total         int            `json:"total"`
	Pass          int            `json:"pass"`
	Fail          int            `json:"fail"`
	NotApplicable int            `json:"not_applicable"`
	BySeverity    map[string]int `json:"by_severity"`
}

type ComplianceStatus struct {
	Level       string `json:"level"`
	Score       int    `json:"score"`
	Description string `json:"description"`
}

func GenerateComplianceReport(result models.ScanResult, policy string) *ComplianceReport {
	stats := calculateCompliance(result)

	return &ComplianceReport{
		Generated:       time.Now(),
		Version:         "1.16.0",
		ScanID:          fmt.Sprintf("scan-%d", time.Now().Unix()),
		Policy:          policy,
		Findings:        stats,
		Compliance:      determineCompliance(stats),
		Recommendations: generateRecommendations(result),
	}
}

func calculateCompliance(result models.ScanResult) FindingSummary {
	summary := FindingSummary{
		BySeverity: make(map[string]int),
	}

	for _, f := range result.Findings {
		summary.Total++
		summary.BySeverity[f.Severity.String()]++

		if f.Severity >= models.SeverityMedium {
			summary.Fail++
		} else {
			summary.Pass++
		}
	}

	return summary
}

func determineCompliance(stats FindingSummary) ComplianceStatus {
	score := 100
	if stats.Total > 0 {
		score = 100 - (stats.BySeverity["CRITICAL"] * 10) - (stats.BySeverity["HIGH"] * 5)
		if score < 0 {
			score = 0
		}
	}

	level := "COMPLIANT"
	if score < 70 {
		level = "NON_COMPLIANT"
	} else if score < 90 {
		level = "PARTIALLY_COMPLIANT"
	}

	return ComplianceStatus{
		Level:       level,
		Score:       score,
		Description: fmt.Sprintf("Compliance score: %d/100", score),
	}
}

func generateRecommendations(result models.ScanResult) []string {
	var recs []string

	for _, f := range result.Findings {
		if f.Severity >= models.SeverityHigh && f.Recommendation != "" {
			recs = append(recs, f.Recommendation)
		}
	}

	if len(recs) > 10 {
		recs = recs[:10]
	}

	return recs
}

func (r *ComplianceReport) String() string {
	return fmt.Sprintf(`PolkitGuard Compliance Report
================================
Policy: %s
Generated: %s
Version: %s

Compliance Level: %s (Score: %d/100)

Findings:
  Total: %d
  Critical: %d
  High: %d
  Medium: %d
  Low: %d

Recommendations:
%s`,
		r.Policy,
		r.Generated.Format("2006-01-02 15:04:05"),
		r.Version,
		r.Compliance.Level,
		r.Compliance.Score,
		r.Findings.Total,
		r.Findings.BySeverity["CRITICAL"],
		r.Findings.BySeverity["HIGH"],
		r.Findings.BySeverity["MEDIUM"],
		r.Findings.BySeverity["LOW"],
		formatRecs(r.Recommendations),
	)
}

func formatRecs(recs []string) string {
	result := ""
	for i, r := range recs {
		result += fmt.Sprintf("  %d. %s\n", i+1, r)
	}
	return result
}
