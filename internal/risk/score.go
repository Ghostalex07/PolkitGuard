package risk

import (
	"math"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type RiskScore struct {
	Overall     float64 `json:"overall"`
	Criticality float64 `json:"criticality"`
	Likelihood  float64 `json:"likelihood"`
	Impact       float64 `json:"impact"`
	Trend        string   `json:"trend"`
	Recommendations []string `json:"recommendations"`
}

type RiskConfig struct {
	TimeWindow    time.Duration
	Weights       RiskWeights
	Thresholds    RiskThresholds
}

type RiskWeights struct {
	Critical float64
	High     float64
	Medium   float64
	Low      float64
}

type RiskThresholds struct {
	Critical float64
	High     float64
	Medium   float64
	Low      float64
}

func NewRiskConfig() *RiskConfig {
	return &RiskConfig{
		TimeWindow: 24 * time.Hour * 30,
		Weights: RiskWeights{
			Critical: 10.0,
			High:     7.0,
			Medium:   4.0,
			Low:      1.0,
		},
		Thresholds: RiskThresholds{
			Critical: 8.0,
			High:     6.0,
			Medium:   4.0,
			Low:      2.0,
		},
	}
}

func CalculateRiskScore(findings []models.Finding, history []models.Finding) RiskScore {
	rs := RiskScore{}

	weights := NewRiskConfig().Weights

	var totalWeight float64
	var weightedSum float64

	severityCounts := map[models.Severity]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     0,
		models.SeverityMedium:   0,
		models.SeverityLow:      0,
	}

	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	for severity, count := range severityCounts {
		weight := getWeight(severity, weights)
		weightedSum += float64(count) * weight
		totalWeight += weight * float64(count)
	}

	if totalWeight > 0 {
		rs.Criticality = weightedSum / totalWeight * 10
	}

	rs.Likelihood = calculateLikelihood(findings)
	rs.Impact = calculateImpact(findings)
	rs.Overall = (rs.Criticality*0.4 + rs.Likelihood*0.3 + rs.Impact*0.3)

	if len(history) > 0 {
		historyScore := calculateHistoryScore(history, weights)
		if historyScore > 0 {
			if rs.Overall > historyScore*1.2 {
				rs.Trend = "increasing"
			} else if rs.Overall < historyScore*0.8 {
				rs.Trend = "decreasing"
			} else {
				rs.Trend = "stable"
			}
		}
	}

	rs.Recommendations = generateRecommendations(findings, rs.Overall)

	return rs
}

func getWeight(severity models.Severity, weights RiskWeights) float64 {
	switch severity {
	case models.SeverityCritical:
		return weights.Critical
	case models.SeverityHigh:
		return weights.High
	case models.SeverityMedium:
		return weights.Medium
	case models.SeverityLow:
		return weights.Low
	default:
		return 0
	}
}

func calculateLikelihood(findings []models.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}

	actionCounts := map[string]int{}
	for _, f := range findings {
		if f.Rule != nil {
			actionCounts[f.Rule.Action]++
		}
	}

	maxCount := 0
	for _, count := range actionCounts {
		if count > maxCount {
			maxCount = count
		}
	}

	return math.Min(float64(maxCount)/float64(len(findings))*10, 10)
}

func calculateImpact(findings []models.Finding) float64 {
	impactActions := []string{
		"system", "user", "admin", "root",
		"shutdown", "reboot", "network", "auth",
	}

	var score float64
	for _, f := range findings {
		if f.Rule != nil {
			for _, action := range impactActions {
				if contains(f.Rule.Action, action) {
					score += 2
					break
				}
			}
		}
	}

	return math.Min(score, 10)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func calculateHistoryScore(history []models.Finding, weights RiskWeights) float64 {
	if len(history) == 0 {
		return 0
	}

	var total float64
	for _, f := range history {
		total += getWeight(f.Severity, weights)
	}

	return total / float64(len(history))
}

func generateRecommendations(findings []models.Finding, score float64) []string {
	var recs []string

	if score > 8 {
		recs = append(recs, "URGENT: Critical risk detected. Immediate action required.")
		recs = append(recs, "Consider disabling or restricting all overly permissive rules.")
	} else if score > 6 {
		recs = append(recs, "High risk detected. Review and remediate findings within 24 hours.")
		recs = append(recs, "Implement principle of least privilege.")
	} else if score > 4 {
		recs = append(recs, "Medium risk. Schedule remediation within 1 week.")
		recs = append(recs, "Review admin group memberships.")
	} else {
		recs = append(recs, "Low risk. Continue monitoring and regular audits.")
	}

	criticalCount := 0
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			criticalCount++
		}
	}

	if criticalCount > 5 {
		recs = append(recs, "Consider implementing automated policy validation in CI/CD.")
	}

	return recs
}

func (r *RiskScore) Level() string {
	switch {
	case r.Overall >= 8:
		return "CRITICAL"
	case r.Overall >= 6:
		return "HIGH"
	case r.Overall >= 4:
		return "MEDIUM"
	case r.Overall >= 2:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

func (r *RiskScore) Color() string {
	switch r.Level() {
	case "CRITICAL":
		return "red"
	case "HIGH":
		return "orange"
	case "MEDIUM":
		return "yellow"
	case "LOW":
		return "blue"
	default:
		return "green"
	}
}