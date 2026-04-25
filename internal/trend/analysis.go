package trend

import (
	"fmt"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type TrendAnalysis struct {
	Period       string           `json:"period"`
	StartDate    time.Time        `json:"start_date"`
	EndDate      time.Time        `json:"end_date"`
	Scans        int              `json:"total_scans"`
	DataPoints   []TrendPoint     `json:"data_points"`
	Trajectory   string           `json:"trajectory"`
	ChangeRate   float64          `json:"change_rate"`
	Predictions  []Prediction     `json:"predictions"`
	Anomalies    []Anomaly        `json:"anomalies"`
}

type TrendPoint struct {
	Timestamp    time.Time        `json:"timestamp"`
	Findings     int               `json:"findings"`
	Critical     int               `json:"critical"`
	High         int               `json:"high"`
	Medium       int               `json:"medium"`
	Low          int               `json:"low"`
	Score        float64           `json:"risk_score"`
}

type Prediction struct {
	Date         time.Time        `json:"date"`
	Findings     int               `json:"predicted_findings"`
	Confidence   float64           `json:"confidence"`
	Direction    string            `json:"direction"`
}

type Anomaly struct {
	Timestamp    time.Time        `json:"timestamp"`
	Type         string           `json:"type"`
	Description  string           `json:"description"`
	Severity     string           `json:"severity"`
}

func AnalyzeTrends(history []models.ScanResult) TrendAnalysis {
	analysis := TrendAnalysis{
		DataPoints:  make([]TrendPoint, len(history)),
		Predictions: []Prediction{},
		Anomalies:   []Anomaly{},
	}

	if len(history) == 0 {
		return analysis
	}

	analysis.StartDate = time.Now().AddDate(0, 0, -30)
	analysis.EndDate = time.Now()
	analysis.Scans = len(history)

	for i, result := range history {
		point := TrendPoint{
			Timestamp: time.Now().AddDate(0, 0, len(history)-i-1),
			Findings:  len(result.Findings),
			Critical:  len(result.GetFindingsByMinSeverity(models.SeverityCritical)),
			High:      len(result.GetFindingsByMinSeverity(models.SeverityHigh)),
			Medium:    len(result.GetFindingsByMinSeverity(models.SeverityMedium)),
			Low:       len(result.GetFindingsByMinSeverity(models.SeverityLow)),
			Score:     calculateTrendScore(result),
		}
		analysis.DataPoints[i] = point
	}

	analysis.Trajectory = calculateTrajectory(analysis.DataPoints)
	analysis.ChangeRate = calculateChangeRate(analysis.DataPoints)
	analysis.Predictions = generatePredictions(analysis.DataPoints)
	analysis.Anomalies = detectAnomalies(analysis.DataPoints)

	return analysis
}

func calculateTrendScore(result models.ScanResult) float64 {
	score := 0.0
	score += float64(len(result.GetFindingsByMinSeverity(models.SeverityCritical))) * 10
	score += float64(len(result.GetFindingsByMinSeverity(models.SeverityHigh))) * 7
	score += float64(len(result.GetFindingsByMinSeverity(models.SeverityMedium))) * 4
	score += float64(len(result.GetFindingsByMinSeverity(models.SeverityLow))) * 1
	return score
}

func calculateTrajectory(points []TrendPoint) string {
	if len(points) < 2 {
		return "insufficient_data"
	}

	firstHalf := 0
	secondHalf := 0

	mid := len(points) / 2
	for i := 0; i < mid; i++ {
		firstHalf += points[i].Findings
	}
	for i := mid; i < len(points); i++ {
		secondHalf += points[i].Findings
	}

	if secondHalf > firstHalf {
		return "increasing"
	} else if secondHalf < firstHalf {
		return "decreasing"
	}
	return "stable"
}

func calculateChangeRate(points []TrendPoint) float64 {
	if len(points) < 2 {
		return 0
	}

	var totalChange float64
	for i := 1; i < len(points); i++ {
		change := float64(points[i].Findings - points[i-1].Findings)
		totalChange += change
	}

	return totalChange / float64(len(points)-1)
}

func generatePredictions(points []TrendPoint) []Prediction {
	var predictions []Prediction

	if len(points) < 3 {
		return predictions
	}

	lastThree := points[len(points)-3:]
	avgChange := float64(0)
	for i := 1; i < len(lastThree); i++ {
		avgChange += float64(lastThree[i].Findings - lastThree[i-1].Findings)
	}
	avgChange /= float64(len(lastThree) - 1)

	confidence := 0.5
	if len(points) >= 10 {
		confidence = 0.8
	} else if len(points) >= 5 {
		confidence = 0.65
	}

	for i := 1; i <= 3; i++ {
		lastPoint := points[len(points)-1]
		predicted := int(float64(lastPoint.Findings) + avgChange*float64(i))

		if predicted < 0 {
			predicted = 0
		}

		direction := "stable"
		if avgChange > 0.5 {
			direction = "increasing"
		} else if avgChange < -0.5 {
			direction = "decreasing"
		}

		predictions = append(predictions, Prediction{
			Date:       time.Now().AddDate(0, 0, i*7),
			Findings:   predicted,
			Confidence: confidence,
			Direction:  direction,
		})
	}

	return predictions
}

func detectAnomalies(points []TrendPoint) []Anomaly {
	var anomalies []Anomaly

	if len(points) < 3 {
		return anomalies
	}

	avg := 0
	for _, p := range points {
		avg += p.Findings
	}
	avg /= len(points)

	threshold := float64(avg) * 2

	for i, p := range points {
		if float64(p.Findings) > threshold {
			anomalies = append(anomalies, Anomaly{
				Timestamp:   p.Timestamp,
				Type:        "spike",
				Description: "Unusual number of findings detected",
				Severity:    "HIGH",
			})
		}

		if i > 0 && i < len(points)-1 {
			if p.Findings == 0 && points[i-1].Findings > 0 && points[i+1].Findings > 0 {
				anomalies = append(anomalies, Anomaly{
					Timestamp:   p.Timestamp,
					Type:        "gap",
					Description: "Missing scan data between regular scans",
					Severity:    "LOW",
				})
			}
		}
	}

	return anomalies
}

func (t *TrendAnalysis) Summary() string {
	return fmt.Sprintf(`
Trend Analysis
==============
Period: %s
Total Scans: %d
Trajectory: %s
Change Rate: %.2f
`, t.Period, t.Scans, t.Trajectory, t.ChangeRate)
}

func formatTrendFloat(f float64) string {
	return fmt.Sprintf("%.2f", f)
}