package polkitguard

import (
	"context"
	"encoding/json"
	"os/exec"
	"time"
)

type Client struct {
	binaryPath string
	timeout    time.Duration
}

func NewClient(binaryPath string) *Client {
	if binaryPath == "" {
		binaryPath = "polkitguard"
	}
	return &Client{
		binaryPath: binaryPath,
		timeout:    60 * time.Second,
	}
}

func (c *Client) Scan(ctx context.Context, path string, severity string) (*ScanResult, error) {
	args := []string{"--format", "json", "--severity", severity}
	if path != "" {
		args = append(args, "--path", path)
	}

	cmd := exec.CommandContext(ctx, c.binaryPath, args...)

	stdout, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var result ScanResult
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) ScanAsync(ctx context.Context, path string, severity string) (<-chan *ScanResult, <-chan error) {
	resultChan := make(chan *ScanResult, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		result, err := c.Scan(ctx, path, severity)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- result
	}()

	return resultChan, errorChan
}

func (c *Client) ScanMultiple(ctx context.Context, paths []string, severity string) (map[string]*ScanResult, error) {
	results := make(map[string]*ScanResult)
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	for _, path := range paths {
		result, err := c.Scan(ctx, path, severity)
		if err != nil {
			results[path] = nil
			continue
		}
		results[path] = result
	}

	return results, nil
}

func (c *Client) CalculateRisk(findings []Finding) RiskScore {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
	}

	for _, f := range findings {
		counts[f.Severity]++
	}

	total := len(findings)
	if total == 0 {
		total = 1
	}

	score := float64(counts[SeverityCritical]*10+counts[SeverityHigh]*7+counts[SeverityMedium]*4+counts[SeverityLow]*1) / float64(total)

	level := "MINIMAL"
	if score >= 8 {
		level = "CRITICAL"
	} else if score >= 6 {
		level = "HIGH"
	} else if score >= 4 {
		level = "MEDIUM"
	} else if score >= 2 {
		level = "LOW"
	}

	return RiskScore{
		Overall:     score,
		Level:       level,
		Criticality: float64(counts[SeverityCritical]) / float64(total) * 10,
		Likelihood: float64(counts[SeverityHigh]) / float64(total) * 10,
		Impact:      float64(counts[SeverityCritical]+counts[SeverityHigh]) / float64(total) * 10,
	}
}

type ScanResult struct {
	Findings []Finding `json:"findings"`
	Scanner string    `json:"scanner"`
	Stats   Stats     `json:"stats"`
	Version string    `json:"version"`
}

type Finding struct {
	Severity Severity `json:"Severity"`
	File     string   `json:"File"`
	RuleName string   `json:"RuleName"`
	RuleID   string   `json:"RuleID"`
	Title    string   `json:"Title"`
	Rule     *Rule    `json:"Rule,omitempty"`
}

type Rule struct {
	Action     string `json:"Action"`
	Identity   string `json:"Identity"`
	ResultAny  string `json:"ResultAny"`
}

type Stats struct {
	FilesScanned int `json:"files_scanned"`
	RulesFound   int `json:"rules_found"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Total        int `json:"total"`
}

type Severity int

const (
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

type RiskScore struct {
	Overall           float64   `json:"overall"`
	Level             string    `json:"level"`
	Criticality       float64   `json:"criticality"`
	Likelihood        float64   `json:"likelihood"`
	Impact            float64   `json:"impact"`
	Trend             string    `json:"trend"`
	Recommendations   []string  `json:"recommendations"`
}

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}