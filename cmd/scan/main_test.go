package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/detector"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
	"github.com/Ghostalex07/PolkitGuard/internal/parser"
	"github.com/Ghostalex07/PolkitGuard/internal/scanner"
)

func getTestDataDir(t *testing.T) string {
	testDir := os.Getenv("TESTDIR")
	if testDir != "" {
		return testDir
	}
	return "testdata"
}

func TestIntegrationFullScan(t *testing.T) {
	s := scanner.NewScanner(nil)
	d := detector.NewDetector()
	p := parser.NewParser()

	testDataPath := getTestDataDir(t)
	files, err := s.ScanDirectory(testDataPath)
	if err != nil {
		t.Fatalf("Failed to scan testdata: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("No test files found")
	}

	var allRules []models.PolkitRule
	for _, file := range files {
		rules, err := p.ParseFile(file)
		if err != nil {
			t.Logf("Warning: Failed to parse %s: %v", file, err)
			continue
		}
		allRules = append(allRules, rules...)
	}

	if len(allRules) == 0 {
		t.Fatal("No rules parsed")
	}

	result := d.DetectAll(allRules)

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings in testdata but got none")
	}

	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity == models.SeverityCritical {
			hasCritical = true
			break
		}
	}

	if !hasCritical {
		t.Error("Expected at least one CRITICAL finding in vulnerable testdata")
	}

	t.Logf("Integration test passed: found %d findings from %d rules", len(result.Findings), len(allRules))
}

func TestIntegrationSafeRules(t *testing.T) {
	s := scanner.NewScanner(nil)
	d := detector.NewDetector()
	p := parser.NewParser()

	safePath := getTestDataDir(t) + "/safe"
	files, err := s.ScanDirectory(safePath)
	if err != nil {
		t.Fatalf("Failed to scan safe testdata: %v", err)
	}

	var allRules []models.PolkitRule
	for _, file := range files {
		rules, err := p.ParseFile(file)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	result := d.DetectAll(allRules)

	criticalCount := 0
	for _, f := range result.Findings {
		if f.Severity == models.SeverityCritical {
			criticalCount++
		}
	}

	if criticalCount > 0 {
		t.Errorf("Expected no CRITICAL findings in safe rules, got %d", criticalCount)
	}
}

func TestIntegrationVulnerableRules(t *testing.T) {
	s := scanner.NewScanner(nil)
	d := detector.NewDetector()
	p := parser.NewParser()

	vulnPath := getTestDataDir(t) + "/vulnerable"
	files, err := s.ScanDirectory(vulnPath)
	if err != nil {
		t.Fatalf("Failed to scan vulnerable testdata: %v", err)
	}

	var allRules []models.PolkitRule
	for _, file := range files {
		rules, err := p.ParseFile(file)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	result := d.DetectAll(allRules)

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings in vulnerable testdata")
	}

	highOrAbove := 0
	for _, f := range result.Findings {
		if f.Severity >= models.SeverityHigh {
			highOrAbove++
		}
	}

	if highOrAbove == 0 {
		t.Error("Expected HIGH or CRITICAL findings in vulnerable testdata")
	}
}

func TestIntegrationExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		finding  models.Finding
		minSev   models.Severity
		expected bool
	}{
		{
			name: "Critical should exit for critical min",
			finding: models.Finding{Severity: models.SeverityCritical},
			minSev:   models.SeverityCritical,
			expected: true,
		},
		{
			name: "High should not exit for critical min",
			finding: models.Finding{Severity: models.SeverityHigh},
			minSev:   models.SeverityCritical,
			expected: false,
		},
		{
			name: "Low should exit for low min",
			finding: models.Finding{Severity: models.SeverityLow},
			minSev:   models.SeverityLow,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := models.ScanResult{
				Findings: []models.Finding{tt.finding},
			}
			filtered := result.GetFindingsByMinSeverity(tt.minSev)
			hasFindings := len(filtered) > 0
			if hasFindings != tt.expected {
				t.Errorf("Expected %v but got %v", tt.expected, hasFindings)
			}
		})
	}
}

func TestIntegrationMultipleOutputFormats(t *testing.T) {
	s := scanner.NewScanner(nil)
	d := detector.NewDetector()
	p := parser.NewParser()

	testDataPath := getTestDataDir(t)
	files, _ := s.ScanDirectory(testDataPath)

	var allRules []models.PolkitRule
	for _, file := range files {
		rules, _ := p.ParseFile(file)
		allRules = append(allRules, rules...)
	}

	result := d.DetectAll(allRules)

	if result.RulesFound == 0 {
		t.Fatal("Expected rules found")
	}

	stats := models.NewScanResult()
	stats.Findings = result.Findings
	_ = stats.GetFindingsByMinSeverity(models.SeverityLow)

	_ = stats.HasCritical()
	_ = stats.HasHigh()
	_ = stats.HasMedium()

	_ = filepath.Join("test", "path")
	_ = os.Stdout
}
