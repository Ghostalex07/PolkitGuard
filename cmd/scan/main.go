package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/polkitguard/polkitguard/internal/detector"
	"github.com/polkitguard/polkitguard/internal/models"
	"github.com/polkitguard/polkitguard/internal/parser"
	"github.com/polkitguard/polkitguard/internal/report"
	"github.com/polkitguard/polkitguard/internal/scanner"
)

var (
	flagPath     string
	flagJSON     bool
	flagSeverity string
	flagHelp     bool
)

func init() {
	flag.StringVar(&flagPath, "path", "", "Custom path to scan (default: system polkit directories)")
	flag.BoolVar(&flagJSON, "json", false, "Output in JSON format")
	flag.StringVar(&flagSeverity, "severity", "low", "Minimum severity level (low, medium, high, critical)")
	flag.BoolVar(&flagHelp, "help", false, "Show help message")
	flag.Usage = usage
}

func usage() {
	fmt.Println("PolkitGuard - Security Scanner for Polkit")
	fmt.Println("\nUsage: polkitguard [options]")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println("  polkitguard                    # Scan default locations")
	fmt.Println("  polkitguard --path /custom/rules")
	fmt.Println("  polkitguard --severity high    # Only show HIGH and CRITICAL")
	fmt.Println("  polkitguard --json             # JSON output")
}

func getSeverityLevel(level string) models.Severity {
	switch level {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

func main() {
	flag.Parse()

	if flagHelp || flag.NFlag() == 0 && flag.NArg() == 0 {
		usage()
		os.Exit(0)
	}

	fmt.Println("PolkitGuard v0.1.0 - Scanning for Polkit security issues...\n")

	var files []string
	var err error

	if flagPath != "" {
		s := scanner.NewScanner(nil)
		files, err = s.ScanDirectory(flagPath)
	} else {
		s := scanner.NewScanner(nil)
		files, err = s.Scan()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Println("No polkit rule files found.")
		os.Exit(0)
	}

	fmt.Printf("Found %d rule file(s)\n\n", len(files))

	p := parser.NewParser()
	d := detector.NewDetector()
	var allRules []models.PolkitRule

	for _, file := range files {
		rules, err := p.ParseFile(file)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	fmt.Printf("Parsed %d rule(s)\n\n", len(allRules))

	result := d.DetectAll(allRules)

	severity := getSeverityLevel(flagSeverity)
	r := report.NewReporter(severity)

	format := "text"
	if flagJSON {
		format = "json"
	}

	r.Output(result, format)
}