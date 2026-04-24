package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/config"
	"github.com/Ghostalex07/PolkitGuard/internal/detector"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
	"github.com/Ghostalex07/PolkitGuard/internal/parser"
	"github.com/Ghostalex07/PolkitGuard/internal/report"
	"github.com/Ghostalex07/PolkitGuard/internal/scanner"
)

const version = "1.0.0"

var (
	flagPath      string
	flagSeverity  string
	flagHelp     bool
	flagVerbose  bool
	flagQuiet    bool
	flagConfirm  bool
	flagConfig   string
	flagOutput   string
	flagSummary  bool
	format      string
)

func init() {
	flag.StringVar(&flagPath, "path", "", "Custom path to scan (default: system polkit directories)")
	flag.StringVar(&flagSeverity, "severity", "low", "Minimum severity level (low, medium, high, critical)")
	flag.StringVar(&flagConfig, "config", "", "Path to config file (JSON)")
	flag.StringVar(&flagOutput, "output", "", "Output file path")
	flag.BoolVar(&flagSummary, "summary", false, "Show summary only (counts)")
	flag.BoolVar(&flagHelp, "help", false, "Show help message")
	flag.BoolVar(&flagVerbose, "v", false, "Enable verbose output")
	flag.BoolVar(&flagQuiet, "q", false, "Quiet mode - suppress banner")
	flag.BoolVar(&flagConfirm, "y", false, "Skip confirmation prompts (auto-confirm)")
	flag.StringVar(&format, "format", "text", "Output format: text, json, html, sarif, csv")
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
	fmt.Println("  polkitguard --format json     # JSON output")
	fmt.Println("  polkitguard --format html    # HTML report")
	fmt.Println("  polkitguard --format sarif    # SARIF output")
	fmt.Println("  polkitguard -y               # Auto-confirm (non-interactive)")
	fmt.Println("  polkitguard -q               # Quiet mode")
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

func loadConfig() (*config.Config, error) {
	if flagConfig == "" {
		return config.Default, nil
	}
	return config.Load(flagConfig)
}

func main() {
	flag.Parse()

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if flagHelp || flag.NFlag() == 0 && flag.NArg() == 0 {
		usage()
		os.Exit(0)
	}

	if flagVerbose {
		scanner.SetLogger(func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
		})
	}

	if !flagQuiet {
		fmt.Printf("PolkitGuard v%s - Scanning for Polkit security issues...\n\n", version)
	}

	var files []string
	var scanErr error

	if flagPath != "" {
		s := scanner.NewScanner(nil)
		files, scanErr = s.ScanDirectory(flagPath)
	} else {
		s := scanner.NewScanner(nil)
		files, scanErr = s.Scan()
	}

	if scanErr != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", scanErr)
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
		shouldIgnore := false
		for _, pattern := range cfg.IgnorePaths {
			if strings.Contains(file, pattern) {
				shouldIgnore = true
				break
			}
		}
		if shouldIgnore {
			continue
		}
		rules, parseErr := p.ParseFile(file)
		if parseErr != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	fmt.Printf("Parsed %d rule(s)\n\n", len(allRules))

	result := d.DetectAll(allRules)

	severity := getSeverityLevel(flagSeverity)
	if severity == 0 {
		severity = getSeverityLevel(cfg.SeverityFilter)
	}
	outputFormat := format
	if outputFormat == "text" && cfg.OutputFormat != "" {
		outputFormat = cfg.OutputFormat
	}
	r := report.NewReporter(severity)

	if flagSummary {
		stats := r.CalculateStats(result)
		fmt.Printf("Files scanned: %d\n", stats.FilesScanned)
		fmt.Printf("Rules analyzed: %d\n", stats.RulesFound)
		fmt.Printf("Critical: %d\n", stats.Critical)
		fmt.Printf("High: %d\n", stats.High)
		fmt.Printf("Medium: %d\n", stats.Medium)
		fmt.Printf("Low: %d\n", stats.Low)
	} else {
		r.Output(result, outputFormat)
	}

	if flagOutput != "" {
		fmt.Printf("Report saved to: %s\n", flagOutput)
	}

	if result.HasCritical() {
		os.Exit(4)
	}
	if result.HasHigh() {
		os.Exit(3)
	}
	if result.HasMedium() {
		os.Exit(2)
	}
	if len(result.Findings) > 0 {
		os.Exit(1)
	}
}