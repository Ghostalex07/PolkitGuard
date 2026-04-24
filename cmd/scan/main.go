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
	flagVersion  bool
	flagRule     string
	flagShell    string
	flagNoColor  bool
	format      string
)

func init() {
	flag.StringVar(&flagPath, "path", "", "Custom path to scan (default: system polkit directories)")
	flag.StringVar(&flagSeverity, "severity", "low", "Minimum severity level (low, medium, high, critical)")
	flag.StringVar(&flagConfig, "config", "", "Path to config file (JSON), use '-' for stdin")
	flag.StringVar(&flagOutput, "output", "", "Output file path")
	flag.StringVar(&flagRule, "rule", "", "Filter by rule ID (e.g., CRIT-001)")
	flag.BoolVar(&flagSummary, "summary", false, "Show summary only (counts)")
	flag.BoolVar(&flagVersion, "version", false, "Show version")
	flag.BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&flagHelp, "help", false, "Show help message")
	flag.BoolVar(&flagVerbose, "v", false, "Enable verbose output")
	flag.BoolVar(&flagQuiet, "q", false, "Quiet mode - suppress banner, show only findings")
	flag.BoolVar(&flagConfirm, "y", false, "Skip confirmation prompts (auto-confirm)")
	flag.StringVar(&format, "format", "text", "Output format: text, json, html, sarif, csv")
	flag.StringVar(&flagShell, "shell", "", "Generate shell completions (bash, zsh, fish)")
	flag.Usage = usage
}

func usage() {
	fmt.Println("PolkitGuard v" + version + " - Security Scanner for Polkit")
	fmt.Println("\nUsage: polkitguard [options]")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println("  polkitguard                    # Scan default locations")
	fmt.Println("  polkitguard --path /custom/rules")
	fmt.Println("  polkitguard --severity high    # Only show HIGH and CRITICAL")
	fmt.Println("  polkitguard --format json     # JSON output")
	fmt.Println("  polkitguard --format html    # HTML report")
	fmt.Println("  polkitguard -q               # Quiet mode")
	fmt.Println("  polkitguard -v               # Verbose output")
	fmt.Println("  polkitguard --no-color      # No colors")
	fmt.Println("  polkitguard --config -        # Read config from stdin")
	fmt.Println("  polkitguard --shell bash   # Generate bash completions")
	fmt.Println("\nConfig file auto-discovery:")
	fmt.Println("  ./polkitguard.json, config.json,")
	fmt.Println("  ~/.config/polkitguard.json, /etc/polkitguard.json")
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
	if flagConfig == "-" {
		return config.LoadReader(os.Stdin)
	}
	
	if flagConfig != "" {
		return config.Load(flagConfig)
	}
	
	// Try config auto-discovery
	paths := []string{
		".polkitguard.json",
		"config.json",
		".config/polkitguard.json",
		os.ExpandEnv("$HOME/.config/polkitguard.json"),
		"/etc/polkitguard.json",
	}
	
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			if cfg, err := config.Load(p); err == nil {
				if flagVerbose {
					fmt.Fprintf(os.Stderr, "[VERBOSE] Using config: %s\n", p)
				}
				return cfg, nil
			}
		}
	}
	
	return config.Default, nil
}

func generateCompletion(shell string) {
	switch shell {
	case "bash":
		fmt.Println("# Bash completion for polkitguard")
		fmt.Println("_polkitguard() {")
		fmt.Println("    local cur prev")
		fmt.Println("    COMPREPLY=()")
		fmt.Println("    cur=\"${COMP_WORDS[COMP_CWORD]}\"")
		fmt.Println("    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"")
		fmt.Println("    opts=\"--path --severity --format --config --output --summary --version --rule --help -v -q -y\"")
		fmt.Println("    COMPREPLY=( $(compgen -W \"${opts}\" -- ${cur}) )")
		fmt.Println("    return 0")
		fmt.Println("}")
		fmt.Println("complete -F _polkitguard polkitguard")
	case "zsh":
		fmt.Println("# Zsh completion for polkitguard")
		fmt.Println("_polkitguard() {")
		fmt.Println("    local -a opts")
		fmt.Println("    opts=('(--path)'{path}'[Custom path]'")
		fmt.Println("           '(--severity)'{severity}'[Severity level]'")
		fmt.Println("           '(--format)'{format}'[Output format]'")
		fmt.Println("           '(--config)'{config}'[Config file]'")
		fmt.Println("           '(--output)'{output}'[Output file]'")
		fmt.Println("           '(--summary)'{summary}'[Summary only]'")
		fmt.Println("           '(--version)'{version}'[Show version]'")
		fmt.Println("           '(--rule)'{rule}'[Filter by rule ID]'")
		fmt.Println("           '(-v)'{v}'[Verbose]'")
		fmt.Println("           '(-q)'{q}'[Quiet]'")
		fmt.Println("           '(-y)'{y}'[Auto-confirm]')")
		fmt.Println("    _describe 'option' opts")
		fmt.Println("}")
		fmt.Println("_compdef _polkitguard polkitguard")
	case "fish":
		fmt.Println("# Fish completion for polkitguard")
		fmt.Println("complete -c polkitguard -l path -d 'Custom path to scan'")
		fmt.Println("complete -c polkitguard -l severity -d 'Severity level' -a 'low medium high critical'")
		fmt.Println("complete -c polkitguard -l format -d 'Output format' -a 'text json html sarif csv'")
		fmt.Println("complete -c polkitguard -l config -d 'Config file'")
		fmt.Println("complete -c polkitguard -l output -d 'Output file'")
		fmt.Println("complete -c polkitguard -l summary -d 'Show summary only'")
		fmt.Println("complete -c polkitguard -l version -d 'Show version'")
		fmt.Println("complete -c polkitguard -l rule -d 'Filter by rule ID'")
		fmt.Println("complete -c polkitguard -s v -l verbose -d 'Verbose output'")
		fmt.Println("complete -c polkitguard -s q -l quiet -d 'Quiet mode'")
		fmt.Println("complete -c polkitguard -s y -d 'Auto-confirm'")
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell: %s (supported: bash, zsh, fish)\n", shell)
		os.Exit(1)
	}
}

func main() {
	flag.Parse()

	if flagVersion {
		fmt.Printf("PolkitGuard version %s\n", version)
		os.Exit(0)
	}

	if flagShell != "" {
		generateCompletion(flagShell)
		os.Exit(0)
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error validating config: %v\n", err)
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

	if flagRule != "" {
		d.SuppressRule(flagRule)
		var filtered []models.Finding
		for _, f := range result.Findings {
			if f.RuleName != flagRule {
				filtered = append(filtered, f)
			}
		}
		result.Findings = filtered
	}

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

	// Exit codes: 0=success, 1=low, 2=medium, 3=high, 4=critical, 5=error
	if result.HasCritical() {
		fmt.Fprintf(os.Stderr, "\n[CRITICAL] %d critical issues found\n", len(result.Findings))
		os.Exit(4)
	}
	if result.HasHigh() {
		fmt.Fprintf(os.Stderr, "\n[HIGH] %d high severity issues found\n", len(result.Findings))
		os.Exit(3)
	}
	if result.HasMedium() {
		fmt.Fprintf(os.Stderr, "\n[MEDIUM] %d medium severity issues found\n", len(result.Findings))
		os.Exit(2)
	}
	if len(result.Findings) > 0 {
		fmt.Fprintf(os.Stderr, "\n[LOW] %d low severity issues found\n", len(result.Findings))
		os.Exit(1)
	}
	fmt.Println("\n✓ No security issues found")
	os.Exit(0)
}