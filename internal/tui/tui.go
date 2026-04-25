package tui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/detector"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
	"github.com/Ghostalex07/PolkitGuard/internal/parser"
	"github.com/Ghostalex07/PolkitGuard/internal/report"
	"github.com/Ghostalex07/PolkitGuard/internal/scanner"
)

type TUI struct {
	detector *detector.Detector
	scanner  *scanner.Scanner
	parser   *parser.Parser
	results  []models.ScanResult
	colors   bool
}

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

func NewTUI(enableColors bool) *TUI {
	return &TUI{
		detector: detector.NewDetector(),
		scanner:  scanner.NewScanner(nil),
		parser:   parser.NewParser(),
		results:  []models.ScanResult{},
		colors:   enableColors,
	}
}

func (t *TUI) clearScreen() {
	cmd := exec.Command("clear")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func (t *TUI) printHeader() {
	if t.colors {
		fmt.Println(ColorBold + ColorCyan)
	}
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          PolkitGuard - Interactive TUI                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	if t.colors {
		fmt.Println(ColorReset)
	}
}

func (t *TUI) printMenu() {
	fmt.Println("\n[M]ain Menu:")
	fmt.Println("  [S]can        - Run security scan")
	fmt.Println("  [V]iew        - View last results")
	fmt.Println("  [R]ules       - Show detection rules")
	fmt.Println("  [H]istory    - Scan history")
	fmt.Println("  [F]ilter     - Filter by severity")
	fmt.Println("  [Q]uit       - Exit")
	fmt.Println("\n> ")
}

func (t *TUI) Run() {
	t.clearScreen()
	t.printHeader()
	t.printMenu()

	var input string
	for {
		fmt.Scan(&input)
		input = strings.ToLower(strings.TrimSpace(input))

		switch input {
		case "s":
			t.runScan()
		case "v":
			t.viewResults()
		case "r":
			t.showRules()
		case "h":
			t.showHistory()
		case "f":
			t.filterResults()
		case "q":
			fmt.Println("Goodbye!")
			os.Exit(0)
		default:
			t.printMenu()
		}
	}
}

func (t *TUI) runScan() {
	t.clearScreen()
	t.printHeader()

	fmt.Println("Running scan...")

	files, err := t.scanner.Scan()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Found %d files\n", len(files))

	var allRules []models.PolkitRule
	for _, file := range files {
		rules, err := t.parser.ParseFile(file)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	result := t.detector.DetectAll(allRules)
	t.results = append(t.results, result)

	t.printResults(result)
}

func (t *TUI) printResults(result models.ScanResult) {
	stats := report.NewReporter(models.SeverityLow).CalculateStats(result)

	fmt.Println()
	if t.colors {
		fmt.Printf("Total: %d | CRITICAL: %s%d%s | HIGH: %s%d%s | MEDIUM: %s%d%s | LOW: %s%d%s\n\n",
			stats.Total,
			ColorRed, stats.Critical, ColorReset,
			ColorYellow, stats.High, ColorReset,
			ColorBlue, stats.Medium, ColorReset,
			ColorCyan, stats.Low, ColorReset)
	} else {
		fmt.Printf("Total: %d | CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d\n\n",
			stats.Total, stats.Critical, stats.High, stats.Medium, stats.Low)
	}

	if result.HasCritical() {
		if t.colors {
			fmt.Println(ColorRed + "CRITICAL ISSUES FOUND!" + ColorReset)
		} else {
			fmt.Println("CRITICAL ISSUES FOUND!")
		}
	}
}

func (t *TUI) viewResults() {
	if len(t.results) == 0 {
		fmt.Println("No results. Run a scan first.")
		return
	}

	lastResult := t.results[len(t.results)-1]
	t.printResults(lastResult)
}

func (t *TUI) showRules() {
	fmt.Printf("\nDetection Rules: 74\n\n")
	fmt.Println("[CRIT] - Critical severity rules")
	fmt.Println("[HIGH] - High severity rules")
	fmt.Println("[MED] - Medium severity rules")
	fmt.Println("[LOW] - Low severity rules")
}

func (t *TUI) showHistory() {
	fmt.Println("\nScan History:")
	for i, r := range t.results {
		stats := report.NewReporter(models.SeverityLow).CalculateStats(r)
		fmt.Printf("%d. Total: %d (C:%d H:%d M:%d L:%d)\n",
			i+1, stats.Total, stats.Critical, stats.High, stats.Medium, stats.Low)
	}
}

func (t *TUI) filterResults() {
	fmt.Println("Filter by severity: [C]ritical, [H]igh, [M]edium, [L]ow, [A]ll")
	fmt.Print("> ")
	var input string
	fmt.Scan(&input)

	severity := models.SeverityLow
	switch strings.ToLower(input) {
	case "c":
		severity = models.SeverityCritical
	case "h":
		severity = models.SeverityHigh
	case "m":
		severity = models.SeverityMedium
	case "l":
		severity = models.SeverityLow
	}

	if len(t.results) > 0 {
		lastResult := t.results[len(t.results)-1]
		findings := lastResult.GetFindingsByMinSeverity(severity)
		fmt.Printf("Found %d issues\n", len(findings))
	}
}
