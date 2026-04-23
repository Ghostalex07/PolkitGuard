package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) ParseFile(filepath string) ([]models.PolkitRule, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var rules []models.PolkitRule
	var currentRule models.PolkitRule
	lineNum := 0
	inBlock := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if inBlock && currentRule.Raw != "" {
				currentRule.RuleName = extractRuleName(currentRule.Raw)
				rules = append(rules, currentRule)
			}
			currentRule = models.PolkitRule{File: filepath, LineNumber: lineNum}
			inBlock = true
			continue
		}

		if !inBlock {
			continue
		}

		currentRule.Raw += line + "\n"

		if strings.HasPrefix(line, "identity=") {
			currentRule.Identity = extractValue(line, "identity=")
		} else if strings.HasPrefix(line, "action=") {
			currentRule.Action = extractValue(line, "action=")
		} else if strings.HasPrefix(line, "result_any=") {
			currentRule.ResultAny = extractValue(line, "result_any=")
		} else if strings.HasPrefix(line, "result_active=") {
			currentRule.ResultActive = extractValue(line, "result_active=")
		} else if strings.HasPrefix(line, "result_inactive=") {
			currentRule.ResultInactive = extractValue(line, "result_inactive=")
		}
	}

	if inBlock && currentRule.Raw != "" {
		currentRule.RuleName = extractRuleName(currentRule.Raw)
		rules = append(rules, currentRule)
	}

	return rules, nil
}

func extractValue(line, prefix string) string {
	value := strings.TrimPrefix(line, prefix)
	value = strings.Trim(value, ";")
	return strings.Trim(value, "\"")
}

func extractRuleName(raw string) string {
	if raw == "" {
		return "unknown"
	}
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "return") || strings.HasPrefix(line, "==") {
			return strings.TrimSpace(line)
		}
	}
	if len(lines) > 0 {
		first := strings.TrimSpace(lines[0])
		if first != "" {
			return first
		}
	}
	return "unknown"
}

func extractActionFromJS(raw string) string {
	if idx := strings.Index(raw, "action"); idx != -1 {
		rest := raw[idx:]
		if strings.Contains(rest, "org.") {
			start := strings.Index(rest, "org.")
			end := start + strings.Index(rest[start:], "\"")
			if end > start {
				action := rest[start:end]
				if idx := strings.Index(action, "\""); idx > 0 {
					return action[:idx]
				}
				return action
			}
		}
	}
	return ""
}

func extractIdentityFromJS(raw string) string {
	if strings.Contains(raw, "euid") || strings.Contains(raw, "uid") {
		if strings.Contains(raw, "== 0") || strings.Contains(raw, "==0") {
			return "unix-user:root"
		}
	}
	if strings.Contains(raw, "gid") {
		return "unix-group:root"
	}
	return ""
}

func (p *Parser) ParseDirectory(dirpath string) ([]models.PolkitRule, error) {
	var allRules []models.PolkitRule

	entries, err := os.ReadDir(dirpath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".rules") {
			rules, err := p.ParseFile(filepath.Join(dirpath, entry.Name()))
			if err != nil {
				continue
			}
			allRules = append(allRules, rules...)
		}
	}

	return allRules, nil
}