package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	content := `{
  "version": "1.0.0",
  "severity_filter": "high",
  "output_format": "json",
  "verbose": true
}`

	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", cfg.Version)
	}
	if cfg.SeverityFilter != "high" {
		t.Errorf("Expected severity_filter high, got %s", cfg.SeverityFilter)
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("Expected output_format json, got %s", cfg.OutputFormat)
	}
	if !cfg.Verbose {
		t.Error("Expected verbose true")
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestDefault(t *testing.T) {
	if Default.Version != "1.15.0" {
		t.Errorf("Expected default version 1.15.0, got %s", Default.Version)
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := &Config{
		SeverityFilter: "high",
		OutputFormat:   "json",
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected valid config, got error: %v", err)
	}
}

func TestConfigValidateInvalidSeverity(t *testing.T) {
	cfg := &Config{
		SeverityFilter: "invalid",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for invalid severity")
	}
}

func TestConfigValidateRuleIDs(t *testing.T) {
	cfg := &Config{
		ExcludeRules: []string{"CRIT-001", "HIGH-001"},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected valid rule IDs, got error: %v", err)
	}
}

func TestConfigValidateInvalidRuleID(t *testing.T) {
	cfg := &Config{
		ExcludeRules: []string{"INVALID"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for invalid rule ID")
	}
}

func TestLoadReader(t *testing.T) {
	content := `{"version": "1.0.0", "severity_filter": "medium"}`
	cfg, err := LoadReader(strings.NewReader(content))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if cfg.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", cfg.Version)
	}
}

func TestLoadReaderInvalid(t *testing.T) {
	_, err := LoadReader(strings.NewReader("invalid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConfigSave(t *testing.T) {
	cfg := &Config{
		Version:        "1.0.0",
		SeverityFilter: "high",
	}
	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = cfg.Save(tmpFile.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
