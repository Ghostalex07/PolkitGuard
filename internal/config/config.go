package config

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
)

type Config struct {
	Version        string       `json:"version"`
	SeverityFilter string       `json:"severity_filter,omitempty"`
	OutputFormat   string       `json:"output_format,omitempty"`
	CustomPaths    []string     `json:"custom_paths,omitempty"`
	ExcludeRules   []string     `json:"exclude_rules,omitempty"`
	EnableRules    []string     `json:"enable_rules,omitempty"`
	IgnorePaths    []string     `json:"ignore_paths,omitempty"`
	CustomRules    []CustomRule `json:"custom_rules,omitempty"`
	Verbose        bool         `json:"verbose,omitempty"`
	Quiet          bool         `json:"quiet,omitempty"`
}

type CustomRule struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Pattern        string `json:"pattern"`
	Message        string `json:"message"`
	Impact         string `json:"impact,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func (c *Config) Validate() error {
	validSeverity := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validFormat := map[string]bool{"text": true, "json": true, "html": true, "sarif": true, "csv": true}

	if c.SeverityFilter != "" && !validSeverity[c.SeverityFilter] {
		return &ConfigError{Field: "severity_filter", Value: c.SeverityFilter}
	}
	if c.OutputFormat != "" && !validFormat[c.OutputFormat] {
		return &ConfigError{Field: "output_format", Value: c.OutputFormat}
	}

	ruleID := regexp.MustCompile(`^(CRIT|HIGH|MED|LOW)-[0-9]{3}$`)
	for _, r := range c.ExcludeRules {
		if !ruleID.MatchString(r) {
			return &ConfigError{Field: "exclude_rules", Value: r}
		}
	}
	for _, r := range c.EnableRules {
		if !ruleID.MatchString(r) {
			return &ConfigError{Field: "enable_rules", Value: r}
		}
	}

	return nil
}

type ConfigError struct {
	Field string
	Value string
}

func (e *ConfigError) Error() string {
	return "invalid config: field '" + e.Field + "' has invalid value '" + e.Value + "'"
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func LoadReader(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

var Default = &Config{
	Version:        "1.6.0",
	SeverityFilter: "low",
	OutputFormat:   "text",
	Verbose:        false,
	Quiet:          false,
}
