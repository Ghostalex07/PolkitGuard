package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Version         string            `json:"version"`
	SeverityFilter   string           `json:"severity_filter,omitempty"`
	OutputFormat   string           `json:"output_format,omitempty"`
	CustomPaths    []string         `json:"custom_paths,omitempty"`
	ExcludeRules  []string         `json:"exclude_rules,omitempty"`
	EnableRules   []string         `json:"enable_rules,omitempty"`
	Verbose      bool             `json:"verbose,omitempty"`
	Quiet        bool             `json:"quiet,omitempty"`
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

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

var Default = &Config{
	Version:       "0.6.0",
	SeverityFilter: "low",
	OutputFormat:  "text",
	Verbose:      false,
	Quiet:       false,
}