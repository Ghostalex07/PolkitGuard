package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Ghostalex07/PolkitGuard/internal/config"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type Validator struct {
	strictMode bool
}

func NewValidator() *Validator {
	return &Validator{strictMode: false}
}

func (v *Validator) ValidateConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}

	return v.ValidateConfig(data)
}

func (v *Validator) ValidateConfig(data []byte) error {
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if err := v.validateSeverity(&cfg); err != nil {
		return err
	}

	if err := v.validatePaths(&cfg); err != nil {
		return err
	}

	if err := v.validateFormat(&cfg); err != nil {
		return err
	}

	return nil
}

func (v *Validator) validateSeverity(cfg *config.Config) error {
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	if cfg.SeverityFilter == "" {
		if v.strictMode {
			return fmt.Errorf("severity is required in strict mode")
		}
		return nil
	}

	if !validSeverities[cfg.SeverityFilter] {
		return fmt.Errorf("invalid severity '%s', must be one of: critical, high, medium, low", cfg.SeverityFilter)
	}

	return nil
}

func (v *Validator) validatePaths(cfg *config.Config) error {
	if len(cfg.CustomPaths) == 0 {
		return nil
	}

	for _, path := range cfg.CustomPaths {
		if path == "" {
			return fmt.Errorf("empty path in paths list")
		}
	}

	return nil
}

func (v *Validator) validateFormat(cfg *config.Config) error {
	validFormats := map[string]bool{
		"text":     true,
		"json":     true,
		"html":     true,
		"sarif":    true,
		"csv":      true,
		"xml":      true,
		"markdown": true,
	}

	if cfg.OutputFormat == "" {
		return nil
	}

	if !validFormats[cfg.OutputFormat] {
		return fmt.Errorf("invalid format '%s', must be one of: text, json, html, sarif, csv, xml, markdown", cfg.OutputFormat)
	}

	return nil
}

func (v *Validator) ValidatePolicyFile(path string) ([]ValidationError, error) {
	var errors []ValidationError

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}

	content := string(data)

	if containsAnonymousAccess(content) {
		errors = append(errors, ValidationError{
			RuleID: "POL-001",
			Message: "Policy contains result_any=yes (anonymous access)",
			Severity: "HIGH",
		})
	}

	if containsWildcardUsers(content) {
		errors = append(errors, ValidationError{
			RuleID: "POL-002",
			Message: "Policy contains unix-user:* (all users)",
			Severity: "CRITICAL",
		})
	}

	if containsWildcardGroups(content) {
		errors = append(errors, ValidationError{
			RuleID: "POL-003",
			Message: "Policy contains unix-group:all",
			Severity: "MEDIUM",
		})
	}

	if containsMissingAuth(content) {
		errors = append(errors, ValidationError{
			RuleID: "POL-004",
			Message: "Policy has rules without authentication requirement",
			Severity: "HIGH",
		})
	}

	return errors, nil
}

func containsAnonymousAccess(content string) bool {
	return contains(content, "result_any=yes")
}

func containsWildcardUsers(content string) bool {
	return contains(content, "unix-user:*")
}

func containsWildcardGroups(content string) bool {
	return contains(content, "unix-group:all") || contains(content, "unix-group: everybody")
}

func containsMissingAuth(content string) bool {
	return contains(content, "ResultAny") && !contains(content, "auth_")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

type ValidationError struct {
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

func (e ValidationError) String() string {
	return fmt.Sprintf("[%s] %s: %s", e.Severity, e.RuleID, e.Message)
}

func ValidateRules(rules []models.PolkitRule) []ValidationError {
	var errors []ValidationError

	for _, rule := range rules {
		if rule.Action == "" {
			errors = append(errors, ValidationError{
				RuleID:   "POL-005",
				Message:  "Rule missing action",
				Severity: "ERROR",
			})
		}

		if rule.Identity == "" {
			errors = append(errors, ValidationError{
				RuleID:   "POL-006",
				Message:  "Rule missing identity",
				Severity: "ERROR",
			})
		}

		if rule.ResultAny == "" && rule.ResultActive == "" && rule.ResultInactive == "" {
			errors = append(errors, ValidationError{
				RuleID:   "POL-007",
				Message:  "Rule has no result defined",
				Severity: "WARNING",
			})
		}
	}

	return errors
}