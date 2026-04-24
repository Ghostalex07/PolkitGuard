package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestParseFile(t *testing.T) {
	tmpDir := t.TempDir()

	testRule := `[polkit_rule]
identity=unix-user:admin
action=org.freedesktop.system-logind*
result_any=auth_admin_keep
`
	testFile := filepath.Join(tmpDir, "test.rules")
	if err := os.WriteFile(testFile, []byte(testRule), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	p := NewParser()
	rules, err := p.ParseFile(testFile)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].Identity != "unix-user:admin" {
		t.Errorf("expected identity 'unix-user:admin', got '%s'", rules[0].Identity)
	}
	if rules[0].Action != "org.freedesktop.system-logind*" {
		t.Errorf("expected action 'org.freedesktop.system-logind*', got '%s'", rules[0].Action)
	}
	if rules[0].ResultAny != "auth_admin_keep" {
		t.Errorf("expected result_any 'auth_admin_keep', got '%s'", rules[0].ResultAny)
	}
}

func TestParseFileNotFound(t *testing.T) {
	p := NewParser()
	_, err := p.ParseFile("/nonexistent/file.rules")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestParseMultipleRules(t *testing.T) {
	tmpDir := t.TempDir()

	testRule := `[polkit_rule]
identity=unix-user:admin
action=org.test.action1
result_any=yes

[polkit_rule]
identity=unix-group:wheel
action=org.test.action2
result_any=auth_admin
`
	testFile := filepath.Join(tmpDir, "test.rules")
	if err := os.WriteFile(testFile, []byte(testRule), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	p := NewParser()
	rules, err := p.ParseFile(testFile)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].Identity != "unix-user:admin" {
		t.Errorf("first rule: expected identity 'unix-user:admin', got '%s'", rules[0].Identity)
	}
	if rules[1].Identity != "unix-group:wheel" {
		t.Errorf("second rule: expected identity 'unix-group:wheel', got '%s'", rules[1].Identity)
	}
}

func TestParseDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "01-test.rules")
	file2 := filepath.Join(tmpDir, "02-another.rules")

	os.WriteFile(file1, []byte("[polkit_rule]\nidentity=u1\naction=a1\nresult_any=yes\n"), 0644)
	os.WriteFile(file2, []byte("[polkit_rule]\nidentity=u2\naction=a2\nresult_any=no\n"), 0644)

	p := NewParser()
	rules, err := p.ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory returned error: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestExtractValue(t *testing.T) {
	tests := []struct {
		line     string
		prefix   string
		expected string
	}{
		{"identity=unix-user:admin;", "identity=", "unix-user:admin"},
		{`action="org.test"`, "action=", "org.test"},
		{"result_any=auth_admin", "result_any=", "auth_admin"},
		{`result_active="yes"`, "result_active=", "yes"},
	}

	for _, tt := range tests {
		result := extractValue(tt.line, tt.prefix)
		if result != tt.expected {
			t.Errorf("extractValue(%q, %q) = %q, want %q", tt.line, tt.prefix, result, tt.expected)
		}
	}
}

func TestExtractRuleName(t *testing.T) {
	tests := []struct {
		raw      string
		expected string
	}{
		{"return auth_admin_keep", "return auth_admin_keep"},
		{"identity=foo\naction=bar", "identity=foo"},
		{"  return yes  ", "return yes"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		result := extractRuleName(tt.raw)
		if result != tt.expected {
			t.Errorf("extractRuleName(%q) = %q, want %q", tt.raw, result, tt.expected)
		}
	}
}

var _ = models.PolkitRule{} // suppress unused import
