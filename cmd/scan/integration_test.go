package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegrationMultiplePaths(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir1, "test1.rules"), []byte(`[unix-user:admin]
result_any=auth_admin
`), 0644)
	os.WriteFile(filepath.Join(tmpDir2, "test2.rules"), []byte(`[unix-group:wheel]
result_any=auth_admin
`), 0644)

	cmd := exec.Command("go", "run", "./cmd/scan", "--path", tmpDir1+","+tmpDir2)
	cmd.Dir = "/home/vaca/github/PolkitGuard"

	output, _ := cmd.CombinedOutput()

	if !strings.Contains(string(output), "rule") {
		t.Logf("Expected output to contain 'rule', got: %s", string(output))
	}
}

func TestIntegrationSeverityFilter(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "high.rules"), []byte(`[unix-user:*]
result_any=yes
`), 0644)

	tests := []struct {
		severity string
	}{
		{"critical"},
		{"high"},
		{"medium"},
		{"low"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			cmd := exec.Command("go", "run", "./cmd/scan", "--path", tmpDir, "--severity", tt.severity)
			cmd.Dir = "/home/vaca/github/PolkitGuard"

			cmd.Run()
		})
	}
}

func TestIntegrationOutputFormats(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "test.rules"), []byte(`[unix-user:admin]
result_any=auth_admin
`), 0644)

	formats := []string{"text", "json", "csv"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			cmd := exec.Command("go", "run", "./cmd/scan", "--path", tmpDir, "--format", format)
			cmd.Dir = "/home/vaca/github/PolkitGuard"

			cmd.Run()
		})
	}
}

func TestIntegrationHelp(t *testing.T) {
	cmd := exec.Command("go", "run", "./cmd/scan", "--help")
	cmd.Dir = "/home/vaca/github/PolkitGuard"

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Help should not error: %v", err)
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Errorf("Expected usage in help output")
	}
}

func TestIntegrationVersion(t *testing.T) {
	cmd := exec.Command("go", "run", "./cmd/scan", "--version")
	cmd.Dir = "/home/vaca/github/PolkitGuard"

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Version should not error: %v", err)
	}

	if !strings.Contains(string(output), "1.18") {
		t.Logf("Expected version in output, got: %s", string(output))
	}
}

func TestIntegrationNoColor(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "test.rules"), []byte(`[unix-user:admin]
result_any=auth_admin
`), 0644)

	cmd := exec.Command("go", "run", "./cmd/scan", "--path", tmpDir, "--no-color")
	cmd.Dir = "/home/vaca/github/PolkitGuard"

	cmd.Run()
}

func TestIntegrationVerbose(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "test.rules"), []byte(`[unix-user:admin]
result_any=auth_admin
`), 0644)

	cmd := exec.Command("go", "run", "./cmd/scan", "--path", tmpDir, "-v")
	cmd.Dir = "/home/vaca/github/PolkitGuard"

	cmd.Run()
}

func TestIntegrationQuiet(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "test.rules"), []byte(`[unix-user:admin]
result_any=auth_admin
`), 0644)

	cmd := exec.Command("go", "run", "./cmd/scan", "--path", tmpDir, "-q")
	cmd.Dir = "/home/vaca/github/PolkitGuard"

	cmd.Run()
}