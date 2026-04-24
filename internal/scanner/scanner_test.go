package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewScanner(t *testing.T) {
	paths := []string{"/test/path"}
	s := NewScanner(paths)
	if len(s.Paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(s.Paths))
	}
}

func TestNewScannerDefault(t *testing.T) {
	s := NewScanner(nil)
	if len(s.Paths) == 0 {
		t.Error("expected default paths")
	}
}

func TestGetDefaultPolkitPaths(t *testing.T) {
	paths := getDefaultPolkitPaths()
	if len(paths) == 0 {
		t.Error("expected default paths")
	}
}

func TestScannerScan(t *testing.T) {
	s := NewScanner([]string{"/nonexistent"})
	files, err := s.Scan()
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
	if files != nil {
		t.Error("expected nil files")
	}
}

func TestScannerScanDirectory(t *testing.T) {
	s := NewScanner(nil)
	_, err := s.ScanDirectory("/nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestScannerScanDirectoryCurrent(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.rules")
	if err := os.WriteFile(testFile, []byte("result_any=auth_admin\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	s := NewScanner(nil)
	files, err := s.ScanDirectory(tmpDir)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestSetLogger(t *testing.T) {
	logger := func(format string, args ...interface{}) {}
	SetLogger(logger)
}
