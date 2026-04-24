package scanner

import (
	"testing"
)

func TestScanDefault(t *testing.T) {
	s := NewScanner(nil)
	if len(s.Paths) == 0 {
		t.Error("Expected default paths")
	}
}

func TestScanCustom(t *testing.T) {
	s := NewScanner([]string{"/tmp"})
	if len(s.Paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(s.Paths))
	}
}

func TestScanDirectory(t *testing.T) {
	s := NewScanner(nil)
	files, err := s.ScanDirectory("testdata")
	if err != nil {
		t.Skip("testdata not found, skipping")
	}
	if len(files) == 0 {
		t.Error("Expected files in testdata")
	}
}

func TestScanDirectoryNotFound(t *testing.T) {
	s := NewScanner(nil)
	_, err := s.ScanDirectory("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for nonexistent directory")
	}
}

func TestGetDefaultPolkitPaths(t *testing.T) {
	paths := getDefaultPolkitPaths()
	if len(paths) == 0 {
		t.Error("Expected default polkit paths")
	}
	for _, p := range paths {
		if p == "" {
			t.Error("Empty path found")
		}
	}
}

func TestSetLogger(t *testing.T) {
	SetLogger(func(format string, args ...interface{}) {})
}
