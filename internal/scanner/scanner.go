package scanner

import (
	"fmt"
	"os"
	"path/filepath"
)

var verboseLog func(format string, args ...interface{})

func init() {
	verboseLog = func(format string, args ...interface{}) {}
}

func SetLogger(logger func(format string, args ...interface{})) {
	verboseLog = logger
}

type Scanner struct {
	Paths []string
}

func NewScanner(paths []string) *Scanner {
	if len(paths) == 0 {
		paths = getDefaultPolkitPaths()
	}
	return &Scanner{Paths: paths}
}

func getDefaultPolkitPaths() []string {
	return []string{
		"/usr/share/polkit-1/rules.d",
		"/etc/polkit-1/rules.d",
		"/usr/share/polkit-1/localauthority/50-local.d",
		"/etc/polkit-1/localauthority/50-local.d",
	}
}

func (s *Scanner) Scan() ([]string, error) {
	var ruleFiles []string

	for _, path := range s.Paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			verboseLog("Directory not found: %s", path)
			continue
		}

		files, err := filepath.Glob(filepath.Join(path, "*.rules"))
		if err != nil {
			verboseLog("Error scanning directory %s: %v", path, err)
			continue
		}
		if len(files) == 0 {
			verboseLog("No .rules files found in: %s", path)
		}
		ruleFiles = append(ruleFiles, files...)
	}

	if len(ruleFiles) == 0 {
		return nil, fmt.Errorf("no polkit rule files found")
	}

	return ruleFiles, nil
}

func (s *Scanner) ScanDirectory(dir string) ([]string, error) {
	var ruleFiles []string

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", dir)
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && filepath.Ext(path) == ".rules" {
			ruleFiles = append(ruleFiles, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return ruleFiles, nil
}