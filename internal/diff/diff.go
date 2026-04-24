package diff

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type DiffResult struct {
	Added   []models.Finding
	Removed []models.Finding
	Same    int
}

type ScanComparison struct {
	Old    models.ScanResult
	New    models.ScanResult
	Result DiffResult
}

func Compare(oldResult, newResult models.ScanResult) *ScanComparison {
	comparison := &ScanComparison{
		Old: oldResult,
		New: newResult,
	}

	oldMap := map[string]bool{}
	for _, f := range oldResult.Findings {
		oldMap[f.RuleName+"|"+f.File] = true
	}

	for _, f := range newResult.Findings {
		key := f.RuleName + "|" + f.File
		if oldMap[key] {
			comparison.Result.Same++
		} else {
			comparison.Result.Added = append(comparison.Result.Added, f)
		}
	}

	for _, f := range oldResult.Findings {
		key := f.RuleName + "|" + f.File
		found := false
		for _, nf := range newResult.Findings {
			if nf.RuleName+"|"+nf.File == key {
				found = true
				break
			}
		}
		if !found {
			comparison.Result.Removed = append(comparison.Result.Removed, f)
		}
	}

	return comparison
}

func (c *ScanComparison) String() string {
	return fmt.Sprintf("Diff: +%d / -%d / =%d",
		len(c.Result.Added), len(c.Result.Removed), c.Result.Same)
}

func SaveDiff(result *models.ScanResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadDiff(path string) (*models.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type DiffConfig struct {
	PreviousPath string `json:"previous_path"`
	OutputPath   string `json:"output_path"`
	Threshold    int    `json:"threshold"`
}

func NewDiffChecker(previousPath string) *DiffConfig {
	return &DiffConfig{
		PreviousPath: previousPath,
		Threshold:    0,
	}
}

func (d *DiffConfig) Check(newResult models.ScanResult) (*ScanComparison, error) {
	var oldResult models.ScanResult
	if d.PreviousPath != "" {
		var err error
		oldResultPtr, err := LoadDiff(d.PreviousPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load previous scan: %w", err)
		}
		oldResult = *oldResultPtr
	}

	comparison := Compare(oldResult, newResult)

	if d.OutputPath != "" {
		if err := SaveDiff(&newResult, d.OutputPath); err != nil {
			return nil, err
		}
	}

	return comparison, nil
}
