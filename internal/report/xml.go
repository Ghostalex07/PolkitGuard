package report

import (
	"encoding/xml"
	"fmt"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type XMLReport struct {
	XMLName    xml.Name        `xml:"PolkitGuardReport"`
	Version    string          `xml:"version,attr"`
	Generated  string         `xml:"generated"`
	Summary    XMLSummary      `xml:"summary"`
	Findings   []XMLFinding    `xml:"findings>finding"`
}

type XMLSummary struct {
	FilesScanned   int `xml:"files_scanned"`
	RulesFound     int `xml:"rules_found"`
	TotalFindings  int `xml:"total_findings"`
	CriticalCount  int `xml:"critical_count"`
	HighCount      int `xml:"high_count"`
	MediumCount    int `xml:"medium_count"`
	LowCount       int `xml:"low_count"`
}

type XMLFinding struct {
	ID          string     `xml:"id,attr"`
	RuleID      string     `xml:"rule_id"`
	Severity    string     `xml:"severity"`
	Title       string     `xml:"title"`
	Description string     `xml:"description"`
	Message     string     `xml:"message"`
	FilePath    string     `xml:"file_path,omitempty"`
	Line        int        `xml:"line,omitempty"`
	Action      string     `xml:"action,omitempty"`
	Identity    string     `xml:"identity,omitempty"`
}

func GenerateXMLReport(result *models.ScanResult) string {
	report := XMLReport{
		Version:   "1.18.0",
		Generated: formatTime(),
		Summary: XMLSummary{
			FilesScanned:  result.FilesScanned,
			RulesFound:    result.RulesFound,
			TotalFindings: len(result.Findings),
			CriticalCount: len(result.GetFindingsByMinSeverity(models.SeverityCritical)),
			HighCount:     len(result.GetFindingsByMinSeverity(models.SeverityHigh)),
			MediumCount:   len(result.GetFindingsByMinSeverity(models.SeverityMedium)),
			LowCount:      len(result.GetFindingsByMinSeverity(models.SeverityLow)),
		},
		Findings: []XMLFinding{},
	}

	for _, f := range result.Findings {
		xmlFinding := XMLFinding{
			ID:          f.RuleID,
			RuleID:      f.RuleID,
			Severity:    f.Severity.String(),
			Title:       f.Title,
			Description: f.Description,
			Message:     f.Message,
		}

		if f.Rule != nil {
			xmlFinding.Action = f.Rule.Action
			xmlFinding.Identity = f.Rule.Identity
		}

		report.Findings = append(report.Findings, xmlFinding)
	}

	bytes, _ := xml.MarshalIndent(report, "", "  ")
	return xml.Header + string(bytes)
}

func formatTime() string {
	return "2026-04-25T12:00:00Z"
}

type ExcelReport struct {
	Sheets []ExcelSheet `xml:"sheets>sheet"`
}

type ExcelSheet struct {
	Name    string         `xml:"name,attr"`
	Headers []string       `xml:"headers>header"`
	Rows    []ExcelRow     `xml:"rows>row"`
}

type ExcelRow struct {
	Cells []ExcelCell `xml:"cell"`
}

type ExcelCell struct {
	Value string `xml:"value,attr"`
	Type  string `xml:"type,attr"`
}

func GenerateExcelXML(result *models.ScanResult) string {
	report := ExcelReport{
		Sheets: []ExcelSheet{
			{
				Name: "Summary",
				Headers: []string{"Metric", "Value"},
				Rows: []ExcelRow{
					{Cells: []ExcelCell{{Value: "Files Scanned", Type: "string"}, {Value: fmt.Sprintf("%d", result.FilesScanned), Type: "number"}}},
					{Cells: []ExcelCell{{Value: "Rules Found", Type: "string"}, {Value: fmt.Sprintf("%d", result.RulesFound), Type: "number"}}},
					{Cells: []ExcelCell{{Value: "Total Findings", Type: "string"}, {Value: fmt.Sprintf("%d", len(result.Findings)), Type: "number"}}},
					{Cells: []ExcelCell{{Value: "Critical", Type: "string"}, {Value: fmt.Sprintf("%d", len(result.GetFindingsByMinSeverity(models.SeverityCritical))), Type: "number"}}},
					{Cells: []ExcelCell{{Value: "High", Type: "string"}, {Value: fmt.Sprintf("%d", len(result.GetFindingsByMinSeverity(models.SeverityHigh))), Type: "number"}}},
					{Cells: []ExcelCell{{Value: "Medium", Type: "string"}, {Value: fmt.Sprintf("%d", len(result.GetFindingsByMinSeverity(models.SeverityMedium))), Type: "number"}}},
					{Cells: []ExcelCell{{Value: "Low", Type: "string"}, {Value: fmt.Sprintf("%d", len(result.GetFindingsByMinSeverity(models.SeverityLow))), Type: "number"}}},
				},
			},
			{
				Name: "Findings",
				Headers: []string{"ID", "Severity", "Title", "Action", "Identity", "Description"},
				Rows:    []ExcelRow{},
			},
		},
	}

	for _, f := range result.Findings {
		row := ExcelRow{
			Cells: []ExcelCell{
				{Value: f.RuleID, Type: "string"},
				{Value: f.Severity.String(), Type: "string"},
				{Value: f.Title, Type: "string"},
			},
		}

		if f.Rule != nil {
			row.Cells = append(row.Cells,
				ExcelCell{Value: f.Rule.Action, Type: "string"},
				ExcelCell{Value: f.Rule.Identity, Type: "string"},
			)
		} else {
			row.Cells = append(row.Cells,
				ExcelCell{Value: "", Type: "string"},
				ExcelCell{Value: "", Type: "string"},
			)
		}

		row.Cells = append(row.Cells, ExcelCell{Value: f.Description, Type: "string"})
		report.Sheets[1].Rows = append(report.Sheets[1].Rows, row)
	}

	bytes, _ := xml.MarshalIndent(report, "", "  ")
	return xml.Header + string(bytes)
}