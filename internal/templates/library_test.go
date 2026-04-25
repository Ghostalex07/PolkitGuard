package templates

import (
	"strings"
	"testing"
)

func TestGetTemplatesByCategory(t *testing.T) {
	templates := GetTemplatesByCategory("System Administration")
	if len(templates) == 0 {
		t.Error("Expected at least one template for System Administration")
	}
}

func TestGetTemplatesByCategoryCaseInsensitive(t *testing.T) {
	t1 := GetTemplatesByCategory("system administration")
	t2 := GetTemplatesByCategory("SYSTEM ADMINISTRATION")

	if len(t1) != len(t2) {
		t.Error("Case should not affect results")
	}
}

func TestGetTemplatesBySeverity(t *testing.T) {
	templates := GetTemplatesBySeverity("CRITICAL")
	if len(templates) == 0 {
		t.Error("Expected at least one CRITICAL template")
	}
}

func TestSearchTemplates(t *testing.T) {
	templates := SearchTemplates("admin")
	if len(templates) == 0 {
		t.Error("Expected at least one result for 'admin' search")
	}
}

func TestSearchTemplatesNoResults(t *testing.T) {
	templates := SearchTemplates("xyznonexistent")
	if len(templates) != 0 {
		t.Errorf("Expected 0 results, got %d", len(templates))
	}
}

func TestSearchTemplatesCaseInsensitive(t *testing.T) {
	t1 := SearchTemplates("admin")
	t2 := SearchTemplates("ADMIN")

	if len(t1) != len(t2) {
		t.Error("Search should be case insensitive")
	}
}

func TestPolicyTemplateGenerateRulesFile(t *testing.T) {
	template := PolicyTemplate{
		Name:        "Test Template",
		Description: "Test description",
		Category:    "Test",
		Rules: []string{
			"[unix-group:wheel]",
			"ResultAny=auth_admin",
		},
	}

	content := template.GenerateRulesFile()
	if !strings.Contains(content, "Test Template") {
		t.Error("Expected template name in output")
	}
	if !strings.Contains(content, "unix-group:wheel") {
		t.Error("Expected rules in output")
	}
}

func TestListCategories(t *testing.T) {
	categories := ListCategories()
	if len(categories) == 0 {
		t.Error("Expected at least one category")
	}

	// Check for duplicates
	seen := make(map[string]bool)
	for _, cat := range categories {
		if seen[cat] {
			t.Errorf("Duplicate category: %s", cat)
		}
		seen[cat] = true
	}
}

func TestGetTemplatesByCategoryNotFound(t *testing.T) {
	templates := GetTemplatesByCategory("NonExistent Category")
	if len(templates) != 0 {
		t.Errorf("Expected 0 results, got %d", len(templates))
	}
}