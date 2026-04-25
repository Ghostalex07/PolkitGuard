package generator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestNewGenerator(t *testing.T) {
	g := NewGenerator()
	if g == nil {
		t.Fatal("Expected non-nil generator")
	}
	if g.author != "admin" {
		t.Errorf("Expected default author 'admin', got %s", g.author)
	}
}

func TestGeneratorSetAuthor(t *testing.T) {
	g := NewGenerator().SetAuthor("testuser")
	if g.author != "testuser" {
		t.Errorf("Expected 'testuser', got %s", g.author)
	}
}

func TestGeneratorSetVersion(t *testing.T) {
	g := NewGenerator().SetVersion("2.0.0")
	if g.version != "2.0.0" {
		t.Errorf("Expected '2.0.0', got %s", g.version)
	}
}

func TestGeneratorGenerateFromFindings(t *testing.T) {
	g := NewGenerator()
	findings := []models.Finding{
		{
			Severity: models.SeverityCritical,
			Rule: &models.PolkitRule{
				Action:    "org.test.action",
				Identity:  "unix-user:*",
				ResultAny: "yes",
			},
		},
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.rules")

	err := g.GenerateFromFindings(findings, outputPath)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Expected file to exist, got error %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty file")
	}

	if !contains(string(data), "unix-user:*") {
		t.Error("Expected generated file to contain identity")
	}
}

func TestGeneratorGenerateSecureRules(t *testing.T) {
	g := NewGenerator()
	actions := []string{"org.test.action1", "org.test.action2"}
	identity := "unix-group:wheel"
	result := "auth_admin"

	content := g.GenerateSecureRules(actions, identity, result)

	if !contains(content, "unix-group:wheel") {
		t.Error("Expected wheel group in output")
	}
	if !contains(content, "auth_admin") {
		t.Error("Expected auth_admin result in output")
	}
}

func TestGeneratorGenerateTemplate(t *testing.T) {
	g := NewGenerator()

	templates := []string{"admin", "service", "network", "user", "default"}

	for _, tmpl := range templates {
		content := g.GenerateTemplate(tmpl)
		if len(content) == 0 {
			t.Errorf("Expected non-empty content for template %s", tmpl)
		}
	}
}

func TestGeneratorGenerateConfig(t *testing.T) {
	g := NewGenerator().SetAuthor("test").SetVersion("1.0.0")

	content := g.GenerateConfig()

	if !contains(content, "test") {
		t.Error("Expected author in config")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (len(substr) == 0 || len(s) > 0 &&
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}