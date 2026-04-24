package detector

import (
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func BenchmarkDetectCRIT001(b *testing.B) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity:  "unix-user:test",
		Action:    "org.test.action",
		ResultAny: "yes",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(rule)
	}
}

func BenchmarkDetectCRIT002(b *testing.B) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "unix-user:*",
		Action:  "org.test.action",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(rule)
	}
}

func BenchmarkDetectHIGH001(b *testing.B) {
	d := NewDetector()
	rule := models.PolkitRule{
		Identity: "unix-group:all",
		Action:  "org.test.action",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(rule)
	}
}

func BenchmarkDetectAll100Rules(b *testing.B) {
	d := NewDetector()
	rules := make([]models.PolkitRule, 100)
	for i := 0; i < 100; i++ {
		rules[i] = models.PolkitRule{
			Identity:  "unix-user:admin",
			Action:   "org.test.action",
			ResultAny: "yes",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.DetectAll(rules)
	}
}