package notifier

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

func TestNewWebhookNotifier(t *testing.T) {
	url := "https://example.com/webhook"
	w := NewWebhookNotifier(url)
	if w.URL != url {
		t.Errorf("expected URL %s, got %s", url, w.URL)
	}
}

func TestWebhookConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid URL", "https://example.com/webhook", false},
		{"empty URL", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &WebhookConfig{URL: tt.url}
			err := w.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWebhookConfigNotifyNoURL(t *testing.T) {
	w := &WebhookConfig{}
	err := w.Notify(*models.NewScanResult())
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestWebhookConfigNotifyNoFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := &WebhookConfig{URL: server.URL}
	result := models.NewScanResult()
	err := notifier.Notify(*result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWebhookConfigNotifyWithFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := &WebhookConfig{URL: server.URL}
	result := models.NewScanResult()
	result.AddFinding(models.Finding{
		Severity: models.SeverityCritical,
		Message:  "Test finding",
	})

	err := notifier.Notify(*result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWebhookConfigNotifyServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := &WebhookConfig{URL: server.URL}
	result := models.NewScanResult()
	result.AddFinding(models.Finding{Severity: models.SeverityHigh})

	err := notifier.Notify(*result)
	if err == nil {
		t.Error("expected error for server error status")
	}
}

func TestWebhookConfigNotifyWithSecret(t *testing.T) {
	receivedSecret := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret = r.Header.Get("X-Webhook-Secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := &WebhookConfig{URL: server.URL, Secret: "test-secret"}
	result := models.NewScanResult()
	result.AddFinding(models.Finding{Severity: models.SeverityMedium})

	err := notifier.Notify(*result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if receivedSecret != "test-secret" {
		t.Errorf("expected secret 'test-secret', got %s", receivedSecret)
	}
}
