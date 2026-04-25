package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type WebhookConfig struct {
	URL         string   `json:"url"`
	URLs        []string `json:"urls,omitempty"`
	Secret      string   `json:"secret,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
}

type WebhookPayload struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Summary   Summary   `json:"summary"`
	Findings  []Finding `json:"findings,omitempty"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

type Finding struct {
	RuleID         string `json:"rule_id"`
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	File           string `json:"file"`
	Action         string `json:"action,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func NewWebhookNotifier(url string) *WebhookConfig {
	if strings.Contains(url, ",") {
		return &WebhookConfig{URLs: strings.Split(url, ",")}
	}
	return &WebhookConfig{URL: url}
}

func (w *WebhookConfig) Notify(result models.ScanResult) error {
	urls := w.URLs
	if len(urls) == 0 && w.URL != "" {
		urls = []string{w.URL}
	}
	if len(urls) == 0 {
		return fmt.Errorf("webhook URL not configured")
	}

	summary := Summary{
		Critical: result.CountBySeverity(models.SeverityCritical),
		High:     result.CountBySeverity(models.SeverityHigh),
		Medium:   result.CountBySeverity(models.SeverityMedium),
		Low:      result.CountBySeverity(models.SeverityLow),
		Total:    len(result.Findings),
	}

	if summary.Total == 0 {
		return nil
	}

	payload := WebhookPayload{
		Version:   "1.17.0",
		Timestamp: time.Now().UTC(),
		Summary:   summary,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	var errors []string
	for _, url := range urls {
		if err := sendToURL(url, w.Secret, data); err != nil {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("webhook errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

func sendToURL(url, secret string, data []byte) error {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Webhook-Secret", secret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (w *WebhookConfig) Validate() error {
	if w.URL == "" && len(w.URLs) == 0 {
		return fmt.Errorf("webhook URL is required")
	}
	return nil
}
