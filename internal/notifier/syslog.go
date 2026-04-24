package notifier

import (
	"fmt"
	"os"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

type SyslogConfig struct {
	Network string
	Address string
	Tag     string
}

func NewSyslogNotifier() *SyslogConfig {
	return &SyslogConfig{
		Tag: "polkitguard",
	}
}

func (s *SyslogConfig) Notify(result models.ScanResult) error {
	priority := 14
	if result.HasCritical() {
		priority = 2
	} else if result.HasHigh() {
		priority = 3
	}

	timestamp := time.Now().Format("Jan  2 15:04:05")
	hostname, _ := os.Hostname()
	tag := s.Tag
	if tag == "" {
		tag = "polkitguard"
	}

	msg := fmt.Sprintf("PolkitGuard: %d issues (C=%d H=%d M=%d L=%d)",
		len(result.Findings),
		result.CountBySeverity(models.SeverityCritical),
		result.CountBySeverity(models.SeverityHigh),
		result.CountBySeverity(models.SeverityMedium),
		result.CountBySeverity(models.SeverityLow))

	syslogMsg := fmt.Sprintf("<%d>%s %s %s: %s", priority, timestamp, hostname, tag, msg)
	fmt.Fprintf(os.Stderr, "[SYSLOG] %s\n", syslogMsg)
	return nil
}
