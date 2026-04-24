package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/models"
)

var (
	scanTotal     int64
	scanCritical  int64
	scanHigh      int64
	scanMedium    int64
	scanLow       int64
	scanLastTime  time.Time
	mu            sync.RWMutex
	lastScanMutex sync.RWMutex
)

type Metrics struct {
	ScanTotal    int64   `json:"polkitguard_scan_total"`
	ScanCritical int64   `json:"polkitguard_scan_critical"`
	ScanHigh     int64   `json:"polkitguard_scan_high"`
	ScanMedium   int64   `json:"polkitguard_scan_medium"`
	ScanLow      int64   `json:"polkitguard_scan_low"`
	ScanLastTime float64 `json:"polkitguard_scan_last_timestamp_seconds"`
}

func RecordScan(result models.ScanResult) {
	mu.Lock()
	defer mu.Unlock()

	scanTotal++
	scanCritical += int64(result.CountBySeverity(models.SeverityCritical))
	scanHigh += int64(result.CountBySeverity(models.SeverityHigh))
	scanMedium += int64(result.CountBySeverity(models.SeverityMedium))
	scanLow += int64(result.CountBySeverity(models.SeverityLow))
	scanLastTime = time.Now()
}

func GetMetrics() Metrics {
	mu.RLock()
	defer mu.RUnlock()

	return Metrics{
		ScanTotal:    scanTotal,
		ScanCritical: scanCritical,
		ScanHigh:     scanHigh,
		ScanMedium:   scanMedium,
		ScanLow:      scanLow,
		ScanLastTime: float64(scanLastTime.Unix()),
	}
}

func (m Metrics) String() string {
	return fmt.Sprintf(`# HELP polkitguard_scan_total Total number of scans performed
# TYPE polkitguard_scan_total counter
polkitguard_scan_total %d
# HELP polkitguard_scan_critical Total critical issues found
# TYPE polkitguard_scan_critical counter
polkitguard_scan_critical %d
# HELP polkitguard_scan_high Total high severity issues found
# TYPE polkitguard_scan_high counter
polkitguard_scan_high %d
# HELP polkitguard_scan_medium Total medium severity issues found
# TYPE polkitguard_scan_medium counter
polkitguard_scan_medium %d
# HELP polkitguard_scan_low Total low severity issues found
# TYPE polkitguard_scan_low counter
polkitguard_scan_low %d
# HELP polkitguard_scan_last_timestamp_seconds Timestamp of last scan
# TYPE polkitguard_scan_last_timestamp_seconds gauge
polkitguard_scan_last_timestamp_seconds %.0f
`,
		m.ScanTotal, m.ScanCritical, m.ScanHigh, m.ScanMedium, m.ScanLow, m.ScanLastTime)
}

func (m Metrics) JSON() (string, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
	m := GetMetrics()

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json, _ := m.JSON()
		w.Write([]byte(json))
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(m.String()))
}

func PrometheusHandler() http.Handler {
	return http.HandlerFunc(Handler)
}
