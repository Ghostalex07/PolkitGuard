package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CVEReport struct {
	ID          string    `json:"id"`
	Published   time.Time `json:"published"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	References  []string  `json:"references"`
}

type CVEService struct {
	baseURL    string
	httpClient *http.Client
}

func NewCVEService() *CVEService {
	return &CVEService{
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *CVEService) Lookup(keyword string) ([]CVEReport, error) {
	url := fmt.Sprintf("%s?keywordSearch=%s", c.baseURL, keyword)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query NVD: %w", err)
	}
	defer resp.Body.Close()

	return c.parseResponse(resp.Body)
}

func (c *CVEService) LookupPolkit() ([]CVEReport, error) {
	return c.Lookup("polkit")
}

func (c *CVEService) LookupPolicyKit() ([]CVEReport, error) {
	return c.Lookup("policy kit")
}

func (c *CVEService) LookupAction(action string) ([]CVEReport, error) {
	keyword := strings.ReplaceAll(action, ".", " ")
	return c.Lookup(keyword)
}

func (c *CVEService) parseResponse(body io.Reader) ([]CVEReport, error) {
	var response struct {
		ResultsPerPage  int `json:"resultsPerPage"`
		Vulnerabilities []struct {
			CVE struct {
				ID          string    `json:"id"`
				Published   time.Time `json:"published"`
				Description string    `json:"description"`
				References  []struct {
					URL string `json:"url"`
				} `json:"references"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						}
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, err
	}

	var reports []CVEReport
	for _, vuln := range response.Vulnerabilities {
		cve := vuln.CVE
		references := make([]string, len(cve.References))
		for i, ref := range cve.References {
			references[i] = ref.URL
		}

		cvss := 0.0
		severity := "UNKNOWN"
		if len(cve.Metrics.CvssMetricV31) > 0 {
			cvss = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}

		reports = append(reports, CVEReport{
			ID:          cve.ID,
			Published:   cve.Published,
			Description: cve.Description,
			Severity:    severity,
			CVSS:        cvss,
			References:  references,
		})

		if len(reports) >= 10 {
			break
		}
	}

	return reports, nil
}

func (r CVEReport) String() string {
	return fmt.Sprintf("[%s] %s (CVSS: %.1f)\n%s",
		r.Severity, r.ID, r.CVSS, r.Description)
}
