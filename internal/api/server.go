package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Ghostalex07/PolkitGuard/internal/detector"
	"github.com/Ghostalex07/PolkitGuard/internal/models"
	"github.com/Ghostalex07/PolkitGuard/internal/parser"
	"github.com/Ghostalex07/PolkitGuard/internal/risk"
	"github.com/Ghostalex07/PolkitGuard/internal/scanner"
)

const version = "1.18.0"

type Server struct {
	port int
	mux  *http.ServeMux
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewServer(port int) *Server {
	mux := http.NewServeMux()
	s := &Server{port: port, mux: mux}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/scan", s.handleScan)
	s.mux.HandleFunc("/risk", s.handleRisk)
	s.mux.HandleFunc("/surface", s.handleSurface)
	s.mux.HandleFunc("/version", s.handleVersion)
	s.mux.HandleFunc("/templates", s.handleTemplates)
	s.mux.HandleFunc("/diff", s.handleDiff)
	s.mux.HandleFunc("/remediate", s.handleRemediate)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	result := scanSystem()
	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":   getHealthStatus(result),
			"findings": len(result.Findings),
		},
	}
	writeJSON(w, response)
}

func getHealthStatus(result models.ScanResult) string {
	if result.HasCritical() {
		return "CRITICAL"
	}
	if result.HasHigh() {
		return "WARNING"
	}
	return "HEALTHY"
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	path := r.URL.Query().Get("path")

	result := runScan(path)

	if severity != "" {
		sev := parseSeverity(severity)
		result.Findings = result.GetFindingsByMinSeverity(sev)
	}

	response := APIResponse{
		Success: true,
		Data:    result,
	}
	writeJSON(w, response)
}

func (s *Server) handleRisk(w http.ResponseWriter, r *http.Request) {
	result := scanSystem()
	score := risk.CalculateRiskScore(result.Findings, nil)

	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"overall":         score.Overall,
			"level":           score.Level(),
			"criticality":     score.Criticality,
			"likelihood":      score.Likelihood,
			"impact":          score.Impact,
			"trend":           score.Trend,
			"recommendations": score.Recommendations,
		},
	}
	writeJSON(w, response)
}

func (s *Server) handleSurface(w http.ResponseWriter, r *http.Request) {
	result := scanSystem()
	surface := analyzeSurface(result.Findings)

	response := APIResponse{
		Success: true,
		Data:    surface,
	}
	writeJSON(w, response)
}

func analyzeSurface(findings []models.Finding) map[string]interface{} {
	surface := map[string]interface{}{
		"total_actions":          len(findings),
		"anonymously_accessible": 0,
		"wildcard_patterns":       0,
		"no_auth_required":       0,
		"network_exposed":        []interface{}{},
		"system_critical":        []interface{}{},
	}

	for _, f := range findings {
		if f.Rule != nil {
			if f.Rule.ResultAny == "yes" && (f.Rule.Identity == "unix-user:*" || f.Rule.Identity == "unix-group:all") {
				surface["anonymously_accessible"] = surface["anonymously_accessible"].(int) + 1
			}
		}
	}

	return surface
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	response := APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"version":    version,
			"build":      "production",
			"go_version": "1.21+",
		},
	}
	writeJSON(w, response)
}

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	templates := getTemplates()
	response := APIResponse{
		Success: true,
		Data:    templates,
	}
	writeJSON(w, response)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "POST required", 400)
		return
	}

	var req DiffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "Invalid JSON", 400)
		return
	}

	result := comparePolicies(req.OldRules, req.NewRules)

	response := APIResponse{
		Success: true,
		Data:    result,
	}
	writeJSON(w, response)
}

func (s *Server) handleRemediate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "POST required", 400)
		return
	}

	var findings []models.Finding
	if err := json.NewDecoder(r.Body).Decode(&findings); err != nil {
		writeError(w, "Invalid JSON", 400)
		return
	}

	plan := generateRemediationPlan(findings)

	response := APIResponse{
		Success: true,
		Data:    plan,
	}
	writeJSON(w, response)
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	return http.ListenAndServe(addr, s.mux)
}

func writeJSON(w http.ResponseWriter, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error:   msg,
	})
}

func scanSystem() models.ScanResult {
	sc := scanner.NewScanner(nil)
	d := detector.NewDetector()
	p := parser.NewParser()

	var allRules []models.PolkitRule
	for _, path := range sc.Paths {
		files, _ := sc.ScanDirectory(path)
		for _, file := range files {
			rules, _ := p.ParseFile(file)
			allRules = append(allRules, rules...)
		}
	}

	return d.DetectAll(allRules)
}

func runScan(path string) models.ScanResult {
	sc := scanner.NewScanner(nil)
	d := detector.NewDetector()
	p := parser.NewParser()

	var paths []string
	if path != "" {
		paths = strings.Split(path, ",")
	} else {
		paths = sc.Paths
	}

	var allRules []models.PolkitRule
	for _, scanPath := range paths {
		files, _ := sc.ScanDirectory(scanPath)
		for _, file := range files {
			rules, _ := p.ParseFile(file)
			allRules = append(allRules, rules...)
		}
	}

	return d.DetectAll(allRules)
}

func parseSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

type DiffRequest struct {
	OldRules []models.PolkitRule `json:"old_rules"`
	NewRules []models.PolkitRule `json:"new_rules"`
}

type DiffResponse struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Changed int `json:"changed"`
	Same    int `json:"same"`
}

func comparePolicies(oldRules, newRules []models.PolkitRule) DiffResponse {
	result := DiffResponse{}

	oldMap := make(map[string]models.PolkitRule)
	for _, r := range oldRules {
		oldMap[r.Action+r.Identity] = r
	}

	newMap := make(map[string]models.PolkitRule)
	for _, r := range newRules {
		newMap[r.Action+r.Identity] = r
	}

	for key, newR := range newMap {
		if oldR, exists := oldMap[key]; exists {
			if oldR.ResultAny != newR.ResultAny {
				result.Changed++
			} else {
				result.Same++
			}
		} else {
			result.Added++
		}
		_ = newR
	}

	for key := range oldMap {
		if _, exists := newMap[key]; !exists {
			result.Removed++
		}
	}

	return result
}

func getTemplates() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "Admin Only", "category": "System Administration", "severity": "HIGH",
			"description": "Restrict system administration to designated admins only"},
		{"name": "Service Management", "category": "Services", "severity": "HIGH",
			"description": "Control systemd service management permissions"},
		{"name": "Network Configuration", "category": "Network", "severity": "HIGH",
			"description": "Restrict network configuration changes"},
		{"name": "Package Management", "category": "Packages", "severity": "CRITICAL",
			"description": "Control package installation and removal"},
		{"name": "User Management", "category": "Users", "severity": "CRITICAL",
			"description": "Control user account modifications"},
	}
}

type RemediationPlan struct {
	Steps     []string `json:"steps"`
	Risk      string   `json:"risk"`
	Estimated string   `json:"estimated"`
}

func generateRemediationPlan(findings []models.Finding) RemediationPlan {
	plan := RemediationPlan{
		Steps:     []string{},
		Risk:      "MEDIUM",
		Estimated: "1 hour",
	}

	plan.Steps = append(plan.Steps, "Create backup of current polkit configuration")

	for _, f := range findings {
		if f.Rule != nil {
			plan.Steps = append(plan.Steps, fmt.Sprintf("Review: %s", f.Rule.Action))
		}
	}

	plan.Steps = append(plan.Steps, "Verify remediation with PolkitGuard scan")

	return plan
}