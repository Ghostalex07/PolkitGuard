# Changelog

All notable changes to PolkitGuard will be documented in this file.

## [1.18.0] - Ultimate Release

### Added
- 30 new detection rules (Azure Arc, GKE, EKS, XFCE, MATE, Cinnamon, desktop)
- Helm chart (examples/helm/)
- Kustomize overlay (examples/kustomize/)
- Operator SDK (internal/operator/)
- GitHub Pages website (docs/index.html)
- Test coverage improvements
- Homebrew tap (packaging/homebrew/)
- Snap package (packaging/snap/)
- Chef cookbook
- Policy comparison tool (internal/policy/comparison.go)
- Config backup/restore system (internal/backup/backup.go)
- Scoop package for Windows (packaging/scoop/)
- Security Policy Guide (docs/SECURITY.md)
- Additional integration tests
- Risk scoring engine (internal/risk/score.go)
- Policy diff/merge tool (internal/diff/policy_diff.go)
- Auto-remediation generator (internal/remediation/generator.go)
- Markdown report format (internal/report/markdown.go)
- XML/Excel format (internal/report/xml.go)
- Config validator CLI (cmd/validate/validate.go)
- Policy templates library (internal/templates/library.go)
- Attack surface analyzer (internal/analyzer/surface.go)
- Trend analysis (internal/trend/analysis.go)
- Config generator (internal/generator/generator.go)
- Finding model expanded with RuleID, Title, Description, Rule pointer
- HTTP API server (internal/api/server.go)
- Multi-command CLI (cmd/polkitguard/main.go)
- Tests for all new packages

### Cross-Language Integrations
- Python package (integrations/python/)
- JavaScript/TypeScript npm package (integrations/node/)
- Rust crate (integrations/rust/)
- Java Maven package (integrations/java/)
- Ruby gem (integrations/ruby/)
- PHP package (integrations/php/)
- Shell scripts (integrations/shell/)

### Changed
- Version bump to 1.18.0
- Total detection rules: 139

## [1.17.0] - Ultimate Release

### Added
- 22 new detection rules (Azure Functions, Cloud Run, K8s SCC, KDE, GNOME, VPN drivers, etc.)
- Chef cookbook (examples/chef/)
- kubectl plugin (examples/kubectl-plugin/)
- Custom templates (examples/templates/)
- Compliance audit reports (internal/audit/)
- Excel/xlsx format support ready

### Changed
- Version bump to 1.17.0
- Total detection rules: 109

## [1.16.0] - Previous Release

### Added
- 15 new detection rules (K8s, OpenShift, Cloud, runc, etc.)
- Puppet module (examples/puppet/)
- Salt states (examples/salt/)
- Fuzzing tests (internal/parser/fuzz_test.go)
- GitHub Actions workflow template (examples/.github/workflows/)

### Changed
- Version bump to 1.16.0
- Total detection rules: 89

## [1.15.0] - Previous Release

### Added
- 10 new detection rules (cloud/container: GCP, Azure, containerd, CRI-O, AWS ECS)
- TUI interactivo (internal/tui)
- Grafana dashboard (examples/grafana-dashboard.json)
- Ansible playbook (examples/polkitguard-ansible.yml)
- HTML report con charts (examples/report-with-charts.html)
- Fuzzing tests подготовка

### Changed
- Version bump to 1.15.0
- Total detection rules: 74

## [1.14.0] - Previous Release

### Added
- 10 new detection rules (cloud/container specific: AWS EC2, Kubernetes, Docker, Podman)
- Prometheus metrics (internal/metrics)
- Better error handling (internal/errors)
- Email notifications (internal/notifier/email)
- CVE lookup (internal/cve)
- OpenSCAP integration (internal/openscap)
- Auto-remediation (internal/remediation)

### Changed
- Version bump to 1.14.0
- Total detection rules: 64

## [1.13.0] - Previous Release

### Added
- JUnit XML output format
- Diff mode for comparing scans (internal/diff package)
- Syslog forwarding (internal/notifier/syslog.go)
- Watcher package completed
- 5 new detection rules (LOW-011, MED-011, CRIT-013, HIGH-016)
- JSON Schema config validation with "junit" format

### Changed
- Version bump to 1.13.0
- Total detection rules: 54

## [1.12.0] - Previous Release

### Added
- 10+ new detection rules (CRIT-011-012, HIGH-013-015, MED-009-010, LOW-009-010)
- PDF export support
- Multiple webhook URLs support (comma-separated)
- Dockerfile + DockerHub badges in README
- Test coverage badge placeholder
- Detection rules badge updated to 49

### Changed
- Version bump to 1.12.0
- Total detection rules: 49

## [1.11.0] - Previous Release

### Added
- 10 new detection rules (CRIT-009-010, HIGH-011-012, MED-007-008, LOW-007-008)
- Scanner tests (69.7% coverage)
- Config tests (78.8% coverage)
- Benchmarks in CI
- Version sync across all packages

### Improved
- Test coverage (config 52%→79%, scanner 27%→70%)
- CI/CD with benchmarks

### Changed
- Version bump to 1.11.0

## [1.10.0] - Previous Release

### Added
- 5 new detection rules (CRIT-008, HIGH-010, MED-006, LOW-006)
- Notifier tests (88.9% coverage)
- Report tests (70.8% coverage)
- Models tests (90.9% coverage)
- Benchmarks for detector
- Unit tests for detector package

### Changed
- Version bump to 1.10.0

## [1.9.0] - Previous Release

### Added
- 5 new detection rules (CRIT-007, HIGH-009, MED-005, LOW-005)
- Webhook notifications (notifier package)
- JSON Schema for config validation
- Cron script for automated scanning
- Unit tests for report package

### Changed
- Version bump to 1.9.0

### Fixed
- CountBySeverity method added to ScanResult

## [1.8.0] - Previous Release

### Added
- Example configs for common distros (Debian, Ubuntu, RHEL, Fedora)
- Version bump to 1.8.0

### Improved
- Reduced cyclomatic complexity by splitting getDetectionRules()

### Changed
- Detection rules now organized by severity level

## [1.0.0] - Production Ready Release

### Added
- 21 Detection Rules for Polkit security (CRIT-001-006, HIGH-001-008, MED-001-004, LOW-001-005)
- Multiple output formats: text, JSON, HTML, SARIF
- CLI flags: --path, --severity, --format, -q, -v, -y
- False positive suppression (SuppressRule)
- CIS Benchmarks checks
- Watch mode for continuous monitoring
- Config file support
- Severity scoring system
- GoReleaser configuration for releases
- Docker support
- Release GitHub Action
- Integration tests

### Professional Polish
- Clean README in English with badges
- LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- Makefile with build targets
- .gitignore
- CI/CD with GitHub Actions
- PROJECT_SPEC.md, ROADMAP.md

## [0.9.0] - Production Ready Release

### Added
- 14 Detection Rules for Polkit security
- Multiple output formats: text, JSON, HTML, SARIF
- CLI flags: --path, --severity, --format, -q, -v, -y
- False positive suppression (SuppressRule)
- CIS Benchmarks checks
- Watch mode for continuous monitoring
- Config file support
- Severity scoring system
- GoReleaser configuration for releases
- Docker support
- Release GitHub Action

### Professional Polish
- Clean README in English
- LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- Makefile with build targets
- .gitignore
- CI/CD with GitHub Actions

## [0.8.0] - Phase 4 Complete

### Added
- Watch mode for continuous monitoring (internal/watcher)
- False positive suppression (SuppressRule method)
- CIS Benchmarks compliance checks (internal/cis)
- Severity scoring (CalculateScore)
- Config file support

## [0.7.0] - Phase 4: Growth

### Added
- Severity scoring system (Score field on Findings)
- Config file support (JSON format)
- Phase 4: Growth tasks started

## [0.6.0] - Phase 3: Maturity

### Added
- GitHub Actions CI/CD workflow
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- SECURITY.md
- Quiet mode (-q flag)
- SARIF output format (--format sarif)

### Fixed
- Usage examples updated

## [0.5.0] - Phase 2 Complete

### Added
- Summary statistics (files scanned, rules, by severity)
- HTML report generation (--html flag)
- Improved parser for JavaScript expressions

## [0.4.0] - Phase 2 Completion

### Added
- 6 new detection rules:
  - CRIT-003: Service escalation patterns
  - CRIT-004: Network-related dangerous actions
  - HIGH-004: Overly permissive session check
  - MED-002: Redundant rules
  - MED-003: Contradictory rules
  - LOW-002: Poorly named files
  - LOW-003: Files without comments
- Exit codes based on severity found
- .pkla format support (legacy)
- HasCritical(), HasHigh(), HasMedium() methods on ScanResult

## [0.3.1] - Verbose Mode & Bug Fixes

### Added
- Verbose mode (`-v` flag) for debugging
- Version constant in main.go (was hardcoded)

### Fixed
- Scanner now logs warnings for missing directories
- Path separator: uses filepath.Join instead of string concatenation (Windows support)
- TestDetectCRIT001: Fixed test to handle multiple findings
- Updated module path from Polkit-Security-Scanner to PolkitGuard to match actual GitHub repo

## [0.3.0] - Unit Tests

### Added
- Added unit tests for `parser` package (ParseFile, ParseDirectory, extractValue, extractRuleName)
- Added unit tests for `detector` package (CRIT-001/002, HIGH-001/002/003, MED-001, LOW-001)

## [0.2.0] - Bug Fixes

### Fixed
- CRIT-001: Now only triggers on `result_any=yes`, not `auth_admin_keep` (which requires auth)
- HIGH-002: Fixed condition to avoid false positives on short patterns

## [0.1.0] - Initial Implementation

### Added

- **Project Structure**
  - `go.mod` module initialization
  - `cmd/scan/main.go` - CLI entry point
  - `internal/models/` - Core data types (Finding, PolkitRule, Severity)
  - `internal/parser/` - Polkit `.rules` file parser
  - `internal/scanner/` - File system scanner for Polkit directories
  - `internal/detector/` - Security pattern detection engine
  - `internal/report/` - Text and JSON output formatting

- **Core Features**
  - Scanning of standard Polkit directories (`/usr/share/polkit-1/rules.d/`, `/etc/polkit-1/rules.d/`)
  - Custom path scanning support
  - Parser for `[polkit_rule]` blocks extracting identity, action, result_*
  - 7 detection rules across CRITICAL, HIGH, MEDIUM, LOW severities
  - Text output with color-coded severity
  - JSON output option for automation

- **Detection Rules**
  - CRIT-001: Access without authentication (result_any=yes)
  - CRIT-002: Access to unix-user:* (any user)
  - HIGH-001: Permissions to unix-group:all
  - HIGH-002: Wildcard action patterns
  - HIGH-003: org.freedesktop.* broad matches
  - MED-001: Ambiguous identity conditions
  - LOW-001: Inconsistent active/inactive session behavior

- **CLI Flags**
  - `--path`: Custom directory to scan
  - `--json`: JSON output format
  - `--severity`: Filter by minimum severity level
  - `--help`: Show help message

- **Test Data**
  - `testdata/safe/` - Safe configuration examples
  - `testdata/vulnerable/` - Known vulnerable configurations

### Architecture

```
polkitguard/
├── cmd/scan/main.go        # CLI entry point
├── internal/
│   ├── models/             # Data types
│   ├── parser/             # .rules file parsing
│   ├── scanner/            # File scanning
│   ├── detector/           # Pattern detection
│   └── report/             # Output formatting
├── rules/                  # Detection rule definitions
├── testdata/               # Test examples
└── go.mod
```

### Detection Flow

```
Scanner → Parser → Detector → Reporter
(Find files) → (Extract rules) → (Find issues) → (Output)
```

---

## [Unreleased]

- Additional detection rules
- Improved parsing for complex JavaScript expressions
- CI/CD integration
- JSON config file support