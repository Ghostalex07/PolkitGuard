# Changelog

All notable changes to PolkitGuard will be documented in this file.

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