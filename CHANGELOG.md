# Changelog

All notable changes to PolkitGuard will be documented in this file.

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