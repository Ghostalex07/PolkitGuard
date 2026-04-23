# PolkitGuard Roadmap

## Project Phases Checklist

---

## Phase 1: MVP ✅

### Core Infrastructure
- [x] `go.mod` module initialization
- [x] Project structure (`cmd/`, `internal/`, `testdata/`)
- [x] `internal/models/` - Core types (Finding, PolkitRule, Severity)
- [x] `internal/parser/` - Basic .rules file parsing
- [x] `internal/scanner/` - File system scanning
- [x] `internal/report/` - Text output
- [x] `cmd/scan/main.go` - CLI entry point

### Detection Rules
- [x] CRIT-001: Access without authentication
- [x] CRIT-002: Access to unix-user:*
- [x] HIGH-001: unix-group:all permissions
- [x] HIGH-002: Wildcard action patterns
- [x] HIGH-003: org.freedesktop.* broad matches
- [x] MED-001: Ambiguous identity conditions
- [x] LOW-001: Inconsistent active/inactive behavior

### CLI & Output
- [x] `--path` flag for custom directories
- [x] `--json` flag for JSON output
- [x] `--severity` flag for filtering
- [x] Color-coded text output

### Documentation
- [x] README.md with architecture
- [x] PROJECT_SPEC.md with full specifications
- [x] CHANGELOG.md for tracking changes
- [x] Test data examples (safe & vulnerable)

### Bug Fixes
- [x] Fixed CRIT-001 false positive (auth_admin_keep)
- [x] Fixed HIGH-002 condition logic

---

## Phase 2: Expansion

### Parser Improvements
- [ ] Handle JavaScript expressions (return polkit.identity()...)
- [x] Support `.pkla` format (legacy)
- [ ] Extract action ID from complex rules

### Detection Rules
- [ ] Add CRIT-003: Service escalation patterns
- [ ] Add CRIT-004: Network-related dangerous actions
- [ ] Add HIGH-004: Overly permissive session checks
- [ ] Add MED-002: Redundant rules
- [ ] Add MED-003: Contradictory rules
- [ ] Add LOW-002: Poorly named files
- [ ] Add LOW-003: Files without comments

### Output & Reporting
- [x] JSON output for machine parsing
- [ ] HTML report generation
- [ ] Summary statistics (total files, rules, by severity)
- [x] Exit codes based on severity found

### Error Handling
- [x] Graceful handling of unreadable files
- [x] Permission denied warnings
- [x] Verbose mode (`-v`)

### Tests
- [x] Unit tests for parser
- [x] Unit tests for detector
- [x] Integration tests with testdata

### Detection Rules
- [x] Add CRIT-003: Service escalation patterns
- [x] Add CRIT-004: Network-related dangerous actions
- [x] Add HIGH-004: Overly permissive session checks
- [x] Add MED-002: Redundant rules
- [x] Add MED-003: Contradictory rules
- [x] Add LOW-002: Poorly named files
- [x] Add LOW-003: Files without comments

---

## Phase 3: Maturity

### CI/CD
- [ ] GitHub Actions workflow
- [ ] Auto-build on push
- [ ] Test runner in CI
- [ ] Release automation

### Distribution
- [ ] Binary releases (Linux amd64, arm64)
- [ ] Package for AUR (Arch Linux)
- [ ] Package for DEB/RPM (Debian/RedHat)

### Documentation
- [ ] CONTRIBUTING.md
- [ ] CODE_OF_CONDUCT.md
- [ ] SECURITY.md (security contact)
- [ ] User guide / manual pages
- [ ] Examples of real vulnerable configurations

### UX Improvements
- [ ] Interactive mode
- [ ] Config file support (JSON/YAML)
- [ ] Multiple output formats (JSON, SARIF, HTML)
- [ ] Quiet mode (`-q`)

---

## Phase 4: Growth

### Advanced Features
- [ ] Daemon mode for continuous monitoring
- [ ] Integration with systemd-journal
- [ ] Watch mode (inotify)

### Integrations
- [ ] CIS Benchmarks compliance check
- [ ] Integration with Lynis
- [ ] Integration with OpenSCAP

### Advanced Detection
- [ ] Severity scoring system
- [ ] False positive suppression
- [ ] Learning mode from user feedback

### Community
- [ ] Rule contributions from community
- [ ] Community rules database
- [ ] Public issue tracker

---

## Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Detection rules | 7 | 30+ |
| Test coverage | 0% | 80%+ |
| Supported formats | .rules | .rules, .pkla, .d |
| Output formats | text | text, json, html, sarif |

---

## Completed Milestones

- [x] **v0.1.0** - Initial implementation (14 files)
- [x] **v0.2.0** - Bug fixes

## Next Release

### v0.3.0 - Parser Improvements
- [ ] JavaScript expression parsing
- [ ] Unit tests
- [ ] Better error messages