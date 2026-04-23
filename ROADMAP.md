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
- [x] CRIT-001: Access without authentication
- [x] CRIT-002: unix-user:*
- [x] CRIT-003: Service escalation
- [x] CRIT-004: Network dangerous
- [x] HIGH-001: unix-group:all
- [x] HIGH-002: Wildcard actions
- [x] HIGH-003: org.freedesktop.*
- [x] HIGH-004: Permissive session
- [x] MED-001: Ambiguous identity
- [x] MED-002: Redundant rules
- [x] MED-003: Contradictory rules
- [x] LOW-001: Inconsistent results
- [x] LOW-002: Poorly named
- [x] LOW-003: No comments

### Output & Reporting
- [x] JSON output
- [x] HTML report
- [x] Summary statistics
- [x] Exit codes

### Error Handling
- [x] Graceful handling
- [x] Permission warnings
- [x] Verbose mode

### Tests
- [x] Unit tests (parser, detector)
- [x] Integration tests

### Parser Improvements
- [x] Handle JavaScript expressions
- [x] Support `.pkla` format
- [x] Extract action ID from complex rules

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