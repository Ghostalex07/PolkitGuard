# PolkitGuard

[![CI Status](https://github.com/Ghostalex07/PolkitGuard/workflows/CI/badge.svg)](https://github.com/Ghostalex07/PolkitGuard/actions)
[![Go Version](https://img.shields.io/go.mod/go-version/Ghostalex07/PolkitGuard)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Practical security auditing for Linux privilege policies**

> Detect dangerous Polkit misconfigurations and turn them into clear, actionable security insights.

---

## Overview

**PolkitGuard** is an open-source security auditing tool that analyzes Polkit rules on Linux systems and identifies configurations that may lead to privilege escalation, unauthorized access, or misuse of system-level actions.

The goal is not to build an academic tool, but a practical, clear utility that allows administrators, security students, and security teams to quickly understand if a machine has dangerous rules.

---

## Quick Start

```bash
# Install
go install github.com/Ghostalex07/PolkitGuard@latest

# Run
polkitguard scan
polkitguard scan --path /etc/polkit
polkitguard scan --severity high
polkitguard scan --format json
polkitguard scan --format html
polkitguard scan --format sarif
```

---

## How It Works

```
Scanner (find .rules files) → Parser (extract rules) → Detector (find risky patterns) → Reporter (output findings)
```

1. **Scan**: Finds Polkit rule files in standard locations (`/usr/share/polkit-1/rules.d/`, `/etc/polkit/`)
2. **Parse**: Extracts rule components (`identity`, `action`, `result_*`)
3. **Detect**: Applies detection patterns to identify security issues
4. **Report**: Generates human-readable output with severity classification

---

## Features

- **14 Detection Rules** - Comprehensive security pattern detection
- **Multiple Output Formats** - Text, JSON, HTML, SARIF
- **Severity-based Filtering** - Filter by CRITICAL, HIGH, MEDIUM, LOW
- **Exit Codes** - Integrate with CI/CD pipelines
- **Quiet Mode** - Suppress banner for automation
- **Cross-Platform** - Linux, Windows, macOS

---

## Installation

### From Source

```bash
git clone https://github.com/Ghostalex07/PolkitGuard.git
cd PolkitGuard
go build -o polkitguard ./cmd/scan
./polkitguard --help
```

### Using Go Install

```bash
go install github.com/Ghostalex07/PolkitGuard@latest
```

---

## Output Example

```
=== PolkitGuard Security Scan Results ===

Files scanned: 3
Rules analyzed: 5
Total issues: 2
-----------------------------------
  Critical: 1
  High:     1
  Medium:   0
  Low:      0

[CRITICAL] /etc/polkit/rules.d/50-local.rules
  → Access granted without authentication
  Impact: Any user may perform privileged actions
  Recommendation: Require authentication for this action

[HIGH] /usr/share/polkit/rules.d/10-network.rules
  → Permissions granted to unix-group:all
  Impact: All users in the system inherit these privileges
  Recommendation: Restrict to specific groups
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Low severity issues found |
| 2 | Medium severity issues found |
| 3 | High severity issues found |
| 4 | Critical severity issues found |

---

## Architecture

```
polkitguard/
├── cmd/scan/main.go        # CLI entry point
├── internal/
│   ├── models/             # Core data types
│   ├── parser/            # .rules file parsing
│   ├── scanner/           # File system scanning
│   ├── detector/          # Pattern detection engine
│   └── report/            # Output formatting (text, JSON, HTML, SARIF)
├── .github/workflows/      # CI/CD
├── testdata/             # Test examples
├── CONTRIBUTING.md       # Contribution guide
├── CODE_OF_CONDUCT.md    # Community code of conduct
├── SECURITY.md          # Security policy
└── CHANGELOG.md         # Version history
```

---

## Detection Rules

| ID | Severity | Description |
|----|----------|-------------|
| CRIT-001 | CRITICAL | Access without authentication |
| CRIT-002 | CRITICAL | unix-user:* (any user) |
| CRIT-003 | CRITICAL | Service escalation patterns |
| CRIT-004 | CRITICAL | Network dangerous actions |
| HIGH-001 | HIGH | unix-group:all permissions |
| HIGH-002 | HIGH | Wildcard action patterns |
| HIGH-003 | HIGH | org.freedesktop.* broad matches |
| HIGH-004 | HIGH | Permissive session check |
| MED-001 | MEDIUM | Ambiguous identity |
| MED-002 | MEDIUM | Redundant rules |
| MED-003 | MEDIUM | Contradictory rules |
| LOW-001 | LOW | Inconsistent results |
| LOW-002 | LOW | Poorly named files |
| LOW-003 | LOW | No comments |

---

## Installation

### From Source (All Linux)

```bash
git clone https://github.com/Ghostalex07/PolkitGuard.git
cd PolkitGuard
make build
sudo install -m 755 polkitguard /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/Ghostalex07/PolkitGuard@latest
```

### Arch Linux (AUR)

```bash
yay -S polkitguard
```

### Debian/Ubuntu

```bash
# Coming soon - DEB package
```

---

## Usage Examples

### Basic Scan

```bash
polkitguard scan
```

### Scan Custom Directory

```bash
polkitguard --path /etc/polkit/rules.d
```

### High Severity Only

```bash
polkitguard --severity high
```

### JSON Output for Automation

```bash
polkitguard --format json > results.json
```

### HTML Report

```bash
polkitguard --format html > report.html
```

### SARIF for SIEM/Tool Integration

```bash
polkitguard --format sarif
```

### Quiet Mode (CI/CD)

```bash
polkitguard -q && echo "Issues found" || echo "Clean"
```

### Check Exit Codes

```bash
polkitguard scan
echo $?
# 0 = Clean, 1 = Low, 2 = Medium, 3 = High, 4 = Critical
```

---

## Use Cases

### For System Administrators

- Audit your Linux systems for polkit vulnerabilities
- Part of hardening process
- Regular security checks

### For Blue Team

- Detect privilege escalation vectors
- Incident response documentation
- Compliance audits

### For Pentesters

- Identify escalation opportunities
- Document findings for reports

### For Students

- Learn about Linux security
- Practice security auditing

---

## Who Should Use This

- Linux system administrators
- Security engineers / Blue Teams
- Pentesters
- DevOps engineers
- Security students
- Anyone hardening Linux systems

---

## Why Polkit?

Polkit is the standard authorization framework in modern Linux. Misconfigurations can allow any user to:
- Execute privileged commands without password
- Access sensitive system functions
- Escalate privileges to root

PolkitGuard helps detect these issues before attackers.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Security

For security issues, please see [SECURITY.md](SECURITY.md).