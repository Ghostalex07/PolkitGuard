# PolkitGuard

**Practical security auditing for Linux privilege policies**

> Detect dangerous Polkit misconfigurations and turn them into clear, actionable security insights.

---

## Overview

**PolkitGuard** is an open-source security auditing tool that analyzes Polkit rules on Linux systems and identifies configurations that may lead to privilege escalation, unauthorized access, or misuse of system-level actions.

The goal is not to build an academic tool, but a practical, clear utility that allows administrators, security students, and security teams to quickly understand if a machine has dangerous rules.

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

## Architecture

```
polkitguard/
├── cmd/scan/main.go        # CLI entry point
├── internal/
│   ├── scanner/            # File system scanning
│   ├── parser/             # .rules file parsing
│   ├── detector/           # Pattern detection engine
│   └── report/             # Report generation
├── rules/                  # Detection rule definitions
├── testdata/               # Safe & vulnerable examples for testing
└── go.mod
```

### Core Components

#### Scanner
Locates Polkit rule files in standard Linux paths.

#### Parser
Parses `.rules` files and extracts:
- `identity` (unix-user, unix-group, etc.)
- `action` (the action being authorized)
- `result_any`, `result_active`, `result_inactive` (authorization result)

#### Detector
Pattern-based detection engine (extensible via interfaces):

| Severity | Pattern Example |
|----------|-----------------|
| CRITICAL | `result_any=yes` without authentication |
| CRITICAL | Access granted to `unix-user:*` (any user) |
| HIGH | Permissions to `unix-group:all` or broad groups |
| HIGH | Wildcard actions like `org.freedesktop.*` |
| MEDIUM | Ambiguous conditions |
| LOW | Redundant or poorly structured rules |

#### Reporter
Outputs findings in multiple formats:
- Text (default): human-readable output
- JSON (`--json`): structured output for automation

---

## Quick Start

```bash
# Build
go build -o polkitguard ./cmd/scan

# Run
./polkitguard scan
./polkitguard scan --json
./polkitguard scan --path /custom/rules/directory
./polkitguard scan --severity high
```

---

## Output Example

```
[CRITICAL] 10-storage.rules
→ Access granted without authentication
Impact: Any user may perform privileged actions
Recommendation: Require authentication for this action

[HIGH] 20-network.rules
→ Broad group permissions detected
Impact: Increased attack surface
Recommendation: Restrict to specific groups
```

---

## Installation

```bash
go install github.com/Ghostalex07/PolkitGuard@latest
```

Or clone and build:

```bash
git clone https://github.com/Ghostalex07/PolkitGuard.git
cd polkitguard
go build -o polkitguard ./cmd/scan
```

---

## What This Project Is

**Scope:**
- Focused scanner for Polkit (not full system auditing)
- Detects real misconfigurations with high confidence
- Lightweight, fast, and easy to use
- Extensible architecture for future growth

**Limitations:**
- Does NOT fully interpret all JavaScript logic
- Does NOT emulate the full Polkit engine
- Does NOT guarantee detection of all vulnerabilities

The focus is on **high-confidence, real-world security issues**.

---

## Target Users

- Linux system administrators
- Security engineers / Blue Teams
- Pentesters looking for privilege escalation vectors
- Advanced Linux users
- Cybersecurity students

---

## Testing Philosophy

PolkitGuard focuses on reliability:

- Real-world vulnerable configurations in `testdata/`
- Safe baseline configurations
- Edge cases
- Continuous improvement to reduce false positives

---

## Roadmap

### Phase 1: MVP
- Basic file scanning
- Critical issue detection
- Simple text output

### Phase 2: Expansion
- Extended detection patterns
- Improved severity classification

### Phase 3: Maturity
- JSON export
- Better reporting
- CI/CD integration

### Phase 4: Growth
- Integration with security tools
- Extended Linux security auditing

---

## Project Principles

- Clarity over complexity
- Practical detection over theoretical accuracy
- Minimal false positives
- Always explain the risk
- Build something useful, not perfect

---

## Contributing

Contributions are welcome:

- Add new detection rules
- Improve documentation
- Suggest improvements via issues

See `PROJECT_SPEC.md` for full project specifications.

---

## License

MIT License