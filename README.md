# PolkitGuard

[![CI Status](https://github.com/Ghostalex07/PolkitGuard/workflows/CI/badge.svg)](https://github.com/Ghostalex07/PolkitGuard/actions)
[![Go Version](https://img.shields.io/go.mod/go-version/Ghostalex07/PolkitGuard)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/Ghostalex07/PolkitGuard)](https://github.com/Ghostalex07/PolkitGuard/releases)

**Security auditing tool for Linux Polkit policies** - Detects dangerous configurations that can lead to privilege escalation.

---

## Quick Installation

### Option 1: From Source (Recommended)

```bash
git clone https://github.com/Ghostalex07/PolkitGuard.git
cd PolkitGuard
go build -o polkitguard ./cmd/scan

# Run
./polkitguard scan
```

### Option 2: With Go

```bash
go install github.com/Ghostalex07/PolkitGuard/cmd/scan@latest
polkitguard scan
```

### Option 3: Download Binary

Go to [Releases](https://github.com/Ghostalex07/PolkitGuard/releases) and download the binary for your platform.

---

## Usage

### Basic

```bash
./polkitguard scan                    # Scan system
./polkitguard --severity high        # Only CRITICAL and HIGH
./polkitguard --format json          # JSON output
./polkitguard --format html          # HTML output
```

### Options

| Flag | Description | Example |
|------|-------------|---------|
| `--path` | Directory to scan | `--path /etc/polkit` |
| `--severity` | Filter by severity | `--severity high` |
| `--format` | Output format | `--format json` |
| `-q` | Quiet mode | `-q` |
| `-v` | Verbose | `-v` |
| `-y` | Auto-confirm | `-y` |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues |
| 1 | Low |
| 2 | Medium |
| 3 | High |
| 4 | Critical |

```bash
# Example in CI/CD
./polkitguard -q
if [ $? -eq 4 ]; then
    echo "CRITICAL ISSUES FOUND!"
    exit 1
fi
```

---

## Install on System

```bash
# Build
go build -o polkitguard ./cmd/scan

# Install (as root)
sudo cp polkitguard /usr/local/bin/
sudo chmod 755 /usr/local/bin/polkitguard
```

Now you can run `polkitguard` from anywhere.

---

## What It Detects

### Critical
- Access without authentication
- unix-user:* (any user)

### High
- unix-group:all
- Actions with wildcards (*)
- org.freedesktop.* too broad

### Medium
- Ambiguous identity
- Redundant rules

### Low
- Inconsistent results
- Files without comments

---

## Project Structure

```
polkitguard/
├── cmd/scan/          # CLI entry point
├── internal/
│   ├── config/       # Configuration
│   ├── detector/     # Detection rules
│   ├── models/       # Data types
│   ├── parser/       # File parser
│   ├── report/       # Output (text, JSON, HTML, SARIF)
│   ├── scanner/      # File scanner
│   ├── watcher/      # Watch mode
│   └── cis/          # CIS Benchmarks
├── testdata/         # Test examples
├── Makefile          # Build commands
└── README.md
```

---

## For Developers

```bash
# Development
make build           # Build
make test            # Tests
make vet             # go vet
make fmt            # Format code

# Local install
make install        # go install
```

---

## Documentation

- [SECURITY.md](SECURITY.md) - Security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Code of conduct
- [CHANGELOG.md](CHANGELOG.md) - Change history

---

## License

MIT - See [LICENSE](LICENSE)