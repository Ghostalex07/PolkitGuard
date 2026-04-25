# Python Package for PolkitGuard

Security scanner for Linux Polkit policies - Python package

## Installation

```bash
pip install polkitguard
```

## Usage

```python
from polkitguard import scan

# Quick scan
result = scan()
print(f"Found {len(result.findings)} findings")

# Scan specific path
result = scan(path="/etc/polkit-1", severity="high")

# Detailed scan
from polkitguard import PolkitGuard

guard = PolkitGuard()
result = guard.scan(path="/etc/polkit-1", severity="critical")

for finding in result.findings:
    print(f"{finding.severity.name}: {finding.title}")

# Get risk score
risk = guard.get_risk_score(result.findings)
print(f"Risk: {risk['score']:.1f} ({risk['level']})")
```

## CLI

```bash
polkitguard --path /etc/polkit-1 --severity high
```

## License

MIT