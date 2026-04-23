# Security Policy

## Supported Versions

| Version | Supported          |
|--------|-------------------|
| 0.5.x  | ✅                 |
| 0.4.x  | ✅                 |
| < 0.4  | ❌                 |

## Reporting a Vulnerability

If you discover a security vulnerability within PolkitGuard, please send an email to the maintainer.

**Do NOT report security vulnerabilities through public GitHub issues.**

Please include the following information:

1. Type of vulnerability
2. Full path of the file(s) affected
3. Location of the vulnerability (line number, function, etc.)
4. How you would reproduce the issue
5. Any potential fixes or suggestions (if any)

We aim to acknowledge reports within 48 hours and provide a timeline for resolution.

## Scope

PolkitGuard is a security auditing tool. We take security seriously:

- We will never exfiltrate data
- We only read Polkit rule files
- No network connections are made
- No credentials are required or stored

## Security Best Practices for Users

When using PolkitGuard:

1. Run with minimal required permissions
2. Review findings before taking action
3. Do not modify rules without understanding the impact
4. Test in a non-production environment first
5. Keep PolkitGuard updated

## Attribution

Thank you for helping keep PolkitGuard secure!