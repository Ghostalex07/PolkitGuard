# PolkitGuard Security Policy Guide

## Overview

This guide provides recommended security policies for Polkit configurations based on best practices and compliance requirements.

## Security Levels

### Level 1: Basic (Development/Testing)
- Minimum severity: medium
- Focus on: Critical and High findings
- Review frequency: Monthly

### Level 2: Standard (Production)
- Minimum severity: low
- Focus on: All findings
- Review frequency: Weekly
- Automated scanning: Daily

### Level 3: High Security
- Minimum severity: low
- Focus on: All findings + recommendations
- Review frequency: Daily
- Automated scanning: Continuous (watch mode)

## Recommended Configurations

### Development Environment
```json
{
  "severity_filter": "medium",
  "output_format": "text",
  "ignore_paths": []
}
```

### Production Environment
```json
{
  "severity_filter": "low",
  "output_format": "json",
  "output": "/var/log/polkitguard/scan.json",
  "ignore_paths": ["/usr/share/polkit-1/actions/*.pkla"]
}
```

### Compliance Environment
```json
{
  "severity_filter": "low",
  "output_format": "sarif",
  "custom_paths": [
    "/etc/polkit-1",
    "/usr/share/polkit-1/rules.d"
  ],
  "webhook_url": "https://your-security-team.com/webhook"
}
```

## Action Recommendations

### Critical Actions (Require auth_admin_keep)
- systemd service management
- Network configuration
- User account management
- System reboot/shutdown

### High Actions (Require auth_admin)
- Package installation
- Device mounting
- Power management
- Hardware configuration

### Medium Actions (Require auth_any)
- Session management
- Display settings
- Printer access

### Low Actions (Informational)
- Read-only access
- Status queries
- Monitoring

## Polkit Rule Templates

### Admin-Only Access
```
[unix-group:wheel]
ResultAny=auth_admin_keep
Action=org.freedesktop.systemd1.*

[unix-group:sudo]
ResultAny=auth_admin_keep
Action=org.freedesktop.systemd1.*
```

### Specific User Access
```
[unix-user:admin]
ResultAny=auth_admin
Action=org.freedesktop.systemd1.manage-units

[unix-user:backup]
ResultAny=auth_admin
Action=org.freedesktop.systemd1.manage-services
```

### Service Account Access
```
[unix-user:monitoring]
ResultAny=auth_admin
Action=org.freedesktop.systemd1.get-unit-properties
Action=org.freedesktop.systemd1.list-units
```

## Compliance Standards

### CIS Benchmark Alignment
PolkitGuard maps to CIS Linux Benchmark:
- Ensure polkit is installed
- Verify default polkit actions
- Review admin group memberships

### PCI-DSS Requirements
- Restrict package management
- Control service modifications
- Monitor privileged access

### HIPAA Considerations
- Audit user access
- Track authentication changes
- Monitor system modifications

## Remediation Workflow

1. **Identify** - Run scan to find issues
2. **Assess** - Review severity and impact
3. **Plan** - Develop remediation plan
4. **Implement** - Apply fixes
5. **Verify** - Re-scan to confirm
6. **Document** - Update security policies

## Monitoring Recommendations

### Real-time Alerts
- Webhook to SIEM
- Email for critical issues
- Syslog for compliance

### Dashboards
- Grafana integration
- Prometheus metrics
- Custom HTML reports

## Audit Checklist

- [ ] Scan all polkit directories
- [ ] Review critical findings
- [ ] Verify admin group memberships
- [ ] Check for overly permissive rules
- [ ] Test authentication flow
- [ ] Document changes
- [ ] Update security policies

## Best Practices

1. **Least Privilege**
   - Grant minimum required permissions
   - Use specific users/groups
   - Avoid wildcards

2. **Defense in Depth**
   - Multiple authentication factors
   - Session timeouts
   - Regular audits

3. **Documentation**
   - Document all custom rules
   - Maintain change log
   - Version control policies

4. **Automation**
   - Scheduled scans
   - Automated reporting
   - Integration with CI/CD

## References

- [Polkit Documentation](https://www.freedesktop.org/wiki/Software/polkit/)
- [CIS Benchmarks](https://www.cisecurity.org/)
- [NIST Security Guidelines](https://csrc.nist.gov/)

---

**PolkitGuard v1.18.0** - Security scanning for Linux Polkit policies