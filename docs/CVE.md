-- CVE Database for Polkit Security Issues
-- https://cve.mitre.org/

-- CRIT-001: Access without authentication
-- Related CVEs: CVE-2021-4034 (Policy Kit Privilege Escalation)

-- CRIT-002: unix-user:* wildcard (any user)
-- Related CVEs: CVE-2021-3560 (polkit privilege escalation)

-- HIGH-001: unix-group:all
-- All users get admin privileges

-- HIGH-003: org.freedesktop.* broad matches
-- Related CVEs: CVE-2022-44639, CVE-2023-23583

-- MEDIUM: Common polkit misconfigurations
-- Related CVEs: Various local privilege escalation

-- Sources:
-- https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=polkit
-- https://github.com/polkit-dev/polkit/security/advisories

-- Note: CVE database is updated periodically
-- Generate with: polkitguard --format json --output cve-report.json