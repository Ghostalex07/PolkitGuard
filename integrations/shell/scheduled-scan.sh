#!/bin/bash

set -euo pipefail

REPORT_DIR="${REPORT_DIR:-/var/log/polkitguard}"
ARCHIVE_DIR="${REPORT_DIR}/archive"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "${REPORT_DIR}/archive"

echo "Running scheduled PolkitGuard scan..."
echo "Report directory: ${REPORT_DIR}"
echo "Timestamp: ${TIMESTAMP}"
echo ""

run_scan() {
    local severity="${1:-high}"
    local output="${REPORT_DIR}/scan_${TIMESTAMP}_${severity}.json"

    echo "Scanning with severity: ${severity}"

    if command -v polkitguard &> /dev/null; then
        polkitguard --path /etc/polkit-1 --severity "${severity}" --format json --output "${output}" 2>/dev/null || true
    else
        echo "Warning: polkitguard not found in PATH"
        return 1
    fi

    if [[ -f "${output}" ]]; then
        local count=$(grep -c '"Severity"' "${output}" 2>/dev/null || echo "0")
        echo "  Found ${count} findings"

        if [[ ${count} -gt 0 ]]; then
            echo "  Results saved to: ${output}"
        fi
    fi

    return 0
}

run_scan "critical"
run_scan "high"

echo ""
echo "Generating HTML report..."
html_report="${REPORT_DIR}/report_${TIMESTAMP}.html"
cat > "${html_report}" << 'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>PolkitGuard Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4a90d9; color: white; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #17a2b8; }
    </style>
</head>
<body>
    <h1>PolkitGuard Security Scan Report</h1>
HTML_EOF

echo "    <p>Generated: ${TIMESTAMP}</p>" >> "${html_report}"
echo "    <p>Directory: /etc/polkit-1</p>" >> "${html_report}"
echo "    <h2>Summary</h2>" >> "${html_report}"
echo "    <ul>" >> "${html_report}"
echo "    <li>Critical findings: ${critical_count:-0}</li>" >> "${html_report}"
echo "    <li>High findings: ${high_count:-0}</li>" >> "${html_report}"
echo "    <li>Report location: ${REPORT_DIR}</li>" >> "${html_report}"
echo "    </ul>" >> "${html_report}"
echo "</body></html>" >> "${html_report}"

echo "HTML report: ${html_report}"

echo ""
echo "Cleaning old reports (keeping last 30 days)..."
find "${REPORT_DIR}" -name "*.json" -mtime +30 -delete 2>/dev/null || true
find "${REPORT_DIR}" -name "*.html" -mtime +30 -delete 2>/dev/null || true

echo ""
echo "Scheduled scan complete!"
echo "Reports saved to: ${REPORT_DIR}"