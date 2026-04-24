#!/bin/bash
# PolkitGuard CI Gate Script
# Exit codes:
#   0 = No issues found
#   1 = LOW findings
#   2 = MEDIUM findings
#   3 = HIGH findings
#   4 = CRITICAL findings
#   5 = Scan error

set -e

# Configuration
POLKITGUARD_BIN="${POLKITGUARD_BIN:-polkitguard}"
MIN_SEVERITY="${MIN_SEVERITY:-low}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Running PolkitGuard CI Gate..."
echo "Minimum severity: $MIN_SEVERITY"
echo ""

# Run scan
OUTPUT=$($POLKITGUARD_BIN --severity "$MIN_SEVERITY" --format "$OUTPUT_FORMAT" --path "${POLKIT_SCAN_PATH:-/etc/polkit-1/localauthority/50-local.d}" 2>&1) || true
EXIT_CODE=$?

# Analyze results
case $EXIT_CODE in
    0)
        echo -e "${GREEN}✓ No security issues found${NC}"
        exit 0
        ;;
    1)
        echo -e "${YELLOW}⚠ LOW severity findings${NC}"
        echo "$OUTPUT"
        [ "$MIN_SEVERITY" = "low" ] && exit 0 || exit 1
        ;;
    2)
        echo -e "${YELLOW}⚠ MEDIUM severity findings${NC}"
        echo "$OUTPUT"
        [ "$MIN_SEVERITY" = "medium" ] && exit 0 || exit 2
        ;;
    3)
        echo -e "${RED}✗ HIGH severity findings${NC}"
        echo "$OUTPUT"
        [ "$MIN_SEVERITY" = "high" ] && exit 0 || exit 3
        ;;
    4)
        echo -e "${RED}✗ CRITICAL severity findings${NC}"
        echo "$OUTPUT"
        exit 4
        ;;
    *)
        echo -e "${RED}✗ Scan error${NC}"
        echo "$OUTPUT"
        exit 5
        ;;
esac