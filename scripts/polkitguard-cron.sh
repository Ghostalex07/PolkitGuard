#!/bin/bash
#
# polkitguard-cron - Automated Polkit security scanning
# Run via: crontab -e
# Example: 0 2 * * * /path/to/polkitguard-cron >> /var/log/polkitguard.log 2>&1
#

set -e

LOG_FILE="${LOG_FILE:-/var/log/polkitguard.log}"
SCAN_PATH="${SCAN_PATH:-/etc/polkit-1:/usr/share/polkit-1}"
SEVERITY="${SEVERITY:-medium}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-json}"
WEBHOOK_URL="${WEBHOOK_URL:-}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting PolkitGuard scan..."

POLKITGUARD="${POLKITGUARD:-/usr/local/bin/polkitguard}"

if [ ! -x "$POLKITGUARD" ]; then
    log "ERROR: polkitguard not found at $POLKITGUARD"
    exit 1
fi

OUTPUT_FILE="/tmp/polkitguard-scan-$(date '+%Y%m%d-%H%M%S').json"

"$POLKITGUARD" \
    --path "$SCAN_PATH" \
    --severity "$SEVERITY" \
    --format "$OUTPUT_FORMAT" \
    --output "$OUTPUT_FILE" \
    --no-color

EXIT_CODE=$?

if [ $EXIT_CODE -ge 2 ]; then
    log "WARNING: Found issues (exit code: $EXIT_CODE)"
    
    if [ -n "$WEBHOOK_URL" ] && [ -f "$OUTPUT_FILE" ]; then
        log "Sending webhook notification..."
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d @"$OUTPUT_FILE" || log "Webhook failed"
    fi
else
    log "No issues found"
fi

log "Scan complete (output: $OUTPUT_FILE)"

exit $EXIT_CODE