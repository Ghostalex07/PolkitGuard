#!/bin/bash

set -euo pipefail

setup_cron() {
    local schedule="${1:-0 2 * * *}"
    local script_path="${2:-/usr/local/bin/polkitguard-scheduled.sh}"
    local cron_user="${3:-$USER}"

    echo "Setting up cron job for PolkitGuard"
    echo "Schedule: ${schedule}"
    echo "Script: ${script_path}"
    echo "User: ${cron_user}"
    echo ""

    if ! command -v crontab &> /dev/null; then
        echo "Error: crontab not found"
        exit 1
    fi

    local cron_entry="${schedule} ${script_path} >> /var/log/polkitguard-cron.log 2>&1"

    (crontab -l 2>/dev/null || true) | grep -v "polkitguard-scheduled" | { echo "${cron_entry}"; } | crontab -

    echo "Cron job installed successfully!"
    echo ""
    echo "Current crontab:"
    crontab -l 2>/dev/null || echo "(empty)"
}

remove_cron() {
    echo "Removing PolkitGuard cron job..."
    crontab -l 2>/dev/null | grep -v "polkitguard-scheduled" | crontab - 2>/dev/null || true
    echo "Cron job removed!"
}

case "${1:-setup}" in
    setup)
        setup_cron "${2:-0 2 * * *}" "${3:-/usr/local/bin/polkitguard-scheduled.sh}" "${4:-$USER}"
        ;;
    remove)
        remove_cron
        ;;
    list)
        echo "Current PolkitGuard cron jobs:"
        crontab -l 2>/dev/null | grep "polkitguard" || echo "(none)"
        ;;
    *)
        echo "Usage: $0 {setup|remove|list} [schedule] [script-path] [user]"
        echo ""
        echo "Examples:"
        echo "  $0 setup '0 2 * * *' /usr/local/bin/scan.sh root"
        echo "  $0 setup                                          # Daily at 2am"
        echo "  $0 setup '*/15 * * * *'                            # Every 15 minutes"
        echo "  $0 list"
        echo "  $0 remove"
        exit 1
        ;;
esac