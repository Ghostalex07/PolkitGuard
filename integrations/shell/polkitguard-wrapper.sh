#!/bin/bash

set -euo pipefail

POLKITGUARD="${POLKITGUARD:-polkitguard}"

show_usage() {
    cat << EOF
Usage: polkitguard-wrapper [OPTIONS]

Options:
    -p, --path PATH       Path to scan (comma-separated)
    -s, --severity LEVEL  Minimum severity: low, medium, high, critical (default: low)
    -f, --format FORMAT   Output format: text, json, html, sarif (default: text)
    -o, --output FILE     Output to file
    -c, --config FILE     Config file
    -y, --yes             Skip confirmation
    -q, --quiet           Quiet mode
    -v, --verbose         Verbose output
    -w, --watch           Watch mode
    -h, --help            Show this help
    -V, --version         Show version

Examples:
    polkitguard-wrapper -p /etc/polkit-1 -s high
    polkitguard-wrapper --path /etc/polkit-1 --format json --output results.json
    polkitguard-wrapper -s critical --watch
EOF
}

parse_args() {
    PATHS=""
    SEVERITY="low"
    FORMAT="text"
    OUTPUT=""
    CONFIG=""
    YES=false
    QUIET=false
    VERBOSE=false
    WATCH=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--path)
                PATHS="$2"
                shift 2
                ;;
            -s|--severity)
                SEVERITY="$2"
                shift 2
                ;;
            -f|--format)
                FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG="$2"
                shift 2
                ;;
            -y|--yes)
                YES=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -w|--watch)
                WATCH=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -V|--version)
                ${POLKITGUARD} --version
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

run_scan() {
    local cmd=("${POLKITGUARD}" "--format" "${FORMAT}" "--severity" "${SEVERITY}")

    if [[ -n "${PATHS}" ]]; then
        cmd+=("--path" "${PATHS}")
    fi

    if [[ -n "${CONFIG}" ]]; then
        cmd+=("--config" "${CONFIG}")
    fi

    if [[ "${YES}" == true ]]; then
        cmd+=("--yes")
    fi

    if [[ "${QUIET}" == true ]]; then
        cmd+=("-q")
    fi

    if [[ "${VERBOSE}" == true ]]; then
        cmd+=("-v")
    fi

    if [[ -n "${OUTPUT}" ]]; then
        "${cmd[@]}" > "${OUTPUT}"
    else
        "${cmd[@]}"
    fi
}

main() {
    parse_args "$@"

    if ! command -v "${POLKITGUARD}" &> /dev/null; then
        echo "Error: ${POLKITGUARD} not found in PATH"
        echo "Please install PolkitGuard first"
        exit 1
    fi

    if [[ "${WATCH}" == true ]]; then
        while true; do
            clear
            echo "PolkitGuard Watch Mode - Press Ctrl+C to stop"
            echo "============================================="
            echo ""
            run_scan
            echo ""
            echo "Next scan in 60 seconds..."
            sleep 60
        done
    else
        run_scan
    fi
}

main "$@"