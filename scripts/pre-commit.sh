#!/bin/bash
# Pre-commit hook for PolkitGuard
# Install: cp scripts/pre-commit.sh .git/hooks/pre-commit

POLKITGUARD_BIN="${POLKITGUARD_BIN:-polkitguard}"

echo "Running PolkitGuard pre-commit check..."

# Scan the files being committed
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "\.rules$" || true)

if [ -z "$FILES" ]; then
    echo "No Polkit rule files changed. Skipping scan."
    exit 0
fi

echo "Scanning changed Polkit rules..."

# Run scan on changed files
for file in $FILES; do
    if [ -f "$file" ]; then
        OUTPUT=$($POLKITGUARD_BIN --path "$file" --severity medium 2>&1) || true
        if echo "$OUTPUT" | grep -q "Critical:"; then
            echo "✗ CRITICAL security issue in $file"
            echo "$OUTPUT"
            exit 1
        elif echo "$OUTPUT" | grep -q "High:"; then
            echo "⚠ High security issue in $file"
            echo "$OUTPUT"
            exit 1
        fi
    fi
done

echo "✓ No critical security issues found"
exit 0