#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: tests/lineending_test.sh
# Purpose: Every shipped file must use LF endings.
#
# Why this exists: the project is edited on Windows and executed on Linux. A file
# that picks up CRLF still passes a local Python syntax check, but on the server
# bash reports `$'\r': command not found` and refuses to run the script at all —
# including preflight.sh, the gate that is supposed to protect the host.
# Usage: bash tests/lineending_test.sh
# ==============================================================================

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BAD=0

while IFS= read -r file; do
    case "$file" in
        *__pycache__*|*/data/state/*|*/data/snapshot/*|*.gz) continue ;;
    esac
    if grep -qU $'\r' "$file" 2>/dev/null; then
        printf '[FAIL] CRLF found: %s\n' "${file#$REPO/}"
        BAD=$((BAD + 1))
    fi
done < <(find "$REPO" -type f \
            \( -name '*.sh' -o -name '*.py' -o -name '*.md' -o -name '*.conf' \
               -o -name '*.txt' -o -name 'logwall' -o -name 'VERSION' \))

if [ "$BAD" -eq 0 ]; then
    echo "[PASS] every shipped file uses LF endings"
    echo " RESULT: line endings are clean"
    exit 0
fi

echo " RESULT: ${BAD} file(s) contain CRLF — they will not run on Linux"
echo " FIX: sed -i 's/\r$//' <file>"
exit 1
