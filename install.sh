#!/usr/bin/env bash

set -euo pipefail

REPO_OWNER="c303s"
REPO_NAME="crowdstrike-falcon-tenant-report"
REPO_BRANCH="${REPO_BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-$(pwd -P)}"
SCRIPT_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/active_accounts.py"
SCRIPT_PATH="$INSTALL_DIR/active_accounts.py"

for cmd in curl python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd" >&2; exit 1; }
done

py_ok="$(python3 -c 'import sys; print("yes" if sys.version_info >= (3,10) else "no")')"
if [[ "$py_ok" != "yes" ]]; then
    echo "Python 3.10 or newer is required (found $(python3 -V 2>&1))." >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"
echo "Downloading active_accounts.py to $SCRIPT_PATH..."
curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"

echo "Launching active_accounts.py..."
exec python3 "$SCRIPT_PATH" </dev/tty
