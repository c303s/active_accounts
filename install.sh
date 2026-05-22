#!/usr/bin/env bash

set -euo pipefail

REPO_OWNER="c303s"
REPO_NAME="crowdstrike-falcon-tenant-report"
REPO_BRANCH="${REPO_BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-$(pwd -P)}"
SCRIPT_PATH="$INSTALL_DIR/active_accounts.py"

for cmd in curl python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd" >&2; exit 1; }
done

py_ok="$(python3 -c 'import sys; print("yes" if sys.version_info >= (3,10) else "no")')"
if [[ "$py_ok" != "yes" ]]; then
    echo "Python 3.10 or newer is required (found $(python3 -V 2>&1))." >&2
    exit 1
fi

# Resolve the latest commit SHA on the branch and download a SHA-pinned URL.
# raw.githubusercontent.com aggressively caches branch URLs; SHA URLs are immutable.
COMMIT_SHA="$(curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/commits/${REPO_BRANCH}" \
    | sed -n 's/.*"sha":[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' | head -n1)"

if [[ -z "$COMMIT_SHA" ]]; then
    echo "Could not resolve latest commit SHA for ${REPO_BRANCH}; falling back to branch URL." >&2
    SCRIPT_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/active_accounts.py"
else
    SCRIPT_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${COMMIT_SHA}/active_accounts.py"
fi

mkdir -p "$INSTALL_DIR"
echo "Downloading active_accounts.py to $SCRIPT_PATH..."
curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"

echo "Launching active_accounts.py..."
exec python3 "$SCRIPT_PATH" </dev/tty
