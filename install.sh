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

# Preflight: verify pip can actually reach a Python package index.
# This catches the common cases where the script later fails with
# "No matching distribution found for reportlab":
#   - corporate proxy required (no HTTPS_PROXY set)
#   - TLS interception (Zscaler/Netskope) breaking pip's cert validation
#   - a custom internal index-url that doesn't mirror reportlab
echo "Preflight: checking that pip can reach a package index..."
preflight_log="$(mktemp -t falcon-preflight.XXXXXX)"
if ! python3 -m pip install --dry-run --quiet --disable-pip-version-check reportlab >"$preflight_log" 2>&1; then
    if grep -q -- '--dry-run' "$preflight_log" && grep -qi 'no such option' "$preflight_log"; then
        echo "Preflight skipped: pip is too old to support --dry-run (need >= 22.2). Continuing." >&2
        rm -f "$preflight_log"
    else
        echo "" >&2
        echo "Preflight failed: pip cannot install 'reportlab' from its configured index." >&2
        echo "----- pip output -----" >&2
        cat "$preflight_log" >&2
        echo "----------------------" >&2
        echo "" >&2
        echo "Diagnostics:" >&2
        echo "  pip version : $(python3 -m pip --version 2>&1)" >&2
        echo "  index-url   : $(python3 -m pip config get global.index-url 2>/dev/null || echo '(default: https://pypi.org/simple)')" >&2
        echo "  HTTPS_PROXY : ${HTTPS_PROXY:-${https_proxy:-<unset>}}" >&2
        echo "  HTTP_PROXY  : ${HTTP_PROXY:-${http_proxy:-<unset>}}" >&2
        if curl -fsSI --max-time 10 https://pypi.org/simple/reportlab/ >/dev/null 2>&1; then
            echo "  pypi.org reachable from curl : yes" >&2
            echo "  -> Network is OK; the problem is pip-side. Likely a custom index-url or a TLS-MITM proxy that pip does not trust." >&2
            echo "     Try one of:" >&2
            echo "       pip3 install --index-url https://pypi.org/simple --trusted-host pypi.org --trusted-host files.pythonhosted.org reportlab" >&2
            echo "       pip3 config set global.cert /path/to/corp-root-ca.pem" >&2
        else
            echo "  pypi.org reachable from curl : NO" >&2
            echo "  -> This machine cannot reach https://pypi.org/. Set a proxy and re-run:" >&2
            echo "       export HTTPS_PROXY=http://proxy.example.com:8080" >&2
            echo "       export HTTP_PROXY=\$HTTPS_PROXY" >&2
        fi
        rm -f "$preflight_log"
        exit 1
    fi
else
    rm -f "$preflight_log"
    echo "Preflight OK."
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
