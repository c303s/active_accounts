#!/usr/bin/env bash

set -euo pipefail

REPO_OWNER="c303s"
REPO_NAME="crowdstrike-falcon-tenant-report"
REPO_BRANCH="${REPO_BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.crowdstrike-falcon-tenant-report}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
WRAPPER_PATH="$BIN_DIR/crowdstrike-falcon-tenant-report"
ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"
DEFAULT_BASE_URL="https://api.eu-1.crowdstrike.com"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

prompt_value() {
    local prompt_text="$1"
    local secret="${2:-false}"
    local value=""

    while [[ -z "$value" ]]; do
        if [[ "$secret" == "true" ]]; then
            read -r -s -p "$prompt_text: " value
            echo
        else
            read -r -p "$prompt_text: " value
        fi
    done

    printf '%s' "$value"
}

require_command curl
require_command tar
require_command python3

tmp_dir="$(mktemp -d)"
existing_env=""
trap 'rm -rf "$tmp_dir"' EXIT

if [[ -f "$INSTALL_DIR/.env" ]]; then
    existing_env="$tmp_dir/.env"
    cp "$INSTALL_DIR/.env" "$existing_env"
fi

rm -rf "$INSTALL_DIR"
mkdir -p "$(dirname "$INSTALL_DIR")"

echo "Downloading ${REPO_NAME}..."
curl -fsSL "$ARCHIVE_URL" | tar -xzf - -C "$tmp_dir"
mv "$tmp_dir/${REPO_NAME}-${REPO_BRANCH}" "$INSTALL_DIR"

if [[ -n "$existing_env" ]]; then
    mv "$existing_env" "$INSTALL_DIR/.env"
fi

echo "Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/.venv"

echo "Installing dependencies..."
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    client_id="$(prompt_value "Enter FALCON_CLIENT_ID")"
    client_secret="$(prompt_value "Enter FALCON_CLIENT_SECRET" true)"

    umask 077
    cat > "$INSTALL_DIR/.env" <<EOF
FALCON_CLIENT_ID=${client_id}
FALCON_CLIENT_SECRET=${client_secret}
FALCON_BASE_URL=${DEFAULT_BASE_URL}
EOF
    chmod 600 "$INSTALL_DIR/.env"
fi

mkdir -p "$BIN_DIR"
cat > "$WRAPPER_PATH" <<EOF
#!/usr/bin/env bash
exec "$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/active_accounts.py" "\$@"
EOF
chmod +x "$WRAPPER_PATH"

echo
echo "Install complete."
echo "Install directory: $INSTALL_DIR"
echo "Command: $WRAPPER_PATH"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "Add $BIN_DIR to your PATH to run crowdstrike-falcon-tenant-report directly."
fi