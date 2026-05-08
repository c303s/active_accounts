#!/usr/bin/env bash

set -euo pipefail

REPO_OWNER="c303s"
REPO_NAME="crowdstrike-falcon-tenant-report"
REPO_BRANCH="${REPO_BRANCH:-main}"
APP_VERSION="0.01"
INSTALL_DIR="${INSTALL_DIR:-$(pwd -P)}"
WRAPPER_PATH="$INSTALL_DIR/crowdstrike-falcon-tenant-report"
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
    local default_value="${3:-}"
    local value=""

    while [[ -z "$value" ]]; do
        if [[ "$secret" == "true" ]]; then
            if [[ -n "$default_value" ]]; then
                read -r -s -p "$prompt_text [$default_value]: " value
            else
                read -r -s -p "$prompt_text: " value
            fi
            printf '\n' >&2
        else
            if [[ -n "$default_value" ]]; then
                read -r -p "$prompt_text [$default_value]: " value
            else
                read -r -p "$prompt_text: " value
            fi
        fi

        if [[ -z "$value" && -n "$default_value" ]]; then
            value="$default_value"
        fi
    done

    printf '%s' "$value"
}

require_command curl
require_command tar
require_command python3

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$INSTALL_DIR"

echo "Downloading ${REPO_NAME}..."
curl -fsSL "$ARCHIVE_URL" | tar -xzf - -C "$tmp_dir"
cp -R "$tmp_dir/${REPO_NAME}-${REPO_BRANCH}/." "$INSTALL_DIR"

echo "Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/.venv"

echo "Installing dependencies..."
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    echo "CrowdStrike Falcon Tenant Report v${APP_VERSION}"
    echo "Before continuing, create a Falcon API client with these scopes enabled:"
    echo "  - Hosts: Read"
    echo "  - Sensor Download: Read"
    echo "  - Identity Protection: Read"
    client_id="$(prompt_value "Enter FALCON_CLIENT_ID")"
    client_secret="$(prompt_value "Enter FALCON_CLIENT_SECRET" true)"
    base_url="$(prompt_value "Enter FALCON_BASE_URL" false "$DEFAULT_BASE_URL")"

    umask 077
    cat > "$INSTALL_DIR/.env" <<EOF
FALCON_CLIENT_ID=${client_id}
FALCON_CLIENT_SECRET=${client_secret}
FALCON_BASE_URL=${base_url}
EOF
    chmod 600 "$INSTALL_DIR/.env"
fi

cat > "$WRAPPER_PATH" <<EOF
#!/usr/bin/env bash
exec "$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/active_accounts.py" "\$@"
EOF
chmod +x "$WRAPPER_PATH"

echo
echo "Install complete for CrowdStrike Falcon Tenant Report v${APP_VERSION}."
echo "Install directory: $INSTALL_DIR"
echo "Command: ./$(basename "$WRAPPER_PATH")"