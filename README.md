# CrowdStrike Falcon Tenant Report v0.01

This repository contains a small Python script that connects to CrowdStrike Falcon and prints a terminal report with:

- the tenant label and CID
- the number of endpoints with an installed Falcon sensor
- an endpoint-per-domain summary based on host machine domains
- the number of active Identity Protection accounts seen in the last 90 days
- a human, service, and admin split for those active identities
- the Active Directory domains represented by those identities
- a CSV export of the full report written after the terminal output completes
- a PDF export with charts and CrowdStrike-themed styling

The main script is `active_accounts.py`.

Current version: `0.01`

## What The Script Uses

The script calls these Falcon REST APIs directly using only the Python standard library (no SDK, no `requests`):

- Hosts (`/devices/queries/devices-scroll/v1`, `/devices/entities/devices/v2`)
- Sensor Download (`/sensors/queries/installers/ccid/v1`)
- Identity Protection GraphQL (`/identity-protection/combined/graphql/v1`)

The only third-party dependency installed at first run is `reportlab` (for the PDF export).

Minimum API permissions:

- Hosts: Read
- Sensor Download: Read
- Identity Protection: Read

## Requirements

- Python 3.10 or newer (any system Python works; nothing else needed)
- A CrowdStrike Falcon API client with the required scopes

The script uses only the Python standard library for HTTP. On first run it installs a single dependency (`reportlab`, used for the PDF export) into a hidden folder named `.falcon-deps-pyX.Y/` next to `active_accounts.py` itself. Nothing is written under `~/Library/Application Support` or any other user-wide data directory. Subsequent runs reuse the same folder; delete it to force a clean reinstall.

## Install And Run

One command — download, set up, and run:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/crowdstrike-falcon-tenant-report/main/install.sh)"
```

The installer:

- verifies that Python 3.10+ is available
- resolves the latest commit SHA on `main` via the GitHub API and downloads a SHA-pinned copy of `active_accounts.py` into the current directory (this avoids stale results from the raw.githubusercontent.com CDN cache)
- launches it

On the first launch the script installs `reportlab` into its private dependency directory, then walks you through entering `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, and `FALCON_BASE_URL` and stores them in a local `.env` file. Every later run is just:

```bash
python3 active_accounts.py
```

Manual alternative (skip the installer):

```bash
curl -fsSL https://raw.githubusercontent.com/c303s/crowdstrike-falcon-tenant-report/main/active_accounts.py -o active_accounts.py
python3 active_accounts.py
```

Behind a corporate proxy? Set `HTTPS_PROXY`/`HTTP_PROXY` before running so that `pip` (for `reportlab`) and the Falcon API calls can reach the internet:

```bash
export HTTPS_PROXY=http://proxy.example.com:8080
export HTTP_PROXY=$HTTPS_PROXY
```

## Configuration

Create a local `.env` file based on `.env.example`.

If the script does not find `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, or `FALCON_BASE_URL`, it starts an interactive setup wizard and writes them to a local `.env` file automatically.

Before entering credentials, make sure a Falcon API client already exists with these scopes enabled:

- `Hosts: Read`
- `Sensor Download: Read`
- `Identity Protection: Read`

Required variables:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_BASE_URL`

Common Falcon base URLs:

- `https://api.crowdstrike.com`
- `https://api.eu-1.crowdstrike.com`
- `https://api.us-2.crowdstrike.com`

Example `.env`:

```dotenv
FALCON_CLIENT_ID=YOUR_CLIENT_ID
FALCON_CLIENT_SECRET=YOUR_CLIENT_SECRET
FALCON_BASE_URL=https://api.crowdstrike.com
```

## Usage

Run the report:

```bash
python3 active_accounts.py
```

Example output:

```text
Tenant                  : Example Tenant
CID                     : 0123456789ABCDEF0123456789ABCDEF
Current date and time   : 08.05.2026 07:00:00 UTC
Version                 : 0.01

Endpoints with an installed CrowdStrike sensor : 6654

Identity Protection accounts used in the last 90 days
  Human accounts         : 6034
  Service accounts       : 1032
  Admin accounts         : 332
  Total active accounts  : 7398 (81.56% human)

Active Directory domains : 2
  - acme.local | Endpoints: 4210 | Total: 4822 | Human: 4010 | Service: 622 | Admin: 190
  - acme-main.local | Endpoints: 2088 | Total: 2576 | Human: 2024 | Service: 411 | Admin: 141

CSV output             : ACME-Group-0123456789ABCDEF0123456789ABCDEF-08-05-2026.csv
PDF output             : ACME-Group-0123456789ABCDEF0123456789ABCDEF-08-05-2026.pdf
```

## Notes

- The endpoint count is paginated and follows the cursor returned by the Hosts API.
- The script verifies Identity Protection GraphQL access before running the more expensive queries.
- Some API clients do not expose a tenant display name directly. In that case, the script tries to derive a tenant label from the discovered Active Directory domains before falling back to the Falcon base URL host name, unless `FALCON_TENANT_NAME` is set.
- The CSV export file name uses the structure `tenant-cid-dd-mm-yyyy.csv` and is written in the current working directory.
- The PDF export uses the same base file name and adds a cleaner CrowdStrike-themed summary page with separate charts and a domain table.
- If you place a local file named `crowdstrike-logo.png` next to the script, it will be embedded in the PDF header automatically.
- Do not commit real credentials to GitHub.

## Publish To GitHub

This workspace is not automatically published by the script. To make it available on GitHub, do this from the repository root:

```bash
git init
git add README.md .gitignore .env.example active_accounts.py req_api_scopes procedure mymethod
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

If the repository already exists:

```bash
git add README.md .gitignore .env.example active_accounts.py req_api_scopes procedure mymethod
git commit -m "Add documentation and setup instructions"
git push
```

## Security

- Keep `.env` local only.
- Rotate any credential that has already been stored in the repository or pasted into public history.
- Use a read-only Falcon API client for this script.