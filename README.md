# CrowdStrike Falcon Tenant Report

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

## What The Script Uses

The script uses these Falcon APIs through FalconPy:

- Hosts
- Sensor Download
- Identity Protection GraphQL

Minimum API permissions:

- Hosts: Read
- Sensor Download: Read
- Identity Protection: Read

## Requirements

- Python 3.10 or newer
- A CrowdStrike Falcon API client with the required scopes

## One-Command Install

Download, install, and set up the script with a single command:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/crowdstrike-falcon-tenant-report/main/install.sh)"
```

The installer will:

- download the latest version of the repository into the current directory
- create a local virtual environment
- install the Python dependencies
- ask for `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, and `FALCON_BASE_URL` if they are not already available
- store those credentials in a local `.env` file with restricted file permissions
- create a local launcher at `./crowdstrike-falcon-tenant-report`

Run the installer from the directory where you want the project files to live.

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Create a local `.env` file based on `.env.example`.

If the script does not find `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, or `FALCON_BASE_URL`, it starts an interactive setup wizard and writes them to a local `.env` file automatically.

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
- If a local file named `crowdstrike-logo.png` exists next to the script, it will be embedded in the PDF header automatically.
- Do not commit real credentials to GitHub.

## Publish To GitHub

This workspace is not automatically published by the script. To make it available on GitHub, do this from the repository root:

```bash
git init
git add README.md .gitignore .env.example active_accounts.py requirements.txt req_api_scopes procedure mymethod
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

If the repository already exists:

```bash
git add README.md .gitignore .env.example active_accounts.py requirements.txt req_api_scopes procedure mymethod
git commit -m "Add documentation and setup instructions"
git push
```

## Security

- Keep `.env` local only.
- Rotate any credential that has already been stored in the repository or pasted into public history.
- Use a read-only Falcon API client for this script.