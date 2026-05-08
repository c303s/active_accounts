import os
import sys
import atexit
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from itertools import cycle
from urllib.parse import urlparse

from dotenv import load_dotenv
from falconpy import Hosts, IdentityProtection, SensorDownload


TENANT_DISPLAY_NAMES = {
    "aunde": "AUNDE Group SE",
    "airventmain": "AUNDE Group SE",
}


def derive_tenant_label_from_domains(domains: set[str]) -> str | None:
    fallback_label = None

    for domain in sorted(domains):
        normalized_domain = domain.strip().lower().rstrip(".")
        if not normalized_domain:
            continue

        labels = [label for label in normalized_domain.split(".") if label]
        if not labels:
            continue

        primary_label = labels[0]
        if primary_label in {"ad", "corp", "global", "emea", "eu", "us", "apac"} and len(labels) > 1:
            primary_label = labels[1]

        if primary_label:
            mapped_label = TENANT_DISPLAY_NAMES.get(primary_label)
            if mapped_label:
                return mapped_label
            if fallback_label is None:
                fallback_label = primary_label

    return fallback_label


def resolve_tenant_label(identity_protection: IdentityProtection) -> str | None:
    domains_response = identity_protection.graphql(query="query { domains }")
    if domains_response["status_code"] != 200:
        return None

    domains_body = domains_response.get("body", {})
    if domains_body.get("errors"):
        return None

    for domain in domains_body.get("data", {}).get("domains", []):
        assessment_query = f'''
        query {{
          securityAssessment(domain: {json.dumps(domain)}) {{
            tenant
          }}
        }}
        '''
        assessment_response = identity_protection.graphql(query=assessment_query)
        if assessment_response["status_code"] != 200:
            continue

        assessment_body = assessment_response.get("body", {})
        if assessment_body.get("errors"):
            continue

        tenant = assessment_body.get("data", {}).get("securityAssessment", {}).get("tenant")
        if tenant:
            return tenant

    return None


def clear_screen() -> None:
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


class Spinner:
    def __init__(self, message: str):
        self.message = message
        self._active = False
        self._thread = None
        self._enabled = sys.stdout.isatty()
        self._message_lock = threading.Lock()
        self._printed_messages = set()

    def update(self, message: str) -> None:
        with self._message_lock:
            self.message = message
            if self._enabled and message not in self._printed_messages:
                if self._active:
                    sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
                sys.stdout.write(f"{message}\n")
                sys.stdout.flush()
                self._printed_messages.add(message)

    def start(self) -> None:
        if not self._enabled:
            return
        self._active = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._enabled:
            return
        if not self._active and self._thread is None:
            return
        self._active = False
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        with self._message_lock:
            sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
        sys.stdout.flush()

    def _spin(self) -> None:
        for frame in cycle("|/-\\"):
            if not self._active:
                break
            with self._message_lock:
                sys.stdout.write(f"\r{self.message} {frame}")
                sys.stdout.flush()
            time.sleep(0.1)


clear_screen()
spinner = Spinner("Loading configuration")
atexit.register(spinner.stop)
spinner.start()

load_dotenv()

client_id = os.environ["FALCON_CLIENT_ID"]
client_secret = os.environ["FALCON_CLIENT_SECRET"]
base_url = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
current_timestamp = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M:%S %Z")

auth = dict(client_id=client_id, client_secret=client_secret, base_url=base_url)

tenant_label = os.environ.get("FALCON_TENANT_NAME")
cid_value = os.environ.get("FALCON_CID", "Unavailable")

spinner.update("Fetching tenant CID")
sensor_download = SensorDownload(**auth)
cid_response = sensor_download.get_sensor_installer_ccid()
if cid_response["status_code"] == 200:
    cid_resources = cid_response.get("body", {}).get("resources", [])
    if cid_resources:
        cid_value = cid_resources[0]

if cid_value != "Unavailable":
    cid_value = cid_value.split("-")[0] if "-" in cid_value else cid_value[:-2]

# 1. Sensor-installed endpoint count

spinner.update("Counting protected endpoints")
hosts = Hosts(**auth)

total_endpoints = 0
cursor = None
cursor_param = None
expected_total = None

while True:
    params = {"limit": 5000}
    if cursor and cursor_param:
        params[cursor_param] = cursor

    response = hosts.query_devices_by_filter_scroll(**params)

    if response["status_code"] != 200:
        errors = response.get("body", {}).get("errors", [])
        raise RuntimeError(f"Hosts API error {response['status_code']}: {errors}")

    resources = response["body"].get("resources", [])
    total_endpoints += len(resources)

    pagination = response["body"].get("meta", {}).get("pagination", {})
    total = pagination.get("total")
    if isinstance(total, int):
        expected_total = total

    next_cursor = None
    next_cursor_param = None
    for key in ("offset", "after"):
        value = pagination.get(key)
        if value:
            next_cursor = value
            next_cursor_param = key
            break

    if not resources:
        break

    if expected_total is not None and total_endpoints >= expected_total:
        break

    if not next_cursor:
        break

    cursor = next_cursor
    cursor_param = next_cursor_param

# 2. Active accounts in the last 90 days (Identity Protection)

spinner.update("Connecting to Identity Protection")
identity_protection = IdentityProtection(**auth)
cutoff = datetime.now(timezone.utc) - timedelta(days=90)
cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

spinner.update("Verifying Identity Protection access")
probe_response = identity_protection.graphql(query="query { __typename }")
if probe_response["status_code"] != 200:
    errors = probe_response.get("body", {}).get("errors", [])
    raise RuntimeError(
        "Identity Protection GraphQL is required for the active-account total, "
        f"but this API client cannot access it: {errors}."
    )

if not tenant_label:
    tenant_label = resolve_tenant_label(identity_protection)

total_query = f'''
query {{
  total: countEntities(
    types: [USER],
    archived: false,
    mostRecentActivityStartTime: "{cutoff_str}"
  )
}}
'''
spinner.update("Counting active user accounts")
spinner.update("Counting active accounts")
total_response = identity_protection.graphql(query=total_query)
if total_response["status_code"] != 200:
    errors = total_response.get("body", {}).get("errors", [])
    raise RuntimeError(f"Identity Protection countEntities error {total_response['status_code']}: {errors}")

total_body = total_response.get("body", {})
if total_body.get("errors"):
    raise RuntimeError(f"Identity Protection countEntities query error: {total_body['errors']}")

verified_total = total_body.get("data", {}).get("total", 0)

category_counts = {
    "human": 0,
    "service": 0,
    "admin": 0,
}

active_directory_domains = set()
domain_account_breakdown = {}

spinner.update("Aggregating active accounts by domain")
after = None
while True:
    after_arg = f', after: "{after}"' if after else ""
    query = f'''
    query {{
      entities(
        first: 200,
        types: [USER],
        archived: false,
        mostRecentActivityStartTime: "{cutoff_str}"
        {after_arg}
      ) {{
        nodes {{
          roles {{ type }}
          ... on UserEntity {{
            accounts {{
              __typename
              archived
              enabled
              ... on ActiveDirectoryAccountDescriptor {{
                domain
              }}
            }}
          }}
        }}
        pageInfo {{ hasNextPage endCursor }}
      }}
    }}
    '''

    response = identity_protection.graphql(query=query)
    if response["status_code"] != 200:
        errors = response.get("body", {}).get("errors", [])
        raise RuntimeError(f"Identity Protection GraphQL error {response['status_code']}: {errors}")

    body = response.get("body", {})
    if body.get("errors"):
        raise RuntimeError(f"Identity Protection GraphQL query error: {body['errors']}")

    entity_connection = body.get("data", {}).get("entities", {})
    for entity in entity_connection.get("nodes", []):
        role_types = {role.get("type") for role in entity.get("roles", []) if role.get("type")}
        is_programmatic = "ProgrammaticUserAccountRole" in role_types
        is_human = "HumanUserAccountRole" in role_types

        enabled_accounts = [
            account
            for account in entity.get("accounts", [])
            if account.get("enabled") and not account.get("archived")
        ]
        has_enabled_account = bool(enabled_accounts)

        if is_programmatic and has_enabled_account:
            entity_category = "service"
            category_counts["service"] += 1
        elif not is_human and not is_programmatic:
            entity_category = "admin"
            category_counts["admin"] += 1
        else:
            entity_category = "human"

        seen_domains = set()
        for account in enabled_accounts:
            if account.get("__typename") != "ActiveDirectoryAccountDescriptor":
                continue

            domain = account.get("domain")
            if not domain or domain in seen_domains:
                continue

            seen_domains.add(domain)
            active_directory_domains.add(domain)
            domain_breakdown = domain_account_breakdown.setdefault(
                domain,
                {
                    "human": 0,
                    "service": 0,
                    "admin": 0,
                },
            )
            domain_breakdown[entity_category] += 1

    page_info = entity_connection.get("pageInfo", {})
    if not page_info.get("hasNextPage"):
        break
    after = page_info.get("endCursor")

category_counts["human"] = verified_total - category_counts["service"] - category_counts["admin"]
total_active_accounts = sum(category_counts.values())
human_percentage = (category_counts["human"] / total_active_accounts * 100) if total_active_accounts else 0

if not tenant_label:
    tenant_label = derive_tenant_label_from_domains(active_directory_domains)

if not tenant_label:
    tenant_label = urlparse(base_url).netloc or base_url

# Output

spinner.update("Preparing report")
spinner.stop()
clear_screen()

print(f"Tenant                  : {tenant_label}")
print(f"CID                     : {cid_value}")
print(f"Current date and time   : {current_timestamp}")
print()
print(f"Endpoints with an installed CrowdStrike sensor : {total_endpoints}")
print()
print("Identity Protection accounts used in the last 90 days")
print(f"  Human accounts         : {category_counts['human']}")
print(f"  Service accounts       : {category_counts['service']}")
print(f"  Admin accounts         : {category_counts['admin']}")
print(f"  Total active accounts  : {total_active_accounts} ({human_percentage:.2f}% human)")
print()
print(f"Active Directory domains : {len(active_directory_domains)}")
for domain in sorted(active_directory_domains):
    domain_counts = domain_account_breakdown[domain]
    domain_total = domain_counts["human"] + domain_counts["service"] + domain_counts["admin"]
    print(
        f"  - {domain} | "
        f"Total: {domain_total} | "
        f"Human: {domain_counts['human']} | "
        f"Service: {domain_counts['service']} | "
        f"Admin: {domain_counts['admin']}"
    )