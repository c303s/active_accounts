import os
import sys

_REQUIRED_PYTHON = (3, 10)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _bootstrap() -> None:
    if sys.version_info < _REQUIRED_PYTHON:
        sys.stderr.write(
            f"Python {_REQUIRED_PYTHON[0]}.{_REQUIRED_PYTHON[1]}+ required, "
            f"found {sys.version.split()[0]}.\n"
        )
        sys.exit(1)


_bootstrap()

import atexit
import json
import csv
import getpass
import ssl
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from itertools import cycle
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlencode, urlparse


TENANT_DISPLAY_NAMES = {
    "aunde": "AUNDE Group SE",
    "airventmain": "AUNDE Group SE",
}

APP_VERSION = "0.01"
DEFAULT_BASE_URL = "https://api.eu-1.crowdstrike.com"
ENV_PATH = Path(SCRIPT_DIR) / ".env"
LOGO_PATH = Path(SCRIPT_DIR) / "crowdstrike-logo.png"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_RESET = "\033[0m"


def read_env_file(path: Path) -> dict[str, str]:
    values = {}
    if not path.exists():
        return values

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key.strip()] = value

    return values


def write_env_file(path: Path, values: dict[str, str]) -> None:
    ordered_keys = [
        "FALCON_CLIENT_ID",
        "FALCON_CLIENT_SECRET",
        "FALCON_BASE_URL",
        "FALCON_TENANT_NAME",
        "FALCON_CID",
    ]
    lines = []
    seen_keys = set()

    for key in ordered_keys:
        value = values.get(key)
        if value:
            lines.append(f"{key}={value}")
            seen_keys.add(key)

    for key in sorted(values):
        if key in seen_keys or not values[key]:
            continue
        lines.append(f"{key}={values[key]}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def prompt_env_value(
    name: str,
    prompt_text: str,
    secret: bool = False,
    default: str | None = None,
) -> str:
    while True:
        prompt_suffix = f" [{default}]" if default else ""
        if secret:
            value = getpass.getpass(f"Enter {prompt_text}{prompt_suffix}: ").strip()
        else:
            value = input(f"Enter {prompt_text}{prompt_suffix}: ").strip()

        if not value and default is not None:
            return default

        if value:
            return value

        print(f"{name} cannot be empty.")


def _prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [y/N]: " if not default else " [Y/n]: "
    try:
        answer = input(prompt + suffix).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


def _collect_credentials(
    existing_id: str | None,
    existing_secret: str | None,
    existing_base_url: str | None,
) -> tuple[str, str, str]:
    print()
    print("Please enter the Falcon API credentials:")
    print()

    if existing_id:
        client_id = prompt_env_value(
            "FALCON_CLIENT_ID", "FALCON_CLIENT_ID", default=existing_id
        )
    else:
        client_id = prompt_env_value("FALCON_CLIENT_ID", "FALCON_CLIENT_ID")
    print()

    if existing_secret:
        entered = getpass.getpass(
            "Enter FALCON_CLIENT_SECRET (leave blank to keep current): "
        ).strip()
        client_secret = entered or existing_secret
    else:
        client_secret = prompt_env_value(
            "FALCON_CLIENT_SECRET", "FALCON_CLIENT_SECRET", secret=True
        )
    print()

    base_url = prompt_env_value(
        "FALCON_BASE_URL",
        "FALCON_BASE_URL",
        default=existing_base_url or DEFAULT_BASE_URL,
    )
    print()
    return client_id, client_secret, base_url


def print_startup_banner() -> None:
    print("CROWDSTRIKE FALCON TENANT REPORT")
    print("=================================")
    print("Connects to CrowdStrike Falcon, validates API access, and generates tenant summary reports.")
    print(f"Version {APP_VERSION}. This is not an offical CrowdStrike tool.")
    print()


def colorize(message: str, color: str) -> str:
    if not sys.stdout.isatty():
        return message
    return f"{color}{message}{ANSI_RESET}"


def _preflight_credentials(client_id: str, client_secret: str, base_url: str) -> tuple[bool, str]:
    api = FalconAPI(client_id=client_id, client_secret=client_secret, base_url=base_url)

    checks = [
        ("Sensor Download", api.get_sensor_installer_ccid),
        ("Hosts", lambda: api.query_devices_by_filter_scroll(limit=1)),
        ("GraphQL", lambda: api.graphql(query="query { __typename }")),
    ]

    for label, action in checks:
        try:
            response = action()
        except RuntimeError as exc:
            return False, f"{label} pre-flight failed: {exc}"

        if response["status_code"] != 200:
            errors = response.get("body", {}).get("errors", [])
            return False, (
                f"{label} pre-flight failed with status {response['status_code']}: {errors}"
            )

        body = response.get("body", {})
        if body.get("errors"):
            return False, f"{label} pre-flight failed: {body['errors']}"

    return True, "Credential pre-flight check passed."


def ensure_local_credentials() -> None:
    env_values = read_env_file(ENV_PATH)
    for key, value in env_values.items():
        os.environ.setdefault(key, value)

    client_id = env_values.get("FALCON_CLIENT_ID") or os.environ.get("FALCON_CLIENT_ID")
    client_secret = env_values.get("FALCON_CLIENT_SECRET") or os.environ.get("FALCON_CLIENT_SECRET")
    base_url = env_values.get("FALCON_BASE_URL") or os.environ.get("FALCON_BASE_URL")

    have_all = bool(client_id and client_secret and base_url)
    interactive = sys.stdin.isatty()

    if have_all and not interactive:
        return

    if have_all and interactive:
        print(f"Found existing credentials in {ENV_PATH}")
        print(f"  FALCON_CLIENT_ID  = {client_id}")
        print(f"  FALCON_CLIENT_SECRET = {'*' * 8} (hidden)")
        print(f"  FALCON_BASE_URL   = {base_url}")
        if not _prompt_yes_no("Update these credentials?", default=False):
            ok, message = _preflight_credentials(client_id, client_secret, base_url)
            if ok:
                print(colorize("Running pre-flight check: successful.", ANSI_GREEN))
                return

            print("Running pre-flight check: failed.")
            print(message)
            print("The saved credentials or required API access are not valid yet. Please enter valid credentials.")
            print()
    else:
        if not interactive:
            raise RuntimeError(
                "Missing Falcon credentials. Run the script interactively once or create a local .env file."
            )
        print("Make sure you have created a Falcon API client with these required scopes enabled:")
        print("  - Hosts: Read")
        print("  - Sensor Download: Read")
        print("  - Identity Protection: Read")
        print("  - GraphQL: Write")
        print()
        print(
            colorize(
                "Could not find API client details.",
                ANSI_RED,
            )
        )

    while True:
        client_id, client_secret, base_url = _collect_credentials(
            client_id, client_secret, base_url
        )
        ok, message = _preflight_credentials(client_id, client_secret, base_url)
        if ok:
            print(colorize("Running pre-flight check: successful.", ANSI_GREEN))
            break

        print("Running pre-flight check: failed.")
        print(message)
        print("The credentials or required API access are not valid yet. Please enter valid credentials.")
        print()

    env_values["FALCON_CLIENT_ID"] = client_id
    env_values["FALCON_CLIENT_SECRET"] = client_secret
    env_values["FALCON_BASE_URL"] = base_url

    write_env_file(ENV_PATH, env_values)
    os.environ["FALCON_CLIENT_ID"] = client_id
    os.environ["FALCON_CLIENT_SECRET"] = client_secret
    os.environ["FALCON_BASE_URL"] = base_url

    print("Saved API client key details.")


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


def normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return None

    normalized = domain.strip().lower().rstrip(".")
    return normalized or None


def sanitize_filename_component(value: str) -> str:
    sanitized = []
    for char in value.strip():
        if char.isalnum() or char in {"-", "_"}:
            sanitized.append(char)
        elif char.isspace():
            sanitized.append("-")
    collapsed = "".join(sanitized).strip("-")
    return collapsed or "unknown"


def write_pdf_report(
    pdf_path: str,
    tenant_label: str,
    cid_value: str,
    current_timestamp: str,
    total_endpoints: int,
    category_counts: dict[str, int],
    total_active_accounts: int,
    human_percentage: float,
    domain_rows: list[dict[str, int | str]],
) -> None:
    lines = [
        f"CrowdStrike Falcon Tenant Report v{APP_VERSION}",
        "",
        f"Tenant: {tenant_label}",
        f"CID: {cid_value}",
        f"Generated: {current_timestamp}",
        "",
        f"Protected endpoints: {total_endpoints}",
        f"Human accounts: {category_counts['human']}",
        f"Service accounts: {category_counts['service']}",
        f"Admin accounts: {category_counts['admin']}",
        f"Total active accounts: {total_active_accounts} ({human_percentage:.2f}% human)",
        "",
        "Active Directory Domains",
    ]

    if domain_rows:
        for row in domain_rows:
            lines.append(
                f"- {row['domain']} | Endpoints: {row['endpoints']} | Total: {row['total']} | "
                f"Human: {row['human']} | Service: {row['service']} | Admin: {row['admin']}"
            )
    else:
        lines.append("- No Active Directory domains were found.")

    max_lines_per_page = 44
    pages = [lines[index:index + max_lines_per_page] for index in range(0, len(lines), max_lines_per_page)]
    if not pages:
        pages = [["CrowdStrike Falcon Tenant Report"]]

    def escape_pdf_text(value: str) -> str:
        sanitized = value.encode("latin-1", "replace").decode("latin-1")
        return sanitized.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def render_page(page_lines: list[str]) -> bytes:
        commands = ["BT", "/F1 11 Tf", "50 792 Td"]
        if page_lines:
            commands.append(f"({escape_pdf_text(page_lines[0])}) Tj")
            for line in page_lines[1:]:
                commands.append(f"0 -16 Td ({escape_pdf_text(line)}) Tj")
        commands.append("ET")
        return "\n".join(commands).encode("latin-1", "replace")

    objects: list[bytes] = []
    page_objects: list[int] = []
    content_objects: list[int] = []
    font_object_number = 3 + len(pages) * 2

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [] /Count 0 >>")

    for page_lines in pages:
        content = render_page(page_lines)
        page_object_number = len(objects) + 1
        content_object_number = page_object_number + 1
        page_objects.append(page_object_number)
        content_objects.append(content_object_number)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 {font_object_number} 0 R >> >> "
                f"/Contents {content_object_number} 0 R >>"
            ).encode("ascii")
        )
        objects.append(
            b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream"
        )

    kids = " ".join(f"{number} 0 R" for number in page_objects)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_objects)} >>".encode("ascii")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )

    Path(pdf_path).write_bytes(pdf)


def resolve_tenant_label(identity_protection: "FalconAPI") -> str | None:
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


class FalconAPI:
    """Minimal CrowdStrike Falcon REST client using only Python stdlib."""

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._ssl_context = self._build_ssl_context()

    @staticmethod
    def _build_ssl_context() -> ssl.SSLContext:
        context = ssl.create_default_context()
        ca_bundle = (
            os.environ.get("FALCON_CA_BUNDLE")
            or os.environ.get("SSL_CERT_FILE")
            or os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("CURL_CA_BUNDLE")
        )
        if ca_bundle:
            bundle_path = Path(ca_bundle).expanduser()
            if not bundle_path.is_file():
                raise RuntimeError(
                    f"Configured CA bundle does not exist: {bundle_path}. "
                    "Set FALCON_CA_BUNDLE (or SSL_CERT_FILE) to a valid PEM file."
                )
            context.load_verify_locations(cafile=str(bundle_path))
        return context

    def _ssl_error(self, exc: Exception) -> RuntimeError:
        host = urlparse(self.base_url).netloc or self.base_url
        message = (
            f"TLS certificate verification failed while connecting to {host}. "
            "Python does not trust the certificate chain presented to this machine. "
            "The script also tries to fall back to curl/system trust automatically; "
            "this message means that fallback was unavailable or also failed. "
            "If your company uses TLS inspection, export the corporate root CA as a PEM file and set "
            "FALCON_CA_BUNDLE=/path/to/corp-root-ca.pem before running the script. "
            "You can also try SSL_CERT_FILE=/path/to/corp-root-ca.pem. "
            f"Original error: {exc}"
        )
        return RuntimeError(message)

    def _send_with_curl(
        self,
        req: urllib_request.Request,
        ssl_exc: Exception,
    ) -> tuple[int, dict[str, str], bytes]:
        curl_cmd = [
            "curl",
            "-sS",
            "--connect-timeout",
            "30",
            "--max-time",
            "60",
            "-X",
            req.get_method(),
        ]

        for key, value in req.header_items():
            curl_cmd.extend(["-H", f"{key}: {value}"])

        ca_bundle = (
            os.environ.get("FALCON_CA_BUNDLE")
            or os.environ.get("SSL_CERT_FILE")
            or os.environ.get("CURL_CA_BUNDLE")
        )
        if ca_bundle:
            curl_cmd.extend(["--cacert", str(Path(ca_bundle).expanduser())])

        body = req.data if req.data is not None else b""
        if body:
            curl_cmd.extend(["--data-binary", "@-"])

        status_marker = "\n__FALCON_HTTP_STATUS__:"
        curl_cmd.extend([
            "-w",
            status_marker + "%{http_code}",
            req.full_url,
        ])

        try:
            result = subprocess.run(
                curl_cmd,
                input=body,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise self._ssl_error(ssl_exc) from exc

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(
                f"Python TLS verification failed and curl fallback also failed: {stderr or ssl_exc}"
            )

        stdout = result.stdout
        marker = status_marker.encode("utf-8")
        if marker not in stdout:
            raise RuntimeError(
                "curl fallback succeeded but did not return an HTTP status code."
            )

        raw_body, _, raw_status = stdout.rpartition(marker)
        try:
            status_code = int(raw_status.decode("utf-8", "replace").strip())
        except ValueError as exc:
            raise RuntimeError(
                "curl fallback returned an invalid HTTP status code."
            ) from exc

        return status_code, {}, raw_body

    def _send_with_fallback(
        self,
        req: urllib_request.Request,
    ) -> tuple[int, dict[str, str], bytes]:
        try:
            return self._send(req, self._ssl_context)
        except ssl.SSLError as exc:
            return self._send_with_curl(req, exc)
        except urllib_error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLError):
                return self._send_with_curl(req, exc.reason)
            raise

    @staticmethod
    def _send(
        req: urllib_request.Request, context: ssl.SSLContext
    ) -> tuple[int, dict[str, str], bytes]:
        try:
            with urllib_request.urlopen(req, timeout=60, context=context) as resp:
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib_error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()) if exc.headers else {}, exc.read() or b""

    def _authenticate(self) -> None:
        data = urlencode(
            {"client_id": self._client_id, "client_secret": self._client_secret}
        ).encode("utf-8")
        req = urllib_request.Request(
            f"{self.base_url}/oauth2/token",
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            status, _, raw = self._send_with_fallback(req)
        except urllib_error.URLError as exc:
            raise RuntimeError(f"Network error while requesting Falcon OAuth token: {exc.reason}") from exc
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}
        if status not in (200, 201) or "access_token" not in body:
            errors = body.get("errors") or [{"message": raw[:200].decode("utf-8", "replace")}]
            raise RuntimeError(f"OAuth2 token error {status}: {errors}")
        self._token = body["access_token"]
        self._token_expiry = time.time() + int(body.get("expires_in", 1800)) - 60

    def _auth_header(self) -> dict[str, str]:
        if not self._token or time.time() >= self._token_expiry:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, path: str, *, params=None, json_body=None) -> dict:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"
        headers = self._auth_header()
        data = None
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(json_body).encode("utf-8")
        req = urllib_request.Request(url, data=data, method=method, headers=headers)
        try:
            status, resp_headers, raw = self._send_with_fallback(req)
        except urllib_error.URLError as exc:
            raise RuntimeError(f"Network error while requesting {url}: {exc.reason}") from exc
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {"raw": raw.decode("utf-8", "replace")}
        return {"status_code": status, "headers": resp_headers, "body": body}

    # SensorDownload
    def get_sensor_installer_ccid(self) -> dict:
        return self._request("GET", "/sensors/queries/installers/ccid/v1")

    # Hosts
    def query_devices_by_filter_scroll(self, **params) -> dict:
        return self._request("GET", "/devices/queries/devices-scroll/v1", params=params)

    def get_device_details(self, ids: list[str]) -> dict:
        return self._request("POST", "/devices/entities/devices/v2", json_body={"ids": ids})

    # IdentityProtection
    def graphql(self, query: str) -> dict:
        return self._request(
            "POST",
            "/identity-protection/combined/graphql/v1",
            json_body={"query": query},
        )


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


def _friendly_excepthook(exc_type, exc_value, exc_traceback) -> None:
    try:
        spinner.stop()
    except Exception:
        pass
    if issubclass(exc_type, KeyboardInterrupt):
        sys.stderr.write("\nAborted by user.\n")
        sys.exit(130)
    if issubclass(exc_type, RuntimeError):
        sys.stderr.write(f"\nError: {exc_value}\n")
        sys.exit(1)
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


sys.excepthook = _friendly_excepthook

clear_screen()
print_startup_banner()
ensure_local_credentials()

spinner = Spinner("Loading configuration")
atexit.register(spinner.stop)
spinner.start()

client_id = os.environ["FALCON_CLIENT_ID"]
client_secret = os.environ["FALCON_CLIENT_SECRET"]
base_url = os.environ.get("FALCON_BASE_URL", DEFAULT_BASE_URL)
current_timestamp = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M:%S %Z")

auth = dict(client_id=client_id, client_secret=client_secret, base_url=base_url)

tenant_label = os.environ.get("FALCON_TENANT_NAME")
cid_value = os.environ.get("FALCON_CID", "Unavailable")

falcon_api = FalconAPI(**auth)

spinner.update("Fetching tenant CID")
sensor_download = falcon_api
cid_response = sensor_download.get_sensor_installer_ccid()
if cid_response["status_code"] == 200:
    cid_resources = cid_response.get("body", {}).get("resources", [])
    if cid_resources:
        cid_value = cid_resources[0]

if cid_value != "Unavailable":
    cid_value = cid_value.split("-")[0] if "-" in cid_value else cid_value[:-2]

# 1. Sensor-installed endpoint count

spinner.update("Counting protected endpoints")
hosts = falcon_api

total_endpoints = 0
endpoint_domain_counts = {}
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

    device_ids = []
    for resource in resources:
        if isinstance(resource, str):
            device_ids.append(resource)
        elif isinstance(resource, dict) and resource.get("device_id"):
            device_ids.append(resource["device_id"])

    if device_ids:
        details_response = hosts.get_device_details(ids=device_ids)
        if details_response["status_code"] != 200:
            errors = details_response.get("body", {}).get("errors", [])
            raise RuntimeError(
                f"Hosts details API error {details_response['status_code']}: {errors}"
            )

        detail_resources = details_response.get("body", {}).get("resources", [])
        for endpoint in detail_resources:
            domain = normalize_domain(endpoint.get("machine_domain"))
            if not domain:
                domain = "Unspecified"
            endpoint_domain_counts[domain] = endpoint_domain_counts.get(domain, 0) + 1

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
identity_protection = falcon_api
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

category_counts["human"] = max(
    0, verified_total - category_counts["service"] - category_counts["admin"]
)
total_active_accounts = sum(category_counts.values())
human_percentage = (category_counts["human"] / total_active_accounts * 100) if total_active_accounts else 0

if not tenant_label:
    tenant_label = derive_tenant_label_from_domains(active_directory_domains)

if not tenant_label:
    tenant_label = urlparse(base_url).netloc or base_url

# Output

csv_filename = (
    f"{sanitize_filename_component(tenant_label)}-"
    f"{sanitize_filename_component(cid_value)}-"
    f"{datetime.now(timezone.utc).strftime('%d-%m-%Y')}.csv"
)
pdf_filename = csv_filename.removesuffix(".csv") + ".pdf"

spinner.update("Preparing report")
spinner.stop()
clear_screen()

print(f"Tenant                  : {tenant_label}")
print(f"CID                     : {cid_value}")
print(f"Current date and time   : {current_timestamp}")
print(f"Version                 : {APP_VERSION}")
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
domain_rows = []
for domain in active_directory_domains:
    domain_counts = domain_account_breakdown[domain]
    domain_total = domain_counts["human"] + domain_counts["service"] + domain_counts["admin"]
    endpoint_count = endpoint_domain_counts.get(normalize_domain(domain), 0)
    domain_rows.append(
        {
            "domain": domain,
            "endpoints": endpoint_count,
            "total": domain_total,
            "human": domain_counts["human"],
            "service": domain_counts["service"],
            "admin": domain_counts["admin"],
        }
    )

domain_rows.sort(key=lambda row: str(row["domain"]).lower())

for row in domain_rows:
    print(
        f"  - {row['domain']} | "
        f"Endpoints: {row['endpoints']} | "
        f"Total: {row['total']} | "
        f"Human: {row['human']} | "
        f"Service: {row['service']} | "
        f"Admin: {row['admin']}"
    )

with open(csv_filename, "w", newline="", encoding="utf-8") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["section", "label", "value", "domain", "endpoints", "total", "human", "service", "admin"])
    writer.writerow(["summary", "tenant", tenant_label, "", "", "", "", "", ""])
    writer.writerow(["summary", "cid", cid_value, "", "", "", "", "", ""])
    writer.writerow(["summary", "current_date_time", current_timestamp, "", "", "", "", "", ""])
    writer.writerow(["summary", "version", APP_VERSION, "", "", "", "", "", ""])
    writer.writerow(["summary", "protected_endpoints", total_endpoints, "", "", "", "", "", ""])
    writer.writerow(["summary", "human_accounts", category_counts["human"], "", "", "", "", "", ""])
    writer.writerow(["summary", "service_accounts", category_counts["service"], "", "", "", "", "", ""])
    writer.writerow(["summary", "admin_accounts", category_counts["admin"], "", "", "", "", "", ""])
    writer.writerow(["summary", "total_active_accounts", total_active_accounts, "", "", "", "", "", ""])
    writer.writerow(["summary", "human_percentage", f"{human_percentage:.2f}", "", "", "", "", "", ""])

    for row in domain_rows:
        writer.writerow(
            [
                "active_directory_domain",
                "domain_breakdown",
                "",
                row["domain"],
                row["endpoints"],
                row["total"],
                row["human"],
                row["service"],
                row["admin"],
            ]
        )

write_pdf_report(
    pdf_filename,
    tenant_label,
    cid_value,
    current_timestamp,
    total_endpoints,
    category_counts,
    total_active_accounts,
    human_percentage,
    domain_rows,
)

print()
print(f"Writing .csv file      : {csv_filename}")
print(f"Writing .pdf file      : {pdf_filename}")
print()
print("Thanks for using CrowdStrike Falcon Tenant Report.")