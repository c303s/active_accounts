import os
import sys

_REQUIRED_PYTHON = (3, 10)
_DEPENDENCIES = ("crowdstrike-falconpy", "reportlab")
_IMPORT_PROBES = ("falconpy", "reportlab")


def _bootstrap() -> None:
    if sys.version_info < _REQUIRED_PYTHON:
        sys.stderr.write(
            f"Python {_REQUIRED_PYTHON[0]}.{_REQUIRED_PYTHON[1]}+ required, "
            f"found {sys.version.split()[0]}.\n"
        )
        sys.exit(1)

    if os.environ.get("CSFTR_BOOTSTRAPPED") == "1":
        return

    import importlib.util

    if all(importlib.util.find_spec(name) is not None for name in _IMPORT_PROBES):
        return

    import venv
    from pathlib import Path
    import subprocess

    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library/Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    venv_dir = base / "crowdstrike-falcon-tenant-report" / "venv"

    py = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not py.exists():
        print(f"First-run setup: creating environment at {venv_dir}", file=sys.stderr)
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        venv.EnvBuilder(with_pip=True, upgrade_deps=False).create(venv_dir)
        subprocess.check_call(
            [str(py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"]
        )

    probe = (
        "import importlib.util, sys; "
        f"sys.exit(0 if all(importlib.util.find_spec(n) for n in {_IMPORT_PROBES!r}) else 1)"
    )
    if subprocess.call([str(py), "-c", probe]) != 0:
        print("Installing dependencies...", file=sys.stderr)
        subprocess.check_call(
            [str(py), "-m", "pip", "install", "--quiet", *_DEPENDENCIES]
        )

    os.environ["CSFTR_BOOTSTRAPPED"] = "1"
    os.execv(str(py), [str(py), os.path.abspath(__file__), *sys.argv[1:]])


_bootstrap()

import atexit
import json
import csv
import getpass
import threading
import time
from datetime import datetime, timedelta, timezone
from itertools import cycle
from pathlib import Path
from urllib.parse import urlparse

from falconpy import Hosts, IdentityProtection, SensorDownload
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


TENANT_DISPLAY_NAMES = {
    "aunde": "AUNDE Group SE",
    "airventmain": "AUNDE Group SE",
}

APP_VERSION = "0.01"
DEFAULT_BASE_URL = "https://api.eu-1.crowdstrike.com"
ENV_PATH = Path.cwd() / ".env"
SCRIPT_PATH = Path(__file__).name
LOGO_PATH = Path(__file__).with_name("crowdstrike-logo.png")
CROWDSTRIKE_RED = colors.HexColor("#E01E26")
CROWDSTRIKE_BLACK = colors.HexColor("#1A1A1A")
CROWDSTRIKE_DARK = colors.HexColor("#252525")
CROWDSTRIKE_LIGHT = colors.HexColor("#F5F5F5")
CROWDSTRIKE_GRAY = colors.HexColor("#D9D9D9")
CROWDSTRIKE_MID = colors.HexColor("#5A5A5A")
CROWDSTRIKE_PALE = colors.HexColor("#F1F1F1")


def read_env_file(path: Path) -> dict[str, str]:
    values = {}
    if not path.exists():
        return values

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

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
            value = getpass.getpass(f"{prompt_text}{prompt_suffix}: ").strip()
        else:
            value = input(f"{prompt_text}{prompt_suffix}: ").strip()

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
            "FALCON_CLIENT_SECRET [leave blank to keep current]: "
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
            return
    else:
        if not interactive:
            raise RuntimeError(
                "Missing Falcon credentials. Run the script interactively once or create a local .env file."
            )
        print(f"CrowdStrike Falcon Tenant Report v{APP_VERSION}")
        print("Falcon API credentials are missing. Let's create a local .env file.")
        print("Before continuing, create a Falcon API client with these scopes enabled:")
        print("  - Hosts: Read")
        print("  - Sensor Download: Read")
        print("  - Identity Protection: Read")

    client_id, client_secret, base_url = _collect_credentials(
        client_id, client_secret, base_url
    )

    env_values["FALCON_CLIENT_ID"] = client_id
    env_values["FALCON_CLIENT_SECRET"] = client_secret
    env_values["FALCON_BASE_URL"] = base_url

    write_env_file(ENV_PATH, env_values)
    os.environ["FALCON_CLIENT_ID"] = client_id
    os.environ["FALCON_CLIENT_SECRET"] = client_secret
    os.environ["FALCON_BASE_URL"] = base_url

    print(f"Saved credentials to {ENV_PATH}.")


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


def build_identity_chart(account_counts: dict[str, int]) -> Drawing:
    drawing = Drawing(500, 240)
    drawing.add(Rect(0, 0, 500, 240, fillColor=colors.white, strokeColor=CROWDSTRIKE_GRAY))
    drawing.add(String(18, 214, "Identity Distribution", fontName="Helvetica-Bold", fontSize=14, fillColor=CROWDSTRIKE_BLACK))

    pie = Pie()
    pie.x = 24
    pie.y = 26
    pie.width = 180
    pie.height = 180
    pie.data = [
        account_counts["human"],
        account_counts["service"],
        account_counts["admin"],
    ]
    pie.labels = ["", "", ""]
    pie.slices[0].fillColor = CROWDSTRIKE_RED
    pie.slices[1].fillColor = CROWDSTRIKE_MID
    pie.slices[2].fillColor = colors.HexColor("#9C9C9C")
    pie.slices.strokeColor = colors.white
    pie.sideLabels = False
    drawing.add(pie)

    legend = Legend()
    legend.x = 250
    legend.y = 150
    legend.colorNamePairs = [
        (CROWDSTRIKE_RED, f"Human ({account_counts['human']})"),
        (CROWDSTRIKE_MID, f"Service ({account_counts['service']})"),
        (colors.HexColor("#9C9C9C"), f"Admin ({account_counts['admin']})"),
    ]
    legend.fontName = "Helvetica"
    legend.fontSize = 11
    legend.dxTextSpace = 8
    legend.dy = 18
    legend.deltay = 22
    drawing.add(legend)

    return drawing


def build_endpoint_chart(domain_rows: list[dict[str, int | str]]) -> Drawing:
    drawing = Drawing(500, 260)
    drawing.add(Rect(0, 0, 500, 260, fillColor=colors.white, strokeColor=CROWDSTRIKE_GRAY))
    drawing.add(String(18, 232, "Endpoints by Domain", fontName="Helvetica-Bold", fontSize=14, fillColor=CROWDSTRIKE_BLACK))

    top_domains = sorted(
        domain_rows,
        key=lambda row: (-int(row["endpoints"]), -int(row["total"]), str(row["domain"]).lower()),
    )[:6]
    chart_domains = list(reversed(top_domains))
    bar_chart = HorizontalBarChart()
    bar_chart.x = 165
    bar_chart.y = 34
    bar_chart.width = 300
    bar_chart.height = 160
    bar_chart.data = [[int(row["endpoints"]) for row in chart_domains] or [0]]
    bar_chart.categoryAxis.categoryNames = [str(row["domain"])[:28] for row in chart_domains] or ["No domains"]
    bar_chart.categoryAxis.labels.boxAnchor = "e"
    bar_chart.categoryAxis.labels.dx = -10
    bar_chart.categoryAxis.labels.fontName = "Helvetica"
    bar_chart.categoryAxis.labels.fontSize = 9
    bar_chart.valueAxis.labels.fontName = "Helvetica"
    bar_chart.valueAxis.labels.fontSize = 9
    bar_chart.valueAxis.strokeColor = CROWDSTRIKE_GRAY
    bar_chart.categoryAxis.strokeColor = CROWDSTRIKE_GRAY
    bar_chart.bars[0].fillColor = CROWDSTRIKE_RED
    bar_chart.bars[0].strokeColor = CROWDSTRIKE_RED
    bar_chart.barSpacing = 6
    bar_chart.groupSpacing = 10
    drawing.add(bar_chart)

    return drawing


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
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CrowdStrikeTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=CROWDSTRIKE_RED,
        spaceAfter=8,
    )
    subtitle_style = ParagraphStyle(
        "CrowdStrikeSubtitle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        textColor=CROWDSTRIKE_DARK,
        spaceAfter=8,
    )
    heading_style = ParagraphStyle(
        "CrowdStrikeHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=CROWDSTRIKE_BLACK,
        spaceBefore=10,
        spaceAfter=6,
    )
    small_style = ParagraphStyle(
        "CrowdStrikeSmall",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        textColor=CROWDSTRIKE_DARK,
        leading=12,
    )

    header_left = [
        Paragraph(f"CrowdStrike Falcon Tenant Report v{APP_VERSION}", title_style),
        Paragraph(f"Tenant: {tenant_label}<br/>CID: {cid_value}<br/>Generated: {current_timestamp}<br/>Version: {APP_VERSION}", subtitle_style),
    ]

    header_right = ""
    if LOGO_PATH.exists():
        header_right = Image(str(LOGO_PATH), width=46 * mm, height=16 * mm, kind="proportional")
    else:
        header_right = Table(
            [[Paragraph("CROWDSTRIKE", ParagraphStyle("HeaderBadge", parent=small_style, fontName="Helvetica-Bold", fontSize=12, textColor=colors.white, alignment=1))]],
            colWidths=[46 * mm],
            rowHeights=[14 * mm],
        )
        header_right.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), CROWDSTRIKE_RED),
                    ("BOX", (0, 0), (-1, -1), 0, colors.white),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )

    header_table = Table([[header_left, header_right]], colWidths=[122 * mm, 48 * mm])
    header_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CROWDSTRIKE_PALE),
                ("BOX", (0, 0), (-1, -1), 0.8, CROWDSTRIKE_GRAY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (0, -1), 10),
                ("RIGHTPADDING", (0, 0), (0, -1), 10),
                ("LEFTPADDING", (1, 0), (1, -1), 2),
                ("RIGHTPADDING", (1, 0), (1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("ALIGN", (1, 0), (1, -1), "LEFT"),
            ]
        )
    )

    story = [header_table]

    summary_table = Table(
        [
            ["Protected endpoints", f"{total_endpoints}"],
            ["Human accounts", f"{category_counts['human']}"],
            ["Service accounts", f"{category_counts['service']}"],
            ["Admin accounts", f"{category_counts['admin']}"],
            ["Total active accounts", f"{total_active_accounts} ({human_percentage:.2f}% human)"],
        ],
        colWidths=[60 * mm, 110 * mm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 1, CROWDSTRIKE_GRAY),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, CROWDSTRIKE_GRAY),
                ("BACKGROUND", (0, 0), (0, -1), CROWDSTRIKE_BLACK),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("TEXTCOLOR", (1, 0), (1, -1), CROWDSTRIKE_BLACK),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 10))
    story.append(build_identity_chart(category_counts))
    story.append(Spacer(1, 10))
    story.append(build_endpoint_chart(domain_rows))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Active Directory Domains", heading_style))

    domain_table_data = [["Domain", "Endpoints", "Total", "Human", "Service", "Admin"]]
    for row in domain_rows:
        domain_table_data.append(
            [
                str(row["domain"]),
                str(row["endpoints"]),
                str(row["total"]),
                str(row["human"]),
                str(row["service"]),
                str(row["admin"]),
            ]
        )

    domain_table = Table(domain_table_data, colWidths=[58 * mm, 20 * mm, 20 * mm, 20 * mm, 22 * mm, 18 * mm])
    domain_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), CROWDSTRIKE_RED),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, CROWDSTRIKE_LIGHT]),
                ("BOX", (0, 0), (-1, -1), 1, CROWDSTRIKE_GRAY),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, CROWDSTRIKE_GRAY),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(domain_table)
    doc.build(story)


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
print(f"CSV output             : {csv_filename}")
print(f"PDF output             : {pdf_filename}")