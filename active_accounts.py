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
import struct
import subprocess
import threading
import time
import zlib
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
            "FALCON_CLIENT_SECRET (leave blank to keep current): "
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

            print(colorize("Running pre-flight check: failed.", ANSI_RED))
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

        print(colorize("Running pre-flight check: failed.", ANSI_RED))
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


def _escape_pdf_text(value: str) -> str:
    sanitized = value.encode("latin-1", "replace").decode("latin-1")
    return sanitized.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_rgb(hex_color: str) -> tuple[float, float, float]:
    value = hex_color.lstrip("#")
    return tuple(int(value[index:index + 2], 16) / 255 for index in (0, 2, 4))


def _pdf_fill_rect(x: float, y: float, width: float, height: float, hex_color: str) -> str:
    red, green, blue = _pdf_rgb(hex_color)
    return f"q {red:.3f} {green:.3f} {blue:.3f} rg {x:.2f} {y:.2f} {width:.2f} {height:.2f} re f Q"


def _pdf_stroke_rect(x: float, y: float, width: float, height: float, hex_color: str, line_width: float = 1.0) -> str:
    red, green, blue = _pdf_rgb(hex_color)
    return f"q {line_width:.2f} w {red:.3f} {green:.3f} {blue:.3f} RG {x:.2f} {y:.2f} {width:.2f} {height:.2f} re S Q"


def _pdf_text(x: float, y: float, text: str, *, font: str = "F1", size: int = 11, hex_color: str = "#1A1A1A") -> str:
    red, green, blue = _pdf_rgb(hex_color)
    return (
        "BT "
        f"/{font} {size} Tf "
        f"{red:.3f} {green:.3f} {blue:.3f} rg "
        f"1 0 0 1 {x:.2f} {y:.2f} Tm "
        f"({_escape_pdf_text(text)}) Tj ET"
    )


def _pdf_line(x1: float, y1: float, x2: float, y2: float, hex_color: str, line_width: float = 1.0) -> str:
    red, green, blue = _pdf_rgb(hex_color)
    return f"q {line_width:.2f} w {red:.3f} {green:.3f} {blue:.3f} RG {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q"


def _png_paeth(left: int, up: int, up_left: int) -> int:
    predictor = left + up - up_left
    left_distance = abs(predictor - left)
    up_distance = abs(predictor - up)
    up_left_distance = abs(predictor - up_left)
    if left_distance <= up_distance and left_distance <= up_left_distance:
        return left
    if up_distance <= up_left_distance:
        return up
    return up_left


def _load_png_for_pdf(path: Path) -> dict[str, int | bytes] | None:
    if not path.exists():
        return None

    payload = path.read_bytes()
    if payload[:8] != b"\x89PNG\r\n\x1a\n":
        return None

    offset = 8
    width = height = bit_depth = color_type = interlace = 0
    idat_parts: list[bytes] = []

    while offset + 8 <= len(payload):
        chunk_length = struct.unpack(">I", payload[offset:offset + 4])[0]
        chunk_type = payload[offset + 4:offset + 8]
        chunk_data_start = offset + 8
        chunk_data_end = chunk_data_start + chunk_length
        chunk_data = payload[chunk_data_start:chunk_data_end]
        offset = chunk_data_end + 4

        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", chunk_data)
        elif chunk_type == b"IDAT":
            idat_parts.append(chunk_data)
        elif chunk_type == b"IEND":
            break

    if not width or not height or bit_depth != 8 or interlace != 0 or color_type not in (2, 6):
        return None

    channels = 3 if color_type == 2 else 4
    stride = width * channels
    decompressed = zlib.decompress(b"".join(idat_parts))
    row_length = stride + 1
    expected_length = row_length * height
    if len(decompressed) != expected_length:
        return None

    rows: list[bytes] = []
    previous = bytearray(stride)

    for row_index in range(height):
        start = row_index * row_length
        filter_type = decompressed[start]
        current = bytearray(decompressed[start + 1:start + row_length])

        for index in range(stride):
            left = current[index - channels] if index >= channels else 0
            up = previous[index]
            up_left = previous[index - channels] if index >= channels else 0

            if filter_type == 0:
                pass
            elif filter_type == 1:
                current[index] = (current[index] + left) & 0xFF
            elif filter_type == 2:
                current[index] = (current[index] + up) & 0xFF
            elif filter_type == 3:
                current[index] = (current[index] + ((left + up) // 2)) & 0xFF
            elif filter_type == 4:
                current[index] = (current[index] + _png_paeth(left, up, up_left)) & 0xFF
            else:
                return None

        previous = current
        rows.append(bytes(current))

    rgb_bytes = bytearray()
    if color_type == 2:
        for row in rows:
            rgb_bytes.extend(row)
    else:
        for row in rows:
            for index in range(0, len(row), 4):
                red, green, blue, alpha = row[index:index + 4]
                rgb_bytes.extend(
                    (
                        (red * alpha + 255 * (255 - alpha)) // 255,
                        (green * alpha + 255 * (255 - alpha)) // 255,
                        (blue * alpha + 255 * (255 - alpha)) // 255,
                    )
                )

    return {
        "width": width,
        "height": height,
        "data": zlib.compress(bytes(rgb_bytes)),
    }


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
    light_bg = "#F1F1F1"
    gray = "#D9D9D9"
    mid = "#7A7A7A"
    dark = "#1A1A1A"
    red = "#E01E26"
    white = "#FFFFFF"

    summary_rows = [
        ("Protected endpoints", f"{total_endpoints}"),
        ("Human accounts", f"{category_counts['human']}"),
        ("Service accounts", f"{category_counts['service']}"),
        ("Admin accounts", f"{category_counts['admin']}"),
        ("Total active accounts", f"{total_active_accounts} ({human_percentage:.2f}% human)"),
    ]

    chart_rows = sorted(
        [
            ("Human", category_counts["human"]),
            ("Service", category_counts["service"]),
            ("Admin", category_counts["admin"]),
        ],
        key=lambda item: (-item[1], item[0]),
    )

    domain_table_rows = [
        [
            str(row["domain"]),
            str(row["endpoints"]),
            str(row["total"]),
            str(row["human"]),
            str(row["service"]),
            str(row["admin"]),
        ]
        for row in domain_rows
    ] or [["No domains found", "-", "-", "-", "-", "-"]]

    logo_image = _load_png_for_pdf(LOGO_PATH)
    page_width = 595
    page_height = 842
    margin = 36
    table_x = margin
    domain_col_widths = [220, 55, 50, 50, 60, 50]

    page_commands: list[str] = []
    commands: list[str] = []

    header_y = 706
    header_height = 104
    commands.append(_pdf_fill_rect(36, header_y, 523, header_height, light_bg))
    commands.append(_pdf_stroke_rect(36, header_y, 523, header_height, gray, 1.0))
    commands.append(_pdf_text(52, 782, f"CrowdStrike Falcon Tenant Report v{APP_VERSION}", font="F2", size=20, hex_color=red))
    commands.append(_pdf_text(52, 750, f"Tenant: {tenant_label}", font="F2", size=10, hex_color=dark))
    commands.append(_pdf_text(52, 730, f"CID: {cid_value}", size=10, hex_color=dark))
    commands.append(_pdf_text(52, 710, f"Generated: {current_timestamp}", size=10, hex_color=dark))

    image_name = None
    if logo_image:
        image_name = "Im1"
        max_width = 132
        max_height = 28
        image_width = int(logo_image["width"])
        image_height = int(logo_image["height"])
        scale = min(max_width / image_width, max_height / image_height)
        draw_width = image_width * scale
        draw_height = image_height * scale
        x = 541 - draw_width
        y = 782 - draw_height / 2
        commands.append(f"q {draw_width:.2f} 0 0 {draw_height:.2f} {x:.2f} {y:.2f} cm /{image_name} Do Q")
    else:
        commands.append(_pdf_fill_rect(419, 765, 124, 30, red))
        commands.append(_pdf_text(433, 776, "CROWDSTRIKE", font="F2", size=12, hex_color=white))

    summary_y = 654
    row_height = 22
    label_width = 170
    value_width = 335
    for index, (label, value) in enumerate(summary_rows):
        y = summary_y - index * row_height
        commands.append(_pdf_fill_rect(table_x, y, label_width, row_height, dark))
        commands.append(_pdf_fill_rect(table_x + label_width, y, value_width, row_height, white))
        commands.append(_pdf_stroke_rect(table_x, y, label_width + value_width, row_height, gray, 0.7))
        commands.append(_pdf_text(table_x + 8, y + 8, label, font="F2", size=10, hex_color=white))
        commands.append(_pdf_text(table_x + label_width + 8, y + 8, value, font="F2", size=10, hex_color=dark))

    chart_box_y = 394
    chart_box_height = 126
    chart_origin_x = 176
    chart_origin_y = 418
    chart_bar_height = 18
    chart_gap = 14
    chart_max_width = 290
    max_chart_value = max((value for _, value in chart_rows), default=0)

    commands.append(_pdf_fill_rect(36, chart_box_y, 523, chart_box_height, white))
    commands.append(_pdf_stroke_rect(36, chart_box_y, 523, chart_box_height, gray, 0.8))
    commands.append(_pdf_text(52, 500, "Active Accounts", font="F2", size=12, hex_color=dark))
    commands.append(_pdf_text(52, 484, "Bar chart sorted by highest account count first.", size=9, hex_color=mid))

    for index, (label, value) in enumerate(chart_rows):
        y = chart_origin_y + (2 - index) * (chart_bar_height + chart_gap)
        bar_width = (value / max_chart_value * chart_max_width) if max_chart_value else 0
        commands.append(_pdf_text(52, y + 4, label, font="F2", size=10, hex_color=dark))
        commands.append(_pdf_fill_rect(chart_origin_x, y, chart_max_width, chart_bar_height, light_bg))
        commands.append(_pdf_fill_rect(chart_origin_x, y, bar_width, chart_bar_height, red))
        commands.append(_pdf_stroke_rect(chart_origin_x, y, chart_max_width, chart_bar_height, gray, 0.6))
        commands.append(_pdf_text(chart_origin_x + chart_max_width + 10, y + 4, str(value), font="F2", size=10, hex_color=dark))

    commands.append(_pdf_line(52, 386, 543, 386, gray, 0.8))
    commands.append(_pdf_text(36, 362, "Active Directory Domains", font="F2", size=12, hex_color=dark))

    table_start_y = 332
    header_row_height = 22
    body_height = 18

    def add_domain_table_header(target: list[str], y: float) -> None:
        labels = ["Domain", "Endpoints", "Total", "Human", "Service", "Admin"]
        current_x = table_x
        for label, width in zip(labels, domain_col_widths):
            target.append(_pdf_fill_rect(current_x, y, width, header_row_height, red))
            target.append(_pdf_stroke_rect(current_x, y, width, header_row_height, gray, 0.6))
            target.append(_pdf_text(current_x + 6, y + 7, label, font="F2", size=9, hex_color=white))
            current_x += width

    add_domain_table_header(commands, table_start_y)

    available_rows_first_page = max(0, int((table_start_y - 56) // body_height) - 1)
    first_page_rows = domain_table_rows[:available_rows_first_page]
    remaining_rows = domain_table_rows[available_rows_first_page:]

    def add_domain_rows(target: list[str], rows: list[list[str]], start_y: float) -> None:
        for row_index, row in enumerate(rows):
            y = start_y - (row_index + 1) * body_height
            fill = white if row_index % 2 == 0 else light_bg
            current_x = table_x
            for cell, width in zip(row, domain_col_widths):
                target.append(_pdf_fill_rect(current_x, y, width, body_height, fill))
                target.append(_pdf_stroke_rect(current_x, y, width, body_height, gray, 0.5))
                target.append(_pdf_text(current_x + 5, y + 5, str(cell)[:34], size=8, hex_color=dark))
                current_x += width

    add_domain_rows(commands, first_page_rows, table_start_y)
    page_commands.append("\n".join(commands))

    rows_per_other_page = 38
    while remaining_rows:
        commands = []
        add_domain_table_header(commands, 780)
        page_rows = remaining_rows[:rows_per_other_page]
        remaining_rows = remaining_rows[rows_per_other_page:]
        add_domain_rows(commands, page_rows, 780)
        page_commands.append("\n".join(commands))

    if not page_commands:
        page_commands = ["\n".join(commands)]

    objects: list[bytes] = []
    page_object_numbers: list[int] = []
    image_object_number = None

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    if logo_image:
        image_object_number = len(objects) + 1
        image_stream = bytes(logo_image["data"])
        objects.append(
            (
                f"<< /Type /XObject /Subtype /Image /Width {int(logo_image['width'])} /Height {int(logo_image['height'])} "
                f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {len(image_stream)} >>\nstream\n"
            ).encode("ascii")
            + image_stream
            + b"\nendstream"
        )

    for command_stream in page_commands:
        stream_bytes = command_stream.encode("latin-1", "replace")
        page_object_number = len(objects) + 1
        content_object_number = page_object_number + 1
        page_object_numbers.append(page_object_number)

        resources = "/Font << /F1 3 0 R /F2 4 0 R >>"
        if image_object_number is not None and image_name:
            resources += f" /XObject << /{image_name} {image_object_number} 0 R >>"

        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_width} {page_height}] "
                f"/Resources << {resources} >> /Contents {content_object_number} 0 R >>"
            ).encode("ascii")
        )
        objects.append(
            b"<< /Length " + str(len(stream_bytes)).encode("ascii") + b" >>\nstream\n" + stream_bytes + b"\nendstream"
        )

    kids = " ".join(f"{number} 0 R" for number in page_object_numbers)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_numbers)} >>".encode("ascii")

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

spinner.update(f"Tenant name: {tenant_label} | CID: {cid_value}")

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