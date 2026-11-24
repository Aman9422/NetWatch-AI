"""M20 demo script - a reproducible walkthrough of the base application (M20.14).

M20.14 asks for a **reproducible demonstration** of the released application. A
recording is not reproducible on its own: the operator has to remember which
interface they picked, which period they filtered, and which report they generated.
This script is the recipe.

It does not simulate anything. Every request it makes goes to a running backend over
real HTTP, and every figure it prints is the figure the API returned. Where a demo
step genuinely needs a human (starting the servers, choosing an authorised
interface, screen recording) the script prints the exact command and moves on rather
than pretending to have done it.

Usage::

    # With a backend already listening on 127.0.0.1:8000
    backend\\.venv\\Scripts\\python.exe backend\\scripts\\demo_m20.py

    # Point at another origin
    backend\\.venv\\Scripts\\python.exe backend\\scripts\\demo_m20.py --base-url http://127.0.0.1:8001

    # Only print the narration, make no requests
    backend\\.venv\\Scripts\\python.exe backend\\scripts\\demo_m20.py --dry-run

The script is read-only apart from the one report it generates, which it names so the
operator can find and delete it. It will not start or stop a capture: capture is the
step the operator is expected to perform live, on an interface they are authorised to
monitor.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
REQUEST_TIMEOUT_SECONDS = 15

# The demo's narration is a numbered sequence, matching M20.14's suggested order so
# a viewer can follow the document and the recording side by side.
STEPS: tuple[str, ...] = (
    "Introduce NetWatch AI",
    "Explain the application architecture",
    "Start the backend",
    "Start the frontend",
    "Select an authorised network interface",
    "Start packet capture",
    "Generate harmless network traffic",
    "Show real-time traffic updates",
    "Show device discovery",
    "Show connection tracking",
    "Demonstrate a controlled detection scenario",
    "Show the resulting alert",
    "Show the correlated incident",
    "Open analytics",
    "Generate a CSV report",
    "Generate a PDF report",
    "Download a report",
    "Show the testing and verification results",
    "Explain current limitations and future AI development",
)


@dataclass
class DemoState:
    """What the run has observed so far, so later steps can refer to real ids."""

    base_url: str
    interface: str | None = None
    capture_status: str | None = None
    packet_count: int | None = None
    device_count: int | None = None
    connection_count: int | None = None
    alert_ids: list[str] = field(default_factory=list)
    incident_ids: list[str] = field(default_factory=list)
    report_ids: dict[str, str] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)


def section(number: int) -> None:
    """Print one numbered demo step as a heading."""
    if 1 <= number <= len(STEPS):
        title = STEPS[number - 1]
    else:
        title = ""
    print(f"\n=== Step {number}: {title} ===")


def note(text: str) -> None:
    """Print an operator instruction the script cannot perform itself."""
    print(f"    [operator] {text}")


def row(label: str, value: object) -> None:
    """Print one measured value the API returned."""
    print(f"    {label:<26} {value}")


def request_json(
    base_url: str, path: str, *, method: str = "GET", body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    """Make one request and return ``(status, decoded body)``.

    Errors are returned rather than raised: a demo that stops on the first 404 has
    told the viewer nothing about the rest of the application. The caller decides
    whether a given status is a failure.
    """
    url = f"{base_url.rstrip('/')}{path}"
    payload = None
    headers = {"Accept": "application/json"}
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = error.code
    except urllib.error.URLError as error:
        return 0, {"transport_error": str(error.reason)}

    if not raw:
        return status, None
    try:
        return status, json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return status, None


def envelope_data(decoded: Any) -> dict[str, Any]:
    """Unwrap the one M13 response envelope, tolerating an already-flat body."""
    if isinstance(decoded, dict):
        data = decoded.get("data")
        if isinstance(data, dict):
            return data
        if "data" not in decoded:
            return decoded
    return {}


def list_total(data: dict[str, Any]) -> int | None:
    """Read a paginated listing's total, which is where the counts actually live."""
    for key in ("total", "count"):
        value = data.get(key)
        if isinstance(value, int):
            return value
    meta = data.get("meta")
    if isinstance(meta, dict):
        value = meta.get("total")
        if isinstance(value, int):
            return value
    for key in ("items", "results"):
        items = data.get(key)
        if isinstance(items, list):
            return len(items)
    return None


def first_list(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the first list of records in a listing body."""
    for key in ("items", "results", "packets", "devices", "connections", "alerts",
                "incidents", "reports", "detections", "notifications"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def identity_of(record: dict[str, Any]) -> str | None:
    """Read a record's identifier, whichever field this resource uses.

    Reports carry an integer ``report_id``; the other resources carry string ids.
    Both are rendered as text so a caller can build a URL without caring which.
    """
    for key in ("id", "alert_id", "incident_id", "report_id", "detection_id"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return None


def step_health(base_url: str, state: DemoState) -> None:
    """Step 3: the backend is up and reporting its own state."""
    section(3)
    status, decoded = request_json(base_url, "/api/v1/health")
    if status != 200:
        state.failures.append(f"health returned {status}")
        row("health", f"HTTP {status} - is the backend running?")
        return
    data = envelope_data(decoded)
    row("health", data.get("status", decoded))
    row("backend", base_url)

    status, version_body = request_json(base_url, "/api/v1/system/info")
    if status == 200:
        info = envelope_data(version_body)
        row("environment", info.get("environment", "-"))
        row("database", info.get("database", "-"))
    else:
        row("system info", f"HTTP {status} (optional surface)")


def step_interface(base_url: str, state: DemoState) -> None:
    """Step 5: enumerate interfaces and confirm which one is selected."""
    section(5)
    status, decoded = request_json(base_url, "/api/v1/capture/interfaces")
    if status != 200:
        state.failures.append(f"interfaces returned {status}")
        row("interfaces", f"HTTP {status}")
        return
    # This route returns the array as the whole ``data`` payload rather than
    # nesting it under a key, so the flat case is the normal one.
    decoded_data = decoded.get("data") if isinstance(decoded, dict) else None
    if isinstance(decoded_data, list):
        interfaces: list[Any] = decoded_data
    else:
        data = envelope_data(decoded)
        candidate = data.get("interfaces")
        interfaces = candidate if isinstance(candidate, list) else first_list(data)

    row("interfaces enumerated", len(interfaces))
    for item in interfaces[:8]:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "?")
        is_up = item.get("is_up")
        row(f"  {name}", "up" if is_up else "down")
    note("select one in the dashboard, or PUT /api/v1/capture/interface")


def step_capture(base_url: str, state: DemoState) -> None:
    """Step 6: report the capture state. The operator starts it; we only read it."""
    section(6)
    status, decoded = request_json(base_url, "/api/v1/capture/status")
    if status != 200:
        state.failures.append(f"capture status returned {status}")
        row("capture status", f"HTTP {status}")
        return
    data = envelope_data(decoded)
    state.capture_status = data.get("status")
    raw_count = data.get("packet_count")
    state.packet_count = raw_count if isinstance(raw_count, int) else None

    row("capture status", state.capture_status)
    row("interface", data.get("interface", state.interface or "-"))
    row("packets captured", state.packet_count)

    if state.capture_status != "running":
        note("start it in the dashboard, or POST /api/v1/capture/start")
        note("this script never starts capture: that is the operator's decision")
    else:
        note("capture is running - generate harmless traffic now, e.g. browsing")
        note("POST /api/v1/capture/start is idempotent-refused (409) if run twice")


def step_live_traffic(base_url: str, state: DemoState) -> None:
    """Step 8: prove the traffic figures are moving and are the backend's own."""
    section(8)
    # The statistics surface is /traffic, /protocols, /top-talkers and /ports.
    # Its snapshot is flat: totals and rates are top-level fields of ``data``.
    status, decoded = request_json(base_url, "/api/v1/statistics/traffic")
    if status != 200:
        state.failures.append(f"statistics/traffic returned {status}")
        row("statistics", f"HTTP {status}")
        return
    data = envelope_data(decoded)
    row("packets (total)", data.get("total_packets"))
    row("bytes (total)", data.get("total_bytes"))
    row("packets/sec", data.get("packets_per_second"))
    row("bytes/sec", data.get("bytes_per_second"))

    protocols = data.get("protocol_statistics")
    if isinstance(protocols, list):
        named = [
            f"{item.get('protocol', '?')}={item.get('packets', '?')}"
            for item in protocols[:6]
            if isinstance(item, dict)
        ]
        row("protocols", ", ".join(named) or "none yet")

    status, packets_body = request_json(base_url, "/api/v1/packets?limit=1")
    if status == 200:
        row("persisted packets", list_total(envelope_data(packets_body)))


def step_devices_and_connections(base_url: str, state: DemoState) -> None:
    """Steps 9 and 10: device discovery and conversation tracking."""
    section(9)
    status, decoded = request_json(base_url, "/api/v1/devices")
    if status == 200:
        data = envelope_data(decoded)
        state.device_count = list_total(data)
        row("devices discovered", state.device_count)
        for item in first_list(data)[:5]:
            row(
                f"  {item.get('ip_address', item.get('mac_address', '?'))}",
                f"{item.get('packet_count', 0)} packets",
            )
    else:
        state.failures.append(f"devices returned {status}")
        row("devices", f"HTTP {status}")

    section(10)
    status, decoded = request_json(base_url, "/api/v1/connections")
    if status == 200:
        data = envelope_data(decoded)
        state.connection_count = list_total(data)
        row("connections tracked", state.connection_count)
        for item in first_list(data)[:5]:
            source = item.get("source_address", item.get("source", "?"))
            dest = item.get("destination_address", item.get("destination", "?"))
            row(f"  {source} -> {dest}", item.get("state", "-"))
    else:
        state.failures.append(f"connections returned {status}")
        row("connections", f"HTTP {status}")


def step_detections_and_alerts(base_url: str, state: DemoState) -> None:
    """Steps 11 to 13: detections, alerts and the correlated incident."""
    section(11)
    status, decoded = request_json(base_url, "/api/v1/detections")
    if status == 200:
        data = envelope_data(decoded)
        row("detections", list_total(data))
        for item in first_list(data)[:5]:
            row(f"  {item.get('rule_name', '?')}", item.get("severity", "-"))
        if not first_list(data):
            note("no findings yet - a port scan raises one. See the design doc")
    else:
        state.failures.append(f"detections returned {status}")
        row("detections", f"HTTP {status}")

    section(12)
    status, decoded = request_json(base_url, "/api/v1/alerts")
    if status == 200:
        data = envelope_data(decoded)
        alerts = first_list(data)
        row("alerts", list_total(data))
        for item in alerts[:5]:
            identifier = identity_of(item)
            if identifier:
                state.alert_ids.append(identifier)
            row(
                f"  {item.get('title', item.get('rule_name', 'alert'))}",
                f"{item.get('severity', '-')} / {item.get('status', '-')}",
            )
        note("acknowledge, resolve, dismiss and false-positive are lifecycle actions")
        note("PATCH /api/v1/alerts/{id} carries the new status")
    else:
        state.failures.append(f"alerts returned {status}")
        row("alerts", f"HTTP {status}")

    section(13)
    status, decoded = request_json(base_url, "/api/v1/incidents")
    if status == 200:
        data = envelope_data(decoded)
        incidents = first_list(data)
        row("incidents", list_total(data))
        for item in incidents[:5]:
            identifier = identity_of(item)
            if identifier:
                state.incident_ids.append(identifier)
            row(
                f"  {item.get('title', identifier or 'incident')}",
                f"risk {item.get('risk_score', '-')} / {item.get('risk_band', '-')}",
            )
    else:
        state.failures.append(f"incidents returned {status}")
        row("incidents", f"HTTP {status}")


def step_analytics(base_url: str, state: DemoState) -> None:
    """Step 14: all five analytics views, each reporting its resolved period."""
    section(14)
    for name in ("traffic", "protocols", "devices", "connections", "threats"):
        status, decoded = request_json(base_url, f"/api/v1/analytics/{name}")
        if status != 200:
            state.failures.append(f"analytics/{name} returned {status}")
            row(f"analytics/{name}", f"HTTP {status}")
            continue
        data = envelope_data(decoded)
        candidate_period = data.get("period")
        period: dict[str, Any] = (
            candidate_period if isinstance(candidate_period, dict) else {}
        )
        # The resolved period is what the server actually queried: ``since`` and
        # ``until`` bounds plus a length. ``defaulted`` says whether the caller
        # supplied that range or the route filled it in, which is the difference
        # between "this is the window you asked for" and "this is the last hour".
        seconds = period.get("seconds")
        length = f"{int(seconds)}s" if isinstance(seconds, (int, float)) else "-"
        defaulted = " (defaulted)" if period.get("defaulted") else ""
        bounds = f"{period.get('since', '-')} .. {period.get('until', '-')}"
        row(f"analytics/{name}", f"{length}{defaulted}")
        row("  resolved period", bounds)

        # Live figures and stored figures are separate answers, and the stored one
        # can legitimately be unavailable. Reporting an unavailable value as zero
        # would be the one thing M16 forbids. Only some views carry a stored block,
        # and only some of those count packets: a view that does not answer the
        # question says so rather than printing a zero it never measured.
        stored = data.get("stored")
        if isinstance(stored, dict):
            if not stored.get("available"):
                row("  stored", f"unavailable: {stored.get('error', '-')}")
            else:
                stored_data = stored.get("data")
                count = (
                    stored_data.get("total_packets")
                    if isinstance(stored_data, dict)
                    else None
                )
                row(
                    "  stored packets",
                    count if count is not None else "not counted by this view",
                )
        else:
            row("  stored", "not reported by this view")


def step_reports(base_url: str, state: DemoState) -> None:
    """Steps 15 to 17: generate a CSV and a PDF, then confirm the files exist."""
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    start = yesterday.strftime("%Y-%m-%dT00:00:00Z")
    end = yesterday.strftime("%Y-%m-%dT23:59:59Z")

    # The request names its bounds ``since``/``until`` and spells the format in
    # upper case ("CSV"/"PDF"), matching the service's own vocabulary. A custom
    # report is the only type that accepts an explicit period; the presets derive
    # theirs from the UTC calendar and refuse one.
    for index, report_format in enumerate(("CSV", "PDF"), start=15):
        section(index)
        body = {
            "report_type": "custom",
            "format": report_format,
            "since": start,
            "until": end,
        }
        status, decoded = request_json(
            base_url, "/api/v1/reports/generate", method="POST", body=body
        )
        if status not in (200, 201, 202):
            row(f"generate {report_format}", f"HTTP {status}")
            errors = decoded.get("errors") if isinstance(decoded, dict) else None
            row("refused because", errors if errors else decoded)
            state.failures.append(f"report generate ({report_format}) returned {status}")
            continue
        # The generation response nests the new record under ``report`` alongside a
        # ``summary`` of the figures it wrote, so the id is one level deeper than a
        # listing's record.
        body_data = envelope_data(decoded)
        candidate_report = body_data.get("report")
        report: dict[str, Any] = (
            candidate_report if isinstance(candidate_report, dict) else body_data
        )
        identifier = identity_of(report)
        row(f"generate {report_format}", f"HTTP {status}")
        row("report id", identifier or "not returned")
        row("status", report.get("status", "-"))
        row("format", report.get("format", "-"))
        row("size (bytes)", report.get("file_size", "-"))
        row("downloadable", report.get("downloadable", "-"))
        if identifier:
            state.report_ids[report_format] = identifier

    section(17)
    for report_format, identifier in state.report_ids.items():
        status, decoded = request_json(base_url, f"/api/v1/reports/{identifier}")
        if status == 200:
            data = envelope_data(decoded)
            row(
                f"metadata ({report_format})",
                f"{data.get('status', '-')} / {data.get('file_size', '-')} bytes "
                f"/ downloadable={data.get('downloadable', '-')}",
            )
        else:
            state.failures.append(f"report metadata {identifier} returned {status}")
            row(f"metadata ({report_format})", f"HTTP {status}")

        download = f"/api/v1/reports/{identifier}/download"
        row(f"download ({report_format})", f"{base_url}{download}")
    note("open the downloaded files: a report is not generated until the artifact exists")


def step_verification(base_url: str, state: DemoState) -> None:
    """Step 18: the numbers a viewer should be shown, and where they come from."""
    section(18)
    row("quality gates", "run_quality_gates.py --full")
    note("the release record in docs/24 carries the measured counts")
    note("do not restate M19's counts: run the gates on this build")
    status, decoded = request_json(base_url, "/api/v1/system/info")
    if status == 200:
        info = envelope_data(decoded)
        row("version", info.get("version", "-"))


def step_limitations() -> None:
    """Step 19: what the recording must not claim."""
    section(19)
    note("no authentication, no RBAC, no TLS: local single-operator scope only")
    note("rule-based detection: five rules, not every malicious behaviour")
    note("behavioural baselines, ML, local LLM and the AI analyst are NOT implemented")
    note("WebSocket events are not replayed: a reconnect starts fresh counters")


def run(base_url: str, dry_run: bool) -> int:
    """Walk the demo sequence and return a process exit code."""
    state = DemoState(base_url=base_url)

    print("NetWatch AI - base application demo")
    print(f"Target: {base_url}")
    if dry_run:
        print("Mode:   dry run (no requests will be made)\n")

    section(1)
    row("what", "local-first network monitoring and security analysis")
    row("scope", "one machine, one operator, no cloud")
    section(2)
    row("backend", "FastAPI + SQLAlchemy + Scapy, SQLite store")
    row("frontend", "React + TypeScript + Vite")
    row("transport", "REST under /api/v1, four WebSocket channels")
    note("capture -> processing -> statistics -> persistence -> devices ->")
    note("connections -> detection -> alerts -> correlation -> risk -> API -> UI")
    section(4)
    note("npm run dev  (Vite serves http://localhost:8443)")

    if dry_run:
        # A dry run prints the framing only, but Step 19 is still shown: the
        # limitation statement is part of the demo rather than a footnote to it.
        step_limitations()
        print("\ndry run complete: no request was made")
        return 0

    step_health(base_url, state)
    step_interface(base_url, state)
    step_capture(base_url, state)
    section(7)
    note("generate harmless traffic: browse a site, or ping a host you own")
    step_live_traffic(base_url, state)
    step_devices_and_connections(base_url, state)
    step_detections_and_alerts(base_url, state)
    step_analytics(base_url, state)
    step_reports(base_url, state)
    step_verification(base_url, state)
    step_limitations()

    print()
    if state.failures:
        print(f"RESULT: {len(state.failures)} problem(s) reached")
        for failure in state.failures:
            print(f"  - {failure}")
        return 1
    print("RESULT: demo sequence completed against a live backend")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and run the demo."""
    parser = argparse.ArgumentParser(
        description="Reproducible NetWatch AI base-application demo (M20.14)."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Backend origin (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the narration without making any request",
    )
    arguments = parser.parse_args(argv)
    return run(arguments.base_url, arguments.dry_run)


if __name__ == "__main__":
    sys.exit(main())
