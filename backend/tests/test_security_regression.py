"""Defensive security regression tests (M18.11).

A regression suite rather than a penetration test: every assertion here pins a
defensive property the application already claims, so a future change that weakens
one fails a test instead of reaching an operator.

The scope is exactly what M18.11 lists, and four of those items had no test at all
before this file:

* **CSV formula injection.** A report is opened in a spreadsheet, and a spreadsheet
  evaluates a cell beginning ``=``, ``+``, ``-`` or ``@``. Report values include the
  caller-supplied title, so the file was an execution surface. ``guard_cell`` in
  :mod:`app.reports.csv_renderer` closes it, and this file proves the guard at the
  function, at the renderer and through the real API. **This test file found the
  defect and is the reason the guard exists**, not a description of a property
  that was always true.
* **SQL parameterisation.** Every store in this application goes through
  SQLAlchemy's bound parameters, so a hostile filter value is data rather than
  SQL. Nothing exercised that, so a future hand-written ``text()`` interpolation
  would have been invisible. The tests here drive injection payloads through the
  real routes and assert both that no request is a ``500`` and that the schema is
  still intact afterwards.

  A refusal *does* echo the value it rejected (``''; DROP TABLE alerts; --' is not
  a valid severity``), so the body of a rejection contains the caller's own
  payload. That is the caller's input and discloses nothing internal -- the leak
  check subtracts it before scanning for an internal, which is the difference
  between testing the application and testing the caller's typing. The subtraction
  ignores case, because a route may normalise a filter before it validates it.

  One shape is deliberately *not* the application envelope: a request-validation
  failure is FastAPI's own ``{"detail": [...]}`` list (M13.6, restated by
  ``tests/test_api_contract.py``). It is more useful as per-field detail, and it
  carries nothing but the field, the constraint and the input that was sent.
* **PDF rendering of untrusted text.** ReportLab's paragraph layer parses an
  XML-like markup, so a value containing ``<`` would either vanish or raise. The
  renderer escapes at the one point text enters the parser; this file is the test
  of that claim.
* **Oversized and malformed input.** Bounded so a long value or an absurd page
  size is a refusal rather than an exception.

What is *not* re-tested here, because a dedicated file already owns it:

* report download containment and path traversal -- ``tests/test_reports_storage.py``
  and ``tests/test_reports_api.py``
* secret withholding on ``/settings`` and ``/system`` -- ``tests/test_settings_api.py``
  and ``tests/test_system_api.py``
* the opaque ``500`` envelope -- ``tests/test_api_contract.py``
* oversized WebSocket frames -- ``tests/test_ws_endpoints.py``
* malformed packets -- ``tests/test_packet_processor.py`` and
  ``tests/test_capture_sniffer.py``

**Authentication and RBAC are not implemented** (M13 is a local application API by
design, and M18.11 asks for that to be stated rather than implied). Nothing in this
file asserts that a caller is authorised, because no caller is: the properties
tested are the ones that hold for an unauthenticated local API -- input validation,
parameterised queries, filesystem containment and bounded resources. This
application is **not** fit for a public or multi-user deployment, and a green run
here is not a claim that it is.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Callable, Generator, Iterable
from pathlib import Path
from xml.sax.saxutils import escape

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.analytics.service import AnalyticsService
from app.api.v1.deps import get_analytics_service, get_report_service
from app.database.session import get_db
from app.reports.content import Metric, ReportContent, ReportSection, ReportTable
from app.reports.csv_renderer import (
    FORMULA_GUARD,
    FORMULA_TRIGGER_CHARS,
    guard_cell,
    render_csv,
)
from app.reports.pdf_renderer import _paragraph, _styles, render_pdf
from app.reports.service import ReportService
from app.reports.storage import ReportStorage
from tests.m13_fakes import api_client, make_db_override

REPORTS_URL = "/api/v1/reports"
GENERATE_URL = f"{REPORTS_URL}/generate"

#: A PDF below this size is not a document with content in it. A single A4 page of
#: headings and one table is comfortably larger; this only rejects an empty stub.
MINIMUM_PDF_BYTES = 1_000

#: Payloads that would matter if any store built SQL by concatenation. Each is the
#: value a filter parameter is sent with; none of them is a valid member of any
#: vocabulary the API accepts, so a refusal is the expected answer.
INJECTION_PAYLOADS: tuple[str, ...] = (
    "' OR '1'='1",
    "'; DROP TABLE alerts; --",
    "1; DELETE FROM devices",
    "' UNION SELECT password FROM users --",
    "'; UPDATE settings SET value='x' --",
)

#: Substrings that must never appear in a response body. A leaked statement, a
#: driver name, a tablespace or a traceback all mean the boundary failed.
LEAK_MARKERS: tuple[str, ...] = (
    "Traceback",
    "sqlalchemy",
    "SQLAlchemy",
    "sqlite3",
    "OperationalError",
    "ProgrammingError",
    "IntegrityError",
    "SELECT ",
    "INSERT INTO",
    "DELETE FROM",
    "DROP TABLE",
    "File \"",
    "site-packages",
)


def without(text: str, value: str) -> str:
    """Return ``text`` with every occurrence of ``value`` removed, ignoring case.

    Case is ignored because a route may normalise a filter before it validates:
    ``/connections?protocol=`` upper-cases its value, so what a 422 echoes back is
    not byte-identical to what was sent. Subtracting only the exact bytes would
    leave the caller's own payload in the body and the leak check would fail on it.
    """
    if not value:
        return text
    return re.sub(re.escape(value), "", text, flags=re.IGNORECASE)


def leaks_internals(body: str, sent: Iterable[str] = ()) -> bool:
    """Return True when a response body carries an internal this API must not show.

    ``sent`` is the caller's own input. A validation refusal legitimately echoes the
    value it rejected, so the caller's payload is removed before the scan: without
    that subtraction the check fails on the caller's own text rather than on a
    disclosure, which is exactly the false positive this parameter exists to avoid.
    Everything left in the body is therefore the application's own words.

    The subtraction ignores case (:func:`without`); the scan does not. A statement
    the driver leaked is rendered in upper case, while ordinary prose about a filter
    ("select a valid protocol") is not -- so keeping the scan case-sensitive is what
    lets a test match the first without tripping on the second.
    """
    inspected = body
    for value in sent:
        inspected = without(inspected, value)
    return any(marker in inspected for marker in LEAK_MARKERS)


@pytest.fixture
def client(db_engine) -> Generator[TestClient, None, None]:
    """A client over an isolated in-memory database (never the real one)."""
    overrides = {get_db: make_db_override(db_engine)}
    with api_client(overrides) as test_client:
        yield test_client


def report_service_override(directory: str) -> Callable[..., ReportService]:
    """Return a ``get_report_service`` override writing into ``directory``.

    The service is built from the *request's* own session and the analytics service
    over it -- everything except the storage directory is what the application
    builds, so the route under test is the real route.
    """

    def override(
        db: Session = Depends(get_db),
        analytics: AnalyticsService = Depends(get_analytics_service),
    ) -> ReportService:
        return ReportService(
            db=db, analytics=analytics, storage=ReportStorage(directory)
        )

    return override


@pytest.fixture
def generating(tmp_path: Path, db_engine) -> Generator[TestClient, None, None]:
    """A client whose report artifacts land in a temporary directory.

    Nothing here writes to the developer's configured ``reports/`` directory.
    """
    overrides = {
        get_db: make_db_override(db_engine),
        get_report_service: report_service_override(str(tmp_path / "artifacts")),
    }
    with api_client(overrides) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# CSV formula injection (M18.11) -- the defect this milestone found
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("trigger", FORMULA_TRIGGER_CHARS)
def test_a_value_a_spreadsheet_would_evaluate_is_guarded(trigger: str) -> None:
    """Each trigger character is prefixed, so no cell can be a formula.

    ``\t`` and ``\r`` are in the set because some importers strip a leading
    control character and then read whatever follows it as the cell's first
    character -- which would expose the ``=`` behind it.
    """
    guarded = guard_cell(f"{trigger}SUM(1)")

    assert guarded == f"{FORMULA_GUARD}{trigger}SUM(1)"
    assert guarded.startswith(FORMULA_GUARD)


def test_the_guarded_value_still_carries_the_original_text() -> None:
    """The guard prefixes; it never drops or rewrites what the value said."""
    original = "=cmd|'/C calc'!A0"

    assert guard_cell(original) == FORMULA_GUARD + original


def test_an_ordinary_value_is_not_altered() -> None:
    """A guard that mangled ordinary values would make every report wrong."""
    for value in (
        "10.0.0.5",
        "TCP",
        "1,234",
        "45.2%",
        "not reported",
        "n/a",
        "###",
        "2026-10-09T00:00:00+00:00",
        "Daily network report 2026-10-09 (CSV)",
    ):
        assert guard_cell(value) == value


@pytest.mark.parametrize("number", ["-12", "+3", "-1.5", "+0.25", "-1e6", "0", "-0"])
def test_a_signed_number_is_left_alone(number: str) -> None:
    """``-12`` is a figure, not a formula, and guarding it would stop it summing.

    This is the one place where the guard has to know what it is looking at: a
    spreadsheet reads a signed number as a number, so prefixing one would turn a
    real figure into text. Any other value beginning with ``-`` is guarded.
    """
    assert guard_cell(number) == number


def test_a_minus_that_is_not_a_number_is_guarded() -> None:
    """The numeric exemption is narrow: it does not open a hole."""
    for value in ("-1+cmd", "- ", "-@SUM(1)", "-cmd|'/C calc'!A0"):
        assert guard_cell(value).startswith(FORMULA_GUARD)


def test_an_empty_value_is_not_guarded() -> None:
    """A prefix on an empty cell would invent content that was not there."""
    assert guard_cell("") == ""


def test_a_non_string_cell_is_guarded_the_same_way() -> None:
    """``writerow`` receives whatever the block helper produced; none of it raises."""
    assert guard_cell(None) == "None"
    assert guard_cell(0) == "0"
    assert guard_cell(-1) == "-1"
    assert guard_cell(1.5) == "1.5"


def test_the_trigger_set_is_closed_and_documented() -> None:
    """The rule has one definition, so a reader can see exactly what is guarded."""
    assert FORMULA_TRIGGER_CHARS == ("=", "+", "-", "@", "\t", "\r")
    assert FORMULA_GUARD == "'"


def _hostile_content() -> ReportContent:
    """A report whose every string field carries a formula payload."""
    payload = "=cmd|'/C calc'!A0"
    return ReportContent(
        report_id=1,
        title=payload,
        report_type="daily",
        output_format="CSV",
        generated_at="2026-10-09T00:00:00+00:00",
        period_start="2026-10-09T00:00:00+00:00",
        period_end="2026-10-10T00:00:00+00:00",
        period_seconds=86400.0,
        summary=(Metric(label=payload, value=payload),),
        sections=(
            ReportSection(
                key="traffic",
                title=payload,
                metrics=(Metric(label=payload, value=payload),),
                tables=(
                    ReportTable(
                        key="top_sources",
                        title=payload,
                        columns=(payload, payload),
                        rows=((payload, payload),),
                    ),
                ),
            ),
        ),
    )


def _parsed_cells(payload: bytes) -> list[list[str]]:
    """Return a rendered CSV as rows of cells."""
    return list(csv.reader(io.StringIO(payload.decode("utf-8"), newline="")))


def test_a_report_title_cannot_be_evaluated_by_a_spreadsheet() -> None:
    """The end-to-end renderer claim: not one exported cell is a formula.

    Checked by reading the file back with a CSV reader and inspecting every cell,
    rather than by matching a literal, because what matters is what a spreadsheet
    would see after parsing.
    """
    rows = _parsed_cells(render_csv(_hostile_content()))

    evaluated = [
        (index, cell)
        for index, row in enumerate(rows, start=1)
        for cell in row
        if cell and cell[0] in FORMULA_TRIGGER_CHARS
    ]
    assert evaluated == []


def test_the_guarded_report_is_still_a_readable_csv() -> None:
    """The guard must not break the block structure it was added to protect.

    A mitigation that produced an unparseable file would trade a security defect
    for a correctness one, so the block markers are re-asserted here.
    """
    payload = render_csv(_hostile_content())
    rows = _parsed_cells(payload)

    markers = [row[1] for row in rows if len(row) == 2 and row[0] == "###"]
    assert markers[0] == "report"
    assert "section:traffic" in markers
    assert "table:traffic.top_sources" in markers
    assert payload.decode("utf-8").endswith("\r\n")


def test_the_title_cell_carries_the_guard_and_the_original_text() -> None:
    """Both halves are asserted: the guard is present, and nothing was lost."""
    rows = _parsed_cells(render_csv(_hostile_content()))
    report = {
        row[0]: row[1] for row in rows[1 : rows.index(["###", "section:traffic"])]
    }

    assert report["title"] == FORMULA_GUARD + "=cmd|'/C calc'!A0"


def test_an_api_generated_report_guards_a_hostile_title(
    generating: TestClient,
) -> None:
    """The guard holds through the real route, not only through the renderer.

    This is the path an operator actually takes -- a title supplied to
    ``POST /reports/generate``, a CSV downloaded, a spreadsheet opened -- so it is
    the one that has to be proven.
    """
    outcome = generating.post(
        GENERATE_URL,
        json={
            "report_type": "daily",
            "format": "CSV",
            "title": "=cmd|'/C calc'!A0",
        },
    )
    assert outcome.status_code == 201
    report_id = outcome.json()["data"]["report"]["report_id"]

    download = generating.get(f"{REPORTS_URL}/{report_id}/download")
    assert download.status_code == 200

    rows = _parsed_cells(download.content)
    titles = [row[1] for row in rows if len(row) == 2 and row[0] == "title"]
    assert titles == [FORMULA_GUARD + "=cmd|'/C calc'!A0"]

    # And nothing anywhere in the artifact would be evaluated.
    assert not [
        cell
        for row in rows
        for cell in row
        if cell and cell[0] in FORMULA_TRIGGER_CHARS
    ]


def test_a_pdf_of_a_hostile_title_is_still_produced(generating: TestClient) -> None:
    """The PDF path is unaffected: it escapes rather than guards, and must work."""
    outcome = generating.post(
        GENERATE_URL,
        json={"report_type": "daily", "format": "PDF", "title": "<b>&=title"},
    )
    assert outcome.status_code == 201

    report_id = outcome.json()["data"]["report"]["report_id"]
    download = generating.get(f"{REPORTS_URL}/{report_id}/download")

    assert download.status_code == 200
    assert download.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# SQL parameterisation (M18.11)
# ---------------------------------------------------------------------------

#: The endpoints an injection payload is driven through, each with the parameter
#: its store would use if it built SQL by hand. The payloads are deliberately not
#: valid members of any vocabulary the API accepts, so the *expected* answer is a
#: refusal or an empty selection -- never a match, and never a fault.
INJECTION_TARGETS: tuple[tuple[str, str], ...] = (
    ("/api/v1/alerts", "severity"),
    ("/api/v1/alerts", "since"),
    ("/api/v1/alerts", "status"),
    ("/api/v1/packets", "protocol"),
    ("/api/v1/packets", "source_ip"),
    ("/api/v1/devices", "ip"),
    ("/api/v1/devices", "status"),
    ("/api/v1/connections", "protocol"),
)


@pytest.mark.parametrize("path,param", INJECTION_TARGETS)
@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_an_injection_payload_is_never_a_server_error(
    client: TestClient, path: str, param: str, payload: str
) -> None:
    """A hostile filter value is refused or selects nothing -- it never faults.

    A ``500`` here would mean the value reached a statement and the driver
    rejected it, which is the signature of string-built SQL. Every store in this
    application goes through SQLAlchemy's bound parameters, so the value is data.
    """
    response = client.get(path, params={param: payload})

    assert response.status_code < 500, response.text
    assert response.status_code in (200, 400, 422), response.text


@pytest.mark.parametrize("path,param", INJECTION_TARGETS)
@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_a_hostile_filter_value_selects_nothing_rather_than_everything(
    client: TestClient, path: str, param: str, payload: str
) -> None:
    """A payload that is silently accepted must not widen the result set.

    This is the shape a successful injection takes when the quote is escaped but
    the value is still concatenated: ``' OR '1'='1`` turns a filter into a
    tautology and returns every row. Nothing in this application may do that, so a
    ``200`` is required to carry an empty collection.
    """
    response = client.get(path, params={param: payload})
    if response.status_code != 200:
        return  # A refusal is an equally good answer and is asserted above.

    data = response.json()["data"]
    collection = next(
        (
            value
            for key, value in data.items()
            if isinstance(value, list) and key not in {"unavailable_sections"}
        ),
        [],
    )
    assert collection == [], response.text


@pytest.mark.parametrize("path,param", INJECTION_TARGETS)
def test_a_hostile_filter_value_never_reaches_the_response_body(
    client: TestClient, path: str, param: str
) -> None:
    """Rejecting a payload must not echo a statement or a driver error back.

    The body is checked rather than the message alone, because a leaked statement
    can ride in a ``detail`` field as easily as in ``message`` (M13.30).
    """
    payload = "'; DROP TABLE alerts; --"

    response = client.get(path, params={param: payload})

    assert not leaks_internals(response.text, sent=[payload]), response.text


def test_an_injection_attempt_leaves_the_schema_intact(
    client: TestClient, db_engine
) -> None:
    """The tables are still there after the payloads have been sent.

    A dropped table is the outcome the payloads ask for, and the only way to know
    it did not happen is to look. The counts are asserted as well as the names,
    because a ``DELETE`` leaves the name behind.
    """
    before = set(inspect(db_engine).get_table_names())

    for path, param in INJECTION_TARGETS:
        for payload in INJECTION_PAYLOADS:
            client.get(path, params={param: payload})

    after = set(inspect(db_engine).get_table_names())
    assert after == before
    assert {"alerts", "devices", "packets", "settings"}.issubset(after)

    with db_engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM alerts")).scalar() == 0


def test_a_path_parameter_is_never_treated_as_sql(client: TestClient) -> None:
    """An id in the path is a value, so a statement in it is a 404 or a 422.

    A path segment is the other place a hand-written statement would interpolate,
    and a non-numeric id is refused by request validation before a route runs.
    """
    for payload in INJECTION_PAYLOADS:
        response = client.get(f"/api/v1/devices/{payload}")
        assert response.status_code in (404, 422), response.text
        assert not leaks_internals(response.text, sent=[payload])


# ---------------------------------------------------------------------------
# PDF rendering of untrusted text (M18.11)
# ---------------------------------------------------------------------------

#: Values that would be parsed as markup if the renderer handed them straight to
#: ReportLab. Each is a real shape: a rule name, a hostname or a title could hold
#: any of them.
MARKUP_PAYLOADS: tuple[str, ...] = (
    "<b>bold</b>",
    "<para>nested</para>",
    "a & b",
    "]]>",
    "<![CDATA[x]]>",
    "<font color='red'>x</font>",
    "<",
    ">",
    "<img src=x onerror=alert(1)>",
    "\u003cscript\u003e",
    "& \u003c &",
)


@pytest.mark.parametrize("payload", MARKUP_PAYLOADS)
def test_pdf_text_is_escaped_before_it_reaches_the_markup_parser(
    payload: str,
) -> None:
    """A value is escaped at the one point text enters ReportLab's paragraph layer.

    ReportLab parses a small XML-like markup. Escaping at that boundary is what
    stops a rule name containing ``<`` from being read as a tag -- which would
    either drop the text or raise, and a raise here would fail a report the
    operator asked for.
    """
    rendered = _paragraph(payload, _styles()["cell"])

    # The paragraph holds the *escaped* source. It is compared against the
    # standard library's own escaper rather than against literal entity strings,
    # so this test states the rule instead of restating one spelling of it.
    assert rendered.text == escape(payload)
    # And no raw markup delimiter survives, which is the property that matters:
    # anything left there would be read as a tag.
    assert "<" not in rendered.text
    assert ">" not in rendered.text


@pytest.mark.parametrize("payload", MARKUP_PAYLOADS)
def test_a_report_of_hostile_strings_is_still_a_valid_pdf(payload: str) -> None:
    """The whole document renders, and the result is a real PDF.

    Proven end to end rather than at the paragraph: a value that reached the
    layout engine unescaped would raise somewhere downstream, so a document that
    comes back with its own signature is the claim being made.
    """
    content = ReportContent(
        report_id=1,
        title=payload,
        report_type="daily",
        output_format="PDF",
        generated_at="2026-10-09T00:00:00+00:00",
        period_start="2026-10-09T00:00:00+00:00",
        period_end="2026-10-10T00:00:00+00:00",
        period_seconds=86400.0,
        summary=(Metric(label=payload, value=payload),),
        sections=(
            ReportSection(
                key="traffic",
                title=payload,
                notice=payload,
                metrics=(Metric(label=payload, value=payload),),
                tables=(
                    ReportTable(
                        key="top_sources",
                        title=payload,
                        columns=(payload,),
                        rows=((payload,),),
                    ),
                ),
            ),
        ),
    )

    payload_bytes = render_pdf(content)

    assert payload_bytes.startswith(b"%PDF")
    assert len(payload_bytes) > MINIMUM_PDF_BYTES


def test_a_report_of_hostile_strings_renders_the_same_way_twice() -> None:
    """Escaping must not introduce non-determinism into a rendered document.

    ReportLab embeds a creation date, so byte equality is not available for a PDF;
    the *size* is the stable proxy available cheaply, and a difference would mean
    a value was being interpreted differently between runs.
    """
    payload = "<b>=' OR '1'='1</b>"
    content = ReportContent(
        report_id=1,
        title=payload,
        report_type="daily",
        output_format="PDF",
        generated_at="2026-10-09T00:00:00+00:00",
        period_start="2026-10-09T00:00:00+00:00",
        period_end="2026-10-10T00:00:00+00:00",
        period_seconds=86400.0,
        summary=(Metric(label=payload, value=payload),),
    )

    first = render_pdf(content)
    second = render_pdf(content)

    assert len(first) == len(second)


# ---------------------------------------------------------------------------
# Resource bounds (M18.11)
# ---------------------------------------------------------------------------


def test_a_very_long_filter_value_is_refused_rather_than_absorbed(
    client: TestClient,
) -> None:
    """An oversized filter is a controlled refusal, never an exception.

    A value long enough to matter is exactly what a naive implementation turns
    into an unbounded ``LIKE`` or an allocation. The assertion is only that the
    answer is one of the three controlled outcomes -- what the bound *is* belongs
    to the router that owns the field.
    """
    oversized = "A" * 20_000

    for path, param in INJECTION_TARGETS:
        response = client.get(path, params={param: oversized})
        assert response.status_code in (200, 400, 414, 422, 431), response.text
        assert not leaks_internals(response.text, sent=[oversized])


@pytest.mark.parametrize("limit", ["0", "-1", "100000", "not-a-number", "1e9"])
def test_an_absurd_page_size_is_refused(client: TestClient, limit: str) -> None:
    """A page bound is validated at the edge, so no store is asked for everything."""
    response = client.get("/api/v1/alerts", params={"limit": limit})

    assert response.status_code == 422, response.text
    assert not leaks_internals(response.text, sent=[limit])


def test_an_unknown_route_and_a_wrong_verb_answer_in_the_envelope(
    client: TestClient,
) -> None:
    """A routing failure is the standard envelope, not a framework page.

    The framework's own 404 and 405 bodies carry a ``detail`` string and no
    application code; the handlers here replace them, and this pins that (M13.5).
    """
    missing = client.get("/api/v1/definitely-not-a-route")
    wrong_verb = client.delete("/api/v1/devices")

    assert missing.status_code == 404
    assert wrong_verb.status_code == 405
    for response in (missing, wrong_verb):
        body = response.json()
        assert body["success"] is False
        assert isinstance(body["message"], str) and body["message"]
        assert "errors" in body
        assert not leaks_internals(response.text)


def test_every_refusal_reports_a_sentence_rather_than_an_exception(
    client: TestClient,
) -> None:
    """A consolidated sweep: no refusal in this file's surface leaks an internal.

    The individual tests above each check their own response; this is the one that
    would catch a *new* field being added to a shared error envelope without a
    leak check, because it walks the widest set of refusals in one pass.
    """
    refusals: list[tuple[str, dict[str, str]]] = [
        ("/api/v1/alerts", {"severity": "'; DROP TABLE alerts; --"}),
        ("/api/v1/packets", {"protocol": "' OR '1'='1"}),
        ("/api/v1/devices", {"ip": "<script>"}),
        ("/api/v1/alerts", {"since": "not-a-timestamp"}),
        ("/api/v1/alerts", {"limit": "999999"}),
        ("/api/v1/devices/no-such-device", {}),
        ("/api/v1/definitely-not-a-route", {}),
    ]

    for url, params in refusals:
        response = client.get(url, params=params)
        assert response.status_code < 500, response.text
        if response.headers.get("content-type", "").startswith("application/json"):
            assert not leaks_internals(response.text, sent=params.values()), (
                response.text
            )

    wrong_verb = client.delete("/api/v1/alerts")
    assert wrong_verb.status_code == 405
    assert not leaks_internals(wrong_verb.text)
