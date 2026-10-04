"""Read-only wire schemas for the system API (M13.22).

The system endpoints answer "what is this process, and what is it doing?".
Everything here is a *statement about observed state*, never a claim about
health that was inferred rather than checked: :class:`SystemHealthData` carries
one entry per probe and the probe's own verdict, so a caller can see which
dependency failed rather than only that something did.

No field here can leak a secret. The database is described by its *dialect*
(``sqlite``) rather than by its URL, because the URL is a filesystem path or,
for a networked database, a credential-bearing connection string — and M13.5 and
M13.30 both forbid returning either.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ServiceStateView(BaseModel):
    """Whether one pipeline stage is switched on and attached (M13.22).

    ``enabled`` is the configuration switch; ``attached`` is whether the running
    pipeline actually holds the component. The two are reported separately
    because they can genuinely disagree: a stage configured on but never wired to
    a pipeline that has not captured anything would otherwise look broken.
    """

    name: str
    enabled: bool = Field(description="Whether the stage is switched on by config")
    attached: bool | None = Field(
        default=None,
        description="Whether the running pipeline holds the component, when known",
    )


class DatabaseStateView(BaseModel):
    """Reachability and flavour of the database (M13.22).

    The URL is deliberately absent: it is a path or a credential-bearing DSN, and
    neither belongs in a response body. The dialect is what a client can act on
    without being told where anything lives.
    """

    reachable: bool = Field(description="Whether a trivial query succeeded")
    dialect: str = Field(default="unknown", description="Engine family, e.g. sqlite")


class CaptureStateView(BaseModel):
    """Capture state as the system endpoints report it (M13.22).

    A bounded copy of what ``GET /capture/status`` returns, plus the per-stage
    error counters the pipeline keeps, so one request answers "is capture on and
    is anything failing?" without a second call.
    """

    running: bool = False
    status: str = "unknown"
    interface: str | None = None
    packet_count: int = 0
    processed_packet_count: int = 0
    error_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Per-stage processing errors observed so far",
    )


class RuntimeMetricsView(BaseModel):
    """Basic runtime facts about the process (M13.22).

    ``uptime_seconds`` is ``None`` when startup was never recorded, rather than
    ``0.0``: "not recorded" and "started just now" are different statements, and
    only one of them is true in that case.
    """

    uptime_seconds: float | None = Field(
        default=None, description="Seconds since startup; absent when not recorded"
    )
    started_at: str | None = Field(
        default=None, description="ISO-8601 UTC instant the process started"
    )
    generated_at: str = Field(description="ISO-8601 UTC instant of this response")
    python_version: str = Field(default="", description="Interpreter version")
    pid: int = Field(default=0, description="Operating-system process id")


class SystemInfoData(BaseModel):
    """Application identity and the environment it runs in (M13.22).

    ``platform`` is the interpreter's platform string and ``database_dialect`` the
    engine family — neither identifies a location or a credential, which is the
    line this module does not cross.
    """

    app_name: str
    app_version: str
    environment: str = Field(description="development / test / production")
    api_version: str = Field(default="v1", description="Base path version of this API")
    timezone: str = Field(default="UTC", description="Timezone API timestamps use")
    platform: str = Field(default="", description="Interpreter platform string")
    database_dialect: str = Field(
        default="unknown", description="Database engine family, e.g. sqlite"
    )
    registered_route_count: int | None = Field(
        default=None,
        description=(
            "Routes documented under the API base path; absent when the "
            "OpenAPI document could not be built"
        ),
    )
    docs_url: str | None = Field(default=None, description="Interactive API docs path")
    openapi_url: str | None = Field(default=None, description="OpenAPI document path")


class HealthCheckView(BaseModel):
    """The verdict of one health probe (M13.22).

    ``detail`` is a short, safe sentence — which dependency failed, not why in
    terms of a stack trace, a path or a driver message (M13.5).
    """

    name: str
    ok: bool
    detail: str = ""


class SystemHealthData(BaseModel):
    """Aggregate health plus the individual probes behind it (M13.22).

    ``status`` is the worst verdict of the probes: ``healthy`` when every probe
    passed, ``degraded`` when one did not. The probes ride along rather than being
    collapsed into the single word, so an operator learns *which* dependency is
    down from the same response.
    """

    status: str = Field(description="healthy or degraded")
    checks: list[HealthCheckView] = Field(default_factory=list)


class SystemStatusData(BaseModel):
    """One consolidated view of process, database and pipeline state (M13.22)."""

    status: str = Field(description="healthy or degraded")
    info: SystemInfoData
    capture: CaptureStateView
    database: DatabaseStateView
    services: list[ServiceStateView] = Field(default_factory=list)
    runtime: RuntimeMetricsView


__all__ = [
    "CaptureStateView",
    "DatabaseStateView",
    "HealthCheckView",
    "RuntimeMetricsView",
    "ServiceStateView",
    "SystemHealthData",
    "SystemInfoData",
    "SystemStatusData",
]
