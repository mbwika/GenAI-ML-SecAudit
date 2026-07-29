"""Reporting engine API routes."""
import html as _html
import os
import re

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ..core import AssuranceReportSnapshotEngine, ReportingEngine
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/reporting", tags=["reporting"])

# Allowlist of valid report format values — reject anything else before it
# reaches the engine to prevent format-parameter injection.
_ALLOWED_REPORT_FORMATS = frozenset({"json", "markdown", "html", "oscal", "sarif"})

# Scope ID fields (artifact_id, model_id, registered_by) must not contain
# HTML-special characters.  Blocking them here prevents taint from reaching
# the HTML report renderer even if the engine does not escape its inputs.
# We use a denylist rather than an allowlist so that legitimate characters
# (e.g. '/' in HuggingFace model IDs like "mistralai/Mistral-7B") are not
# accidentally rejected.
_UNSAFE_HTML_CHARS_RE = re.compile(r'[<>"\'&]')

# Security headers added to every text/html response to restrict what the
# browser can do with the report even if unexpected content slips through.
_HTML_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class ReportSnapshotCreate(BaseModel):
    created_by: str = Field(min_length=1, max_length=255)
    artifact_id: str | None = Field(default=None, max_length=255)
    model_id: str | None = Field(default=None, max_length=255)
    registered_by: str | None = Field(default=None, max_length=255)
    sign: bool = False


@router.get("/summary")
def reporting_summary(
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
    api_key: str = Depends(get_api_key),
):
    store = get_store()
    engine = ReportingEngine(datastore=store)
    scope = _scope_filters(artifact_id, model_id, registered_by)
    return engine.summarize(**scope)


@router.get("/assurance-report")
def assurance_report(
    format: str = "json",
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
    api_key: str = Depends(get_api_key),
):
    fmt = _validate_report_format(format)
    store = get_store()
    engine = ReportingEngine(datastore=store)
    scope = _scope_filters(artifact_id, model_id, registered_by)
    if fmt == "markdown":
        return Response(
            engine.assurance_report_markdown(**scope),
            media_type="text/markdown",
        )
    if fmt == "html":
        return _html_report_response(engine, scope)
    if fmt == "oscal":
        return engine.assurance_report_oscal(**_escape_scope(scope))
    if fmt == "sarif":
        return engine.assurance_report_sarif(**scope)
    return engine.assurance_report(**scope)


@router.get("/alerts")
def reporting_alerts(
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
    api_key: str = Depends(get_api_key),
):
    store = get_store()
    engine = ReportingEngine(datastore=store)
    return engine.alerts(**_scope_filters(artifact_id, model_id, registered_by))


@router.get("/compliance")
def reporting_compliance(
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
    api_key: str = Depends(get_api_key),
):
    store = get_store()
    engine = ReportingEngine(datastore=store)
    return engine.compliance(**_scope_filters(artifact_id, model_id, registered_by))


@router.get("/metrics")
def reporting_metrics(
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
    metric_name: str | None = None,
    limit: int = 500,
    api_key: str = Depends(get_api_key),
):
    """Historical assurance-metric time series for trend and drift charts.

    Points are grouped by ``metric_name`` and returned in ascending time order
    (oldest first within the most recent ``limit`` records), each carrying its
    artifact id and any severity dimension so the UI can colour the series.
    """
    store = get_store()
    scope = _scope_filters(artifact_id, model_id, registered_by)
    report = ReportingEngine(datastore=store).assurance_report(**scope)
    artifact_ids = {
        model.get("model_id")
        for model in (report.get("model_inventory") or {}).get("models", [])
        if model.get("model_id")
    }
    scoped_artifact = scope.get("artifact_id") or scope.get("model_id")
    rows = store.list_metrics(
        limit=min(max(int(limit), 1), 5000), artifact_id=scoped_artifact
    )
    if scope.get("registered_by"):
        rows = [row for row in rows if row.get("artifact_id") in artifact_ids]
    series: dict = {}
    for row in rows:
        name = row.get("metric_name")
        if metric_name and name != metric_name:
            continue
        dimensions = row.get("dimensions") or {}
        series.setdefault(name, []).append(
            {
                "t": row.get("created_at"),
                "value": row.get("metric_value"),
                "artifact_id": row.get("artifact_id"),
                "severity": dimensions.get("severity") or dimensions.get("overall_severity"),
            }
        )
    # list_metrics is newest-first; charts want oldest-first.
    for points in series.values():
        points.reverse()
    return {
        "series": series,
        "metric_names": sorted(series),
        "point_count": sum(len(points) for points in series.values()),
    }


@router.post("/snapshots")
def create_report_snapshot(
    request: ReportSnapshotCreate, api_key: str = Depends(get_api_key)
):
    try:
        scope = _scope_filters(
            request.artifact_id, request.model_id, request.registered_by
        )
        return _snapshot_engine().create(
            created_by=request.created_by,
            **scope,
            sign=request.sign,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/snapshots")
def list_report_snapshots(
    limit: int = 100,
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
    api_key: str = Depends(get_api_key),
):
    snapshots = _snapshot_engine().list(
        limit=limit,
        artifact_id=artifact_id,
        model_id=model_id,
        registered_by=registered_by,
    )
    return {
        "snapshots": [_snapshot_metadata(snapshot) for snapshot in snapshots],
        "count": len(snapshots),
    }


@router.get("/snapshots/{snapshot_id}")
def get_report_snapshot(
    snapshot_id: str, api_key: str = Depends(get_api_key)
):
    snapshot = _snapshot_engine().get(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Assurance report snapshot not found")
    return snapshot


@router.post("/snapshots/{snapshot_id}/verify")
def verify_report_snapshot(
    snapshot_id: str, api_key: str = Depends(get_api_key)
):
    verification = _snapshot_engine().verify(snapshot_id)
    if not verification:
        raise HTTPException(status_code=404, detail="Assurance report snapshot not found")
    return verification


def _snapshot_engine() -> AssuranceReportSnapshotEngine:
    return AssuranceReportSnapshotEngine(
        get_store(),
        signing_key=os.environ.get("AIAF_REPORT_SIGNING_KEY"),
        key_id=os.environ.get("AIAF_REPORT_SIGNING_KEY_ID", "default"),
        signing_private_key_pem=os.environ.get("AIAF_REPORT_SIGNING_PRIVATE_KEY_PEM"),
        verification_public_key_pem=os.environ.get("AIAF_REPORT_SIGNING_PUBLIC_KEY_PEM"),
    )


def _snapshot_metadata(snapshot):
    metadata = {key: value for key, value in snapshot.items() if key != "report"}
    metadata["scope"] = (snapshot.get("report") or {}).get("scope", {})
    return metadata


def _scope_filters(
    artifact_id: str | None,
    model_id: str | None,
    registered_by: str | None,
) -> dict[str, str | None]:
    values = {
        "artifact_id": _validate_scope_id(artifact_id, "artifact_id"),
        "model_id": _validate_scope_id(model_id, "model_id"),
        "registered_by": _validate_scope_id(registered_by, "registered_by"),
    }
    selected = [name for name, value in values.items() if value]
    if len(selected) > 1:
        raise HTTPException(
            status_code=422,
            detail="Choose only one report scope filter: artifact_id, model_id, or registered_by.",
        )
    return values


def _escape_scope(scope: dict[str, str | None]) -> dict[str, str | None]:
    """Apply html.escape() to all scope values before they enter a markup renderer.

    Our denylist (_validate_scope_id) already blocks the five HTML/XML-special
    characters, so this is a no-op for any value that reaches this point.  It
    exists to give static-analysis scanners a recognizable sanitization call at
    the exact point where HTTP-parameter-derived data enters an HTML/OSCAL renderer,
    terminating the taint path.
    """
    return {k: _html.escape(v) if v is not None else v for k, v in scope.items()}


def _html_report_response(
    engine: ReportingEngine, scope: dict[str, str | None]
) -> HTMLResponse:
    """Render the assurance report HTML only after explicit scope sanitization."""
    safe_scope = _escape_scope(scope)
    return HTMLResponse(
        content=engine.assurance_report_html(**safe_scope),
        headers=_HTML_SECURITY_HEADERS,
    )


def _validate_report_format(fmt: str) -> str:
    """Allowlist-validate the format query parameter."""
    normalized = (fmt or "").lower().strip()
    if normalized not in _ALLOWED_REPORT_FORMATS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid report format {fmt!r}. "
                f"Allowed values: {', '.join(sorted(_ALLOWED_REPORT_FORMATS))}."
            ),
        )
    return normalized


@router.get("/evidence-pack/{framework}")
def evidence_pack(
    framework: str,
    fmt: str = "json",
    model_id: str | None = None,
    artifact_id: str | None = None,
    registered_by: str | None = None,
    api_key: str = Depends(get_api_key),
):
    """Build and return a per-framework compliance evidence pack.

    ``framework`` must be one of: ``NIST_AI_RMF``, ``ISO_42001``,
    ``EU_AI_ACT_HIGH_RISK``, ``OWASP_LLM_TOP10``, ``OWASP_AGENTIC``.

    ``?format=json`` (default) returns the full pack dict.
    ``?format=oscal`` returns an OSCAL 1.1.2 SSP.
    ``?format=html`` returns an HTML document.
    ``?format=markdown`` returns a Markdown string.
    """
    from ..reporting.evidence_pack import (
        EXPORT_FORMATS as PACK_FORMATS,
    )
    from ..reporting.evidence_pack import (
        EvidencePackError,
        export_pack,
    )

    fmt_normalized = str(fmt).lower().strip()
    if fmt_normalized not in PACK_FORMATS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid format {fmt!r}. Allowed: {', '.join(sorted(PACK_FORMATS))}.",
        )

    scope: dict[str, str | None] = {}
    if model_id:
        scope["model_id"] = str(model_id)[:512]
    if artifact_id:
        scope["artifact_id"] = str(artifact_id)[:512]
    if registered_by:
        scope["registered_by"] = str(registered_by)[:512]

    store = get_store()
    try:
        result = export_pack(framework.upper(), scope, store, fmt=fmt_normalized)
    except EvidencePackError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if fmt_normalized == "html":
        return HTMLResponse(content=result, headers=_HTML_SECURITY_HEADERS)
    if fmt_normalized == "markdown":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(result, media_type="text/markdown")
    return result


def _validate_scope_id(value: str | None, field: str) -> str | None:
    """Reject scope ID values that contain HTML-special characters.

    A denylist (block <, >, &, ", ') is used rather than an allowlist so that
    legitimate characters — including '/' in HuggingFace-style model IDs — are
    not accidentally rejected.
    """
    if not value:
        return None
    stripped = str(value).strip()
    if not stripped:
        return None
    if len(stripped) > 255:
        raise HTTPException(
            status_code=422,
            detail=f"Value for {field!r} exceeds the 255-character limit.",
        )
    if _UNSAFE_HTML_CHARS_RE.search(stripped):
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid characters in {field!r}. "
                "HTML-special characters (<, >, \", ', &) are not permitted."
            ),
        )
    return stripped
