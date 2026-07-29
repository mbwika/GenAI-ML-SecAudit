"""Reporting engine for assurance summaries and historical metrics."""
from typing import Any

from ..reporting.assurance_report import (
    build_assurance_report,
    render_assurance_report_html,
    render_assurance_report_markdown,
)
from ..reporting.exporters import export_oscal_ssp, export_sarif
from ..reporting.report import Reporter


class ReportingEngine:
    def __init__(self, datastore: object | None = None):
        self.datastore = datastore

    def summarize(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> dict[str, Any]:
        if self.datastore is None:
            return {
                "scope": build_assurance_report(
                    None,
                    artifact_id=artifact_id,
                    model_id=model_id,
                    registered_by=registered_by,
                ).get("scope", {}),
                "findings": {"total_findings": 0, "average_score": 0.0, "by_type": {}, "by_severity": {}},
                "audit_logs": [],
                "metrics": [],
            }

        report = self.assurance_report(
            artifact_id=artifact_id, model_id=model_id, registered_by=registered_by
        )
        scope = report.get("scope", {})
        scope_artifact = artifact_id or model_id
        artifact_ids = {
            item.get("model_id")
            for item in (report.get("model_inventory") or {}).get("models", [])
            if item.get("model_id")
        }
        self.datastore.list_findings(limit=100, artifact_id=scope_artifact)
        audit_logs = self.datastore.list_audit_logs(limit=100, artifact_id=scope_artifact)
        metrics = self.datastore.list_metrics(limit=100, artifact_id=scope_artifact)
        if scope.get("type") == "REGISTRANT":
            [
                finding
                for finding in self.datastore.list_findings(limit=1000)
                if finding.get("artifact_id") in artifact_ids
            ][:100]
            audit_logs = [
                entry
                for entry in self.datastore.list_audit_logs(limit=1000)
                if entry.get("artifact_id") in artifact_ids
            ][:100]
            metrics = [
                metric
                for metric in self.datastore.list_metrics(limit=1000)
                if metric.get("artifact_id") in artifact_ids
            ][:100]
        reporter = Reporter(self.datastore)
        summary = {
            "scope": report.get("scope", {}),
            "findings": reporter.aggregate(artifact_id=scope_artifact)
            if scope.get("type") != "REGISTRANT"
            else report.get("risk_posture", {}),
            "audit_logs": audit_logs,
            "metrics": metrics,
        }
        return summary

    def assurance_report(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> dict[str, Any]:
        return build_assurance_report(
            self.datastore,
            artifact_id=artifact_id,
            model_id=model_id,
            registered_by=registered_by,
        )

    def assurance_report_markdown(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> str:
        return render_assurance_report_markdown(
            self.assurance_report(
                artifact_id=artifact_id,
                model_id=model_id,
                registered_by=registered_by,
            )
        )

    def assurance_report_html(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> str:
        return render_assurance_report_html(
            self.assurance_report(
                artifact_id=artifact_id,
                model_id=model_id,
                registered_by=registered_by,
            )
        )

    def assurance_report_oscal(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> dict[str, Any]:
        report = self.assurance_report(
            artifact_id=artifact_id,
            model_id=model_id,
            registered_by=registered_by,
        )
        scope = report.get("scope") or {}
        system_name = (
            scope.get("model_id")
            or scope.get("artifact_id")
            or scope.get("registered_by")
            or "AIAF Portfolio"
        )
        evidence = self._scoped_control_evidence(report, artifact_id, model_id, registered_by)
        controls = _controls_from_report(report)
        return export_oscal_ssp(
            system_name=system_name,
            controls=controls,
            evidence=evidence,
            version=str(report.get("schema_version") or "1.0"),
            system_description=(
                "AI system and assurance posture exported from the AI Assurance Framework"
            ),
            report=report,
        )

    def assurance_report_sarif(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> dict[str, Any]:
        report = self.assurance_report(
            artifact_id=artifact_id,
            model_id=model_id,
            registered_by=registered_by,
        )
        findings = _sarif_findings(report.get("raw_finding_items") or [])
        return export_sarif(findings, tool_version=str(report.get("schema_version") or "0.2.0"))

    def alerts(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> dict[str, Any]:
        return self.assurance_report(
            artifact_id=artifact_id,
            model_id=model_id,
            registered_by=registered_by,
        ).get(
            "monitoring_alerts",
            {"status": "OK", "total_alerts": 0, "by_severity": {}, "alerts": []},
        )

    def compliance(
        self,
        artifact_id: str | None = None,
        model_id: str | None = None,
        registered_by: str | None = None,
    ) -> dict[str, Any]:
        return self.assurance_report(
            artifact_id=artifact_id,
            model_id=model_id,
            registered_by=registered_by,
        ).get("compliance", {})

    def _scoped_control_evidence(
        self,
        report: dict[str, Any],
        artifact_id: str | None,
        model_id: str | None,
        registered_by: str | None,
    ) -> list[dict[str, Any]]:
        if self.datastore is None:
            return []
        scope_artifact = artifact_id or model_id
        evidence = self.datastore.list_control_evidence(
            limit=1000, artifact_id=scope_artifact
        )
        if registered_by:
            artifact_ids = {
                item.get("model_id")
                for item in (report.get("model_inventory") or {}).get("models", [])
                if item.get("model_id")
            }
            evidence = [
                item for item in self.datastore.list_control_evidence(limit=5000)
                if item.get("artifact_id") in artifact_ids
            ]
        return evidence


def _sarif_findings(finding_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adapt AIAF's flattened finding-item shape to what export_sarif expects.

    finding_items carry whatever fields their producer set (deployment
    drift, RAG scans, red-team results, ...) plus artifact_id/timestamp/
    risk_score injected by _flatten_findings; they have no producer-agnostic
    description or per-item id, so both are synthesized here.
    """
    adapted = []
    for index, item in enumerate(finding_items):
        detail = item.get("detail")
        description = (
            item.get("summary")
            or (detail if isinstance(detail, str) else None)
            or item.get("title")
            or str(item.get("type") or "AIAF finding")
        )
        artifact_id = item.get("artifact_id")
        adapted.append(
            {
                "type": item.get("type", "unknown"),
                "severity": item.get("severity", "none"),
                "description": description,
                "id": item.get("finding_id") or f"{artifact_id or 'portfolio'}-{item.get('type', 'finding')}-{index}",
                "artifact_id": artifact_id,
                "score": item.get("risk_score"),
                "model_id": artifact_id,
                "framework_refs": item.get("framework_refs") or {},
            }
        )
    return adapted


def _controls_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    compliance = report.get("compliance") or {}
    frameworks = compliance.get("frameworks") or {}
    consolidated: dict[str, dict[str, Any]] = {}

    for framework in frameworks.values():
        for control in framework.get("control_evidence") or []:
            control_id = str(control.get("control_id") or "")
            if not control_id:
                continue
            current = consolidated.setdefault(
                control_id,
                {
                    "id": control_id,
                    "status": control.get("status", "NOT_EVALUATED"),
                    "description": "",
                    "notes": "",
                    "objective": "",
                    "domain": "",
                    "provided_evidence": [],
                    "missing_evidence": [],
                },
            )
            current["description"] = current["description"] or str(
                control.get("title") or control_id
            )
            current["provided_evidence"] = list(
                {
                    *current.get("provided_evidence", []),
                    *(control.get("provided_evidence") or []),
                }
            )
            current["missing_evidence"] = list(
                {
                    *current.get("missing_evidence", []),
                    *(control.get("missing_evidence") or []),
                }
            )

    for gap in (report.get("governance") or {}).get("open_gaps") or []:
        control_id = str(gap.get("id") or "")
        if not control_id:
            continue
        current = consolidated.setdefault(
            control_id,
            {
                "id": control_id,
                "status": gap.get("status", "missing"),
                "description": str(gap.get("title") or control_id),
                "notes": "",
                "objective": str(gap.get("objective") or ""),
                "domain": str(gap.get("domain") or ""),
                "provided_evidence": list(gap.get("provided_evidence") or []),
                "missing_evidence": list(gap.get("missing_evidence") or []),
            },
        )
        current["objective"] = current["objective"] or str(gap.get("objective") or "")
        current["domain"] = current["domain"] or str(gap.get("domain") or "")
        current["notes"] = current["notes"] or str(gap.get("description") or "")

    return sorted(consolidated.values(), key=lambda item: item["id"])
