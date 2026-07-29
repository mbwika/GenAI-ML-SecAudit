"""Evidence-driven assurance report generation."""
from datetime import datetime, timezone
from html import escape
from typing import Any

from ..analysis import RISK_DRIFT_SCORING_VERSION, analyze_risk_drift
from ..mapping.standards import FRAMEWORKS, STANDARD_PROFILES
from .compliance import build_compliance_matrix
from .monitoring import evaluate_monitoring_alerts

# Robust drift replaces naive last-two-point/split-half deltas. The metric scale
# and direction differ per series, and drift is computed per (artifact_id,
# metric_name) partition so unrelated artifacts never share a trend.
_DRIFT_STATUS_TO_TREND = {
    "DETERIORATING": "WORSENING",
    "STALE": "WORSENING",
    "IMPROVING": "IMPROVING",
    "STABLE": "STABLE",
}


def _metric_drift_summary(
    metrics: list[dict[str, Any]],
    metric_name: str,
    *,
    direction: str,
    metric_min: float,
    metric_max: float,
    as_of: str | None = None,
) -> dict[str, Any]:
    """Run robust drift per (artifact_id, metric_name) partition over history."""
    by_artifact: dict[Any, list[dict[str, Any]]] = {}
    for metric in metrics:
        if metric.get("metric_name") != metric_name:
            continue
        by_artifact.setdefault(metric.get("artifact_id"), []).append(metric)

    if not by_artifact:
        return {
            "trend": "NO_DATA",
            "status": "NO_DATA",
            "severity": "LOW",
            "scoring_version": None,
            "partition_count": 0,
            "by_artifact": [],
        }

    context = {
        "metric_min": metric_min,
        "metric_max": metric_max,
        "direction": direction,
    }
    if as_of:
        context["as_of"] = as_of

    partitions = []
    for artifact_id, series in by_artifact.items():
        ordered = sorted(
            series, key=lambda item: (item.get("created_at") or "", item.get("id") or 0)
        )
        result = analyze_risk_drift(ordered, context)
        partitions.append(
            {
                "artifact_id": artifact_id,
                "status": result["status"],
                "severity": result["severity"],
                "risk_score": result["risk_score"],
                "direction": result["direction"],
                "confidence": result["confidence"],
                "observation_count": result["observation_count"],
                "freshness": result.get("freshness"),
            }
        )

    headline = max(partitions, key=lambda item: item["risk_score"])
    return {
        "trend": _DRIFT_STATUS_TO_TREND.get(headline["status"], "BASELINE"),
        "status": headline["status"],
        "severity": headline["severity"],
        "risk_score": headline["risk_score"],
        "scoring_version": RISK_DRIFT_SCORING_VERSION,
        "partition_count": len(partitions),
        "most_drifted_artifact": headline["artifact_id"],
        "by_artifact": sorted(
            partitions, key=lambda item: item["risk_score"], reverse=True
        )[:25],
    }


FRAMEWORK_ALIASES = {
    "NIST SSDF": "NIST Secure Software Development Framework",
    "NIST Secure Software Development Framework": "NIST Secure Software Development Framework",
    "NIST AI RMF": "NIST AI RMF",
    "OWASP Top 10 for LLMs": "OWASP Top 10 for LLMs",
    "MITRE ATLAS": "MITRE ATLAS",
    "CIS Controls": "CIS Controls",
}

_AGENT_DECLARATION_FIELDS = [
    "tools",
    "permissions",
    "autonomy_level",
    "workflow_steps",
    "tool_invocations",
    "agent_policy",
    "agent_policy_profile",
    "runtime_tool_authorization",
    "human_review_required",
    "credential_scope",
    "target_scope",
    "data_scope",
    "internet_access",
    "self_modification",
    "sandboxing",
    "credential_scoping",
    "continuous_monitoring",
    "audit_logging",
    "kill_switch",
    "rate_limits",
    "delegation_policy",
]


def build_assurance_report(
    datastore: object | None,
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
) -> dict[str, Any]:
    """Build a compliance-oriented report from stored assurance evidence."""
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    scope = _report_scope(
        artifact_id=artifact_id, model_id=model_id, registered_by=registered_by
    )
    if datastore is None:
        return _empty_report(generated_at, scope)

    models = _safe_list_models(
        datastore,
        artifact_id=scope.get("artifact_id"),
        model_id=scope.get("model_id"),
        registered_by=scope.get("registered_by"),
    )
    artifact_ids = _scope_artifact_ids(scope, models)
    artifact_filter = _scope_single_artifact(scope)

    findings = _filter_rows_by_artifact_ids(
        datastore.list_findings(limit=1000, artifact_id=artifact_filter),
        artifact_ids,
    )
    audit_logs = _filter_rows_by_artifact_ids(
        datastore.list_audit_logs(limit=1000, artifact_id=artifact_filter),
        artifact_ids,
    )
    metrics = _filter_rows_by_artifact_ids(
        datastore.list_metrics(limit=1000, artifact_id=artifact_filter),
        artifact_ids,
    )
    schedules = _filter_rows_by_artifact_ids(
        _safe_list_monitoring_schedules(datastore, artifact_filter),
        artifact_ids,
    )
    monitoring_runs = _filter_rows_by_artifact_ids(
        _safe_list_monitoring_runs(datastore, artifact_filter),
        artifact_ids,
    )
    risks = _filter_rows_by_artifact_ids(
        _safe_list_risks(datastore, artifact_filter),
        artifact_ids,
    )
    advisories = [] if scope.get("type") != "PORTFOLIO" else _safe_list_advisories(datastore)
    advisory_feed_snapshots = (
        []
        if scope.get("type") != "PORTFOLIO"
        else _safe_list_advisory_feed_snapshots(datastore)
    )
    control_evidence = _filter_rows_by_artifact_ids(
        _safe_list_control_evidence(datastore, artifact_filter),
        artifact_ids,
    )
    agent_sessions = _filter_rows_by_artifact_ids(
        _safe_list_agent_sessions(datastore, artifact_filter),
        artifact_ids,
    )
    tool_invocations = _filter_rows_by_artifact_ids(
        _safe_list_tool_invocations(datastore, artifact_filter),
        artifact_ids,
    )
    report_snapshots = _filter_report_snapshots_by_scope(
        _safe_list_report_snapshots(datastore, artifact_filter),
        scope,
    )

    finding_items = _flatten_findings(findings)
    governance_evaluations = [
        log for log in audit_logs if log.get("event_type") == "governance_evaluation"
    ]
    latest_governance = governance_evaluations[0]["details"] if governance_evaluations else None

    report = {
        "report_type": "AI Assurance Compliance Report",
        "schema_version": "1.0",
        "generated_at": generated_at,
        "scope": scope,
        "executive_summary": _executive_summary(
            findings, finding_items, latest_governance, models, risks
        ),
        "model_inventory": _model_inventory_summary(models),
        "risk_posture": _risk_posture(findings, finding_items),
        "model_risk": _model_risk_summary(finding_items, metrics),
        "risk_register": _risk_register_summary(risks, generated_at),
        "trustworthiness": _trustworthiness_summary(metrics, generated_at),
        "continuous_monitoring": _continuous_monitoring(
            findings, metrics, schedules, monitoring_runs, generated_at
        ),
        "governance": _governance_summary(latest_governance, governance_evaluations),
        "governance_evidence": _governance_evidence_summary(
            control_evidence, generated_at
        ),
        "agentic_runtime": _agentic_runtime_summary(
            agent_sessions, tool_invocations
        ),
        "report_snapshots": _report_snapshot_summary(report_snapshots),
        "compliance": build_compliance_matrix(finding_items, latest_governance),
        "standards_coverage": _standards_coverage(finding_items, latest_governance),
        "technical_explainability": _technical_explainability(
            scope,
            models,
            finding_items,
            governance_evaluations,
            control_evidence,
        ),
        "supply_chain": _supply_chain_summary(
            models,
            finding_items,
            advisories,
            advisory_feed_snapshots,
            generated_at,
        ),
        "evidence_inventory": {
            "finding_records": len(findings),
            "finding_items": len(finding_items),
            "audit_logs": len(audit_logs),
            "historical_metrics": len(metrics),
            "registered_models": len(models),
            "monitoring_schedules": len(schedules),
            "monitoring_runs": len(monitoring_runs),
            "risk_register_items": len(risks),
            "vulnerability_advisories": len(advisories),
            "advisory_feed_snapshots": len(advisory_feed_snapshots),
            "control_evidence": len(control_evidence),
            "agent_sessions": len(agent_sessions),
            "tool_invocation_decisions": len(tool_invocations),
            "assurance_report_snapshots": len(report_snapshots),
        },
    }
    report["monitoring_alerts"] = evaluate_monitoring_alerts(report)
    report["assurance_questions"] = _assurance_questions(report)
    report["risk_score_context"] = _risk_score_context(report)
    report["recommended_actions"] = _recommended_actions(report)
    report["visualizations"] = _visualizations(report, metrics)
    # Flattened, ungrouped finding list — distinct from evidence_inventory's
    # counts above, this is the actual per-finding data other exporters
    # (e.g. SARIF) need rather than a summary.
    report["raw_finding_items"] = finding_items
    return report


def render_assurance_report_markdown(report: dict[str, Any]) -> str:
    """Render a question-led markdown export for human review."""
    summary = report.get("executive_summary", {})
    scope = report.get("scope", {})
    inventory = report.get("model_inventory", {})
    posture = report.get("risk_posture", {})
    model_risk = report.get("model_risk", {})
    trust = report.get("trustworthiness", {})
    monitoring = report.get("continuous_monitoring", {})
    governance = report.get("governance", {})
    governance_evidence = report.get("governance_evidence", {})
    agentic_runtime = report.get("agentic_runtime", {})
    report_snapshots = report.get("report_snapshots", {})
    compliance = report.get("compliance", {})
    standards = report.get("standards_coverage", {})
    supply_chain = report.get("supply_chain", {})
    explainability = report.get("technical_explainability", {})
    alerts = report.get("monitoring_alerts", {})
    risk_register = report.get("risk_register", {})
    questions = report.get("assurance_questions", {})
    actions = report.get("recommended_actions", [])
    risk_score_context = report.get("risk_score_context", {})

    lines = [
        f"# {report.get('report_type', 'AI Assurance Report')}",
        "",
        f"Generated: {report.get('generated_at', 'unknown')}",
        f"Scope: {scope}",
        "",
        "## Executive Summary",
        "",
        f"- Overall status: {_humanize_label(summary.get('overall_status', 'UNKNOWN'))}",
        f"- Risk score: {summary.get('current_risk_score', 0.0)} {_humanize_label(risk_score_context.get('current_band', 'UNKNOWN'))}",
        f"- Open governance gaps: {summary.get('open_governance_gaps', 0)}",
        f"- Registered models: {summary.get('registered_models', 0)}",
        f"- Latest trustworthiness: {trust.get('latest_score', 0.0)} ({_humanize_label(trust.get('latest_level', 'NO_DATA'))})",
        f"- Monitoring alerts: {alerts.get('total_alerts', 0)}",
        "",
        "## Questions This Report Answers",
        "",
        f"- What is in scope? {questions.get('what_is_in_scope', {}).get('answer', 'Unknown.')}",
        f"- Can we trust the model supply chain? {questions.get('can_we_trust_the_supply_chain', {}).get('answer', 'Unknown.')}",
        f"- What needs attention now? {questions.get('what_needs_attention_now', {}).get('answer', 'Unknown.')}",
        f"- Are controls and evidence sufficient? {questions.get('are_controls_and_evidence_sufficient', {}).get('answer', 'Unknown.')}",
        f"- What is changing over time? {questions.get('what_is_changing_over_time', {}).get('answer', 'Unknown.')}",
        "",
        "## Scope And Model Inventory",
        "",
        f"- Scope type: {_humanize_label(scope.get('type', 'UNKNOWN'))}",
        f"- Models in scope: {inventory.get('total_models', 0)}",
        f"- Distinct registrants: {inventory.get('distinct_registrants', 0)}",
        f"- Distinct publishers: {inventory.get('distinct_publishers', 0)}",
        f"- Models by risk: {inventory.get('by_risk', {})}",
        "",
        "## Risk Posture",
        "",
        f"- Finding records: {posture.get('finding_records', 0)}",
        f"- Finding items: {posture.get('finding_items', 0)}",
        f"- By severity: {posture.get('by_severity', {})}",
        f"- By type: {posture.get('by_type', {})}",
        f"- Active managed risks: {risk_register.get('active_risks', 0)}",
        f"- Overdue risks: {risk_register.get('overdue_risks', 0)}",
        f"- Risk lifecycle status: {risk_register.get('by_status', {})}",
        f"- Model risk assessments: {model_risk.get('assessment_count', 0)}",
        f"- Latest model risk: {model_risk.get('latest_score', 0.0)} ({model_risk.get('latest_severity', 'NO_DATA')})",
        "",
        "## Continuous Monitoring",
        "",
        f"- Risk trend: {_humanize_label(monitoring.get('trend', 'NO_DATA'))}",
        f"- Enabled schedules: {monitoring.get('enabled_schedules', 0)} of {monitoring.get('total_schedules', 0)}",
        f"- Overdue schedules: {monitoring.get('overdue_schedules', 0)}",
        f"- Assessment runs: {monitoring.get('total_runs', 0)}",
        f"- Runs by status: {monitoring.get('runs_by_status', {})}",
        f"- Failed runs: {monitoring.get('failed_runs', 0)}",
        "",
        "## Trustworthiness",
        "",
        f"- Latest score: {trust.get('latest_score', 0.0)}",
        f"- Average score: {trust.get('average_score', 0.0)}",
        f"- Trend: {_humanize_label(trust.get('trend', 'NO_DATA'))}",
        f"- By level: {trust.get('by_level', {})}",
        "",
        "## Monitoring Alerts",
        "",
        f"- Status: {_humanize_label(alerts.get('status', 'UNKNOWN'))}",
        f"- By severity: {alerts.get('by_severity', {})}",
        "",
        "## Governance",
        "",
        f"- Status: {_humanize_label(governance.get('status', 'UNKNOWN'))}",
        f"- Control status: {governance.get('control_summary', {}).get('by_status', {})}",
        f"- Control coverage by domain: {governance.get('control_summary', {}).get('by_domain', {})}",
        f"- Approved evidence: {governance_evidence.get('approved_evidence', 0)}",
        f"- Pending evidence: {governance_evidence.get('pending_evidence', 0)}",
        f"- Expired approved evidence: {governance_evidence.get('expired_approved_evidence', 0)}",
        f"- Retained report snapshots: {report_snapshots.get('total_snapshots', 0)}",
        f"- Signed report snapshots: {report_snapshots.get('signed_snapshots', 0)}",
        "",
        "## Agentic Runtime",
        "",
        f"- Sessions: {agentic_runtime.get('total_sessions', 0)}",
        f"- Active sessions: {agentic_runtime.get('active_sessions', 0)}",
        f"- Authorization decisions: {agentic_runtime.get('total_decisions', 0)}",
        f"- Decisions by outcome: {agentic_runtime.get('decisions_by_outcome', {})}",
        f"- Allowed external calls: {agentic_runtime.get('allowed_external_calls', 0)}",
        "",
        "## Compliance Evidence",
        "",
        f"- Status: {_humanize_label(compliance.get('status', 'NO_EVALUATION'))}",
        f"- Scope: {compliance.get('scope', {}).get('frameworks', [])}",
        f"- Summary: {compliance.get('summary', {})}",
        f"- Assessment basis: {compliance.get('assessment_basis', '')}",
        "",
        "## Standards Coverage",
        "",
        f"- Frameworks: {standards.get('frameworks', [])}",
        f"- Covered frameworks: {standards.get('covered_frameworks', [])}",
        f"- Uncovered frameworks: {standards.get('uncovered_frameworks', [])}",
        "",
        "## Supply Chain",
        "",
        f"- Registered models: {supply_chain.get('registered_models', 0)}",
        f"- Models with vulnerability scans: {supply_chain.get('models_with_vulnerability_scans', 0)}",
        f"- Known vulnerability matches: {supply_chain.get('known_vulnerability_matches', 0)}",
        f"- Advisory catalog records: {supply_chain.get('vulnerability_advisories', 0)}",
        f"- Advisory intelligence: {_humanize_label(supply_chain.get('advisory_feed_status', 'UNVERIFIED'))}",
        f"- Verified advisory feeds: {supply_chain.get('verified_advisory_feeds', 0)}",
        f"- Stale advisory feeds: {supply_chain.get('stale_advisory_feeds', 0)}",
        f"- Scan status: {supply_chain.get('vulnerability_scans_by_status', {})}",
        "",
        "## Technical Explainability",
        "",
        f"- LLM06 basis: {(explainability.get('analysis_basis') or {}).get('llm06_basis', 'Unknown.')}",
        f"- Binary/file analysis: {(explainability.get('analysis_basis') or {}).get('binary_file_analysis', {})}",
        f"- Declared agent fields reviewed: {(explainability.get('analysis_basis') or {}).get('declared_agent_fields', [])}",
        f"- Artifacts summarized: {(explainability.get('summary') or {}).get('artifact_count', 0)}",
        "",
        "## Recommended Actions",
        "",
    ]
    if actions:
        lines.extend(
            f"- [{item.get('priority', 'P3')}] {item.get('title', 'Action')}: {item.get('reason', '')}"
            for item in actions
        )
    else:
        lines.append("- No immediate actions identified from current evidence.")
    return "\n".join(lines) + "\n"


def _empty_report(
    generated_at: str, scope: dict[str, Any] | None = None
) -> dict[str, Any]:
    scope = scope or _report_scope()
    return {
        "report_type": "AI Assurance Compliance Report",
        "schema_version": "1.0",
        "generated_at": generated_at,
        "scope": scope,
        "executive_summary": {
            "overall_status": "NO_EVIDENCE",
            "current_risk_score": 0.0,
            "open_governance_gaps": 0,
            "registered_models": 0,
            "active_managed_risks": 0,
            "known_dependency_vulnerabilities": 0,
        },
        "model_inventory": {
            "total_models": 0,
            "by_risk": {},
            "by_source": {},
            "by_publisher": {},
            "by_registrant": {},
            "distinct_publishers": 0,
            "distinct_registrants": 0,
            "models": [],
        },
        "risk_posture": {
            "finding_records": 0,
            "finding_items": 0,
            "average_record_score": 0.0,
            "by_type": {},
            "by_severity": {},
        },
        "risk_register": {
            "evaluated_at": generated_at,
            "total_risks": 0,
            "active_risks": 0,
            "actionable_risks": 0,
            "accepted_risks": 0,
            "resolved_risks": 0,
            "overdue_risks": 0,
            "unassigned_high_or_critical": 0,
            "by_status": {},
            "by_severity": {},
            "actionable_by_severity": {},
            "by_type": {},
        },
        "model_risk": {
            "assessment_count": 0,
            "average_score": 0.0,
            "latest_score": 0.0,
            "latest_severity": "NO_DATA",
            "by_severity": {},
            "by_indicator": {},
            "assessment_versions": {},
        },
        "trustworthiness": {
            "latest_score": 0.0,
            "latest_level": "NO_DATA",
            "average_score": 0.0,
            "trend": "NO_DATA",
            "by_level": {},
            "metric_count": 0,
        },
        "continuous_monitoring": {
            "trend": "NO_DATA",
            "current_average": 0.0,
            "previous_average": 0.0,
            "delta": 0.0,
            "metrics": [],
            "total_schedules": 0,
            "enabled_schedules": 0,
            "overdue_schedules": 0,
            "total_runs": 0,
            "runs_by_status": {},
            "failed_runs": 0,
            "latest_run_at": None,
        },
        "governance": {
            "status": "NO_EVIDENCE",
            "control_summary": {},
            "open_gaps": [],
            "evaluations": 0,
        },
        "governance_evidence": {
            "evaluated_at": generated_at,
            "total_evidence": 0,
            "pending_evidence": 0,
            "approved_evidence": 0,
            "rejected_evidence": 0,
            "expired_evidence": 0,
            "expired_approved_evidence": 0,
            "by_control": {},
            "by_type": {},
        },
        "agentic_runtime": {
            "total_sessions": 0,
            "active_sessions": 0,
            "sessions_by_status": {},
            "total_decisions": 0,
            "decisions_by_outcome": {},
            "denied_decisions": 0,
            "approval_required_decisions": 0,
            "allowed_external_calls": 0,
            "decisions_by_tool": {},
        },
        "report_snapshots": {
            "total_snapshots": 0,
            "signed_snapshots": 0,
            "unsigned_snapshots": 0,
            "by_scope": {},
            "snapshot_versions": {},
            "report_versions": {},
            "latest_created_at": None,
        },
        "compliance": build_compliance_matrix([], None),
        "standards_coverage": {
            "frameworks": FRAMEWORKS,
            "covered_frameworks": [],
            "uncovered_frameworks": FRAMEWORKS,
            "by_framework": {},
            "controls_by_framework": {},
            "framework_profiles": _framework_profiles(),
        },
        "technical_explainability": {
            "summary": {
                "artifact_count": 0,
                "registry_record_count": 0,
                "finding_count": 0,
                "governance_evaluation_count": 0,
                "control_evidence_count": 0,
            },
            "analysis_basis": {
                "llm06_basis": (
                    "LLM06 Excessive Agency is assessed from declared tools, permissions, "
                    "autonomy, workflow, delegation, policy, and mitigating controls."
                ),
                "binary_file_analysis": {
                    "hashes_and_dependency_inventory": True,
                    "reverse_engineers_model_weights": False,
                },
                "storage_locations": [],
                "declared_agent_fields": list(_AGENT_DECLARATION_FIELDS),
            },
            "artifacts": [],
        },
        "supply_chain": {
            "registered_models": 0,
            "models_by_risk": {},
            "models_with_training_artifacts": 0,
            "models_with_deployment_pipeline": 0,
            "models_with_dependency_discovery": 0,
            "models_with_provenance_attestations": 0,
            "models_with_vulnerability_scans": 0,
            "models_with_known_vulnerabilities": 0,
            "known_vulnerability_matches": 0,
            "vulnerability_advisories": 0,
            "active_vulnerability_advisories": 0,
            "advisory_feed_status": "UNVERIFIED",
            "advisory_feed_snapshots": 0,
            "verified_advisory_feeds": 0,
            "stale_advisory_feeds": 0,
            "authenticated_advisory_records": 0,
            "unverified_advisory_records": 0,
            "advisory_feeds": [],
            "vulnerability_scans_by_status": {},
            "supply_chain_findings": 0,
        },
        "monitoring_alerts": {
            "status": "OK",
            "total_alerts": 0,
            "by_severity": {},
            "alerts": [],
        },
        "assurance_questions": {},
        "risk_score_context": {
            "scale_label": "0-10",
            "minimum": 0.0,
            "maximum": 10.0,
            "higher_is_worse": True,
            "methodology": "severity_weighted_mean_with_floor_and_density",
            "bands": [],
            "current_score": 0.0,
            "current_band": "LOW",
            "next_threshold": 3.0,
        },
        "recommended_actions": [],
        "visualizations": {},
        "evidence_inventory": {
            "finding_records": 0,
            "finding_items": 0,
            "audit_logs": 0,
            "historical_metrics": 0,
            "registered_models": 0,
            "monitoring_schedules": 0,
            "monitoring_runs": 0,
            "risk_register_items": 0,
            "vulnerability_advisories": 0,
            "advisory_feed_snapshots": 0,
            "control_evidence": 0,
            "agent_sessions": 0,
            "tool_invocation_decisions": 0,
            "assurance_report_snapshots": 0,
        },
    }


def _executive_summary(
    finding_records: list[dict[str, Any]],
    finding_items: list[dict[str, Any]],
    latest_governance: dict[str, Any] | None,
    models: list[dict[str, Any]],
    risks: list[dict[str, Any]],
) -> dict[str, Any]:
    avg_score = _average([record.get("score", 0.0) for record in finding_records])
    open_gaps = len(latest_governance.get("gaps", [])) if latest_governance else 0
    high_or_critical = sum(
        1
        for item in finding_items
        if item.get("severity") in {"HIGH", "CRITICAL"}
    )
    active_priority = sum(
        1
        for risk in risks
        if risk.get("status") != "RESOLVED"
        and risk.get("severity") in {"HIGH", "CRITICAL"}
    )
    priority_risks = active_priority if risks else high_or_critical
    known_vulnerability_matches = sum(
        int((model.get("vulnerability_scan") or {}).get("match_count", 0) or 0)
        for model in models
    )

    if not finding_records and not latest_governance:
        status = "NO_EVIDENCE"
    elif open_gaps or priority_risks:
        status = "NEEDS_REVIEW"
    else:
        status = "PASS"

    return {
        "overall_status": status,
        "current_risk_score": round(avg_score, 3),
        "high_or_critical_findings": high_or_critical,
        "active_high_or_critical_risks": active_priority,
        "open_governance_gaps": open_gaps,
        "registered_models": len(models),
        "active_managed_risks": sum(
            1 for risk in risks if risk.get("status") != "RESOLVED"
        ),
        "known_dependency_vulnerabilities": known_vulnerability_matches,
    }


def _risk_posture(finding_records: list[dict[str, Any]], finding_items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "finding_records": len(finding_records),
        "finding_items": len(finding_items),
        "average_record_score": round(_average([record.get("score", 0.0) for record in finding_records]), 3),
        "by_type": _count_by(finding_items, "type"),
        "by_severity": _count_by(finding_items, "severity"),
    }


def _model_risk_summary(
    finding_items: list[dict[str, Any]], metrics: list[dict[str, Any]]
) -> dict[str, Any]:
    model_metrics = [
        metric for metric in metrics if metric.get("metric_name") == "model_risk_score"
    ]
    if model_metrics:
        latest = model_metrics[0]
        indicators = [
            {"indicator": indicator}
            for metric in model_metrics
            for indicator in (metric.get("dimensions") or {}).get("indicators", [])
        ]
        versions = [
            {
                "version": (metric.get("dimensions") or {}).get(
                    "assessment_version", "unknown"
                )
            }
            for metric in model_metrics
        ]
        severities = [
            {
                "severity": (metric.get("dimensions") or {}).get(
                    "severity", "UNKNOWN"
                )
            }
            for metric in model_metrics
        ]
        return {
            "assessment_count": len(model_metrics),
            "average_score": round(
                _average(
                    [metric.get("metric_value", 0.0) for metric in model_metrics]
                ),
                3,
            ),
            "latest_score": round(
                float(latest.get("metric_value", 0.0) or 0.0), 3
            ),
            "latest_severity": (latest.get("dimensions") or {}).get(
                "severity", "UNKNOWN"
            ),
            "by_severity": _count_by(severities, "severity"),
            "by_indicator": _count_by(indicators, "indicator"),
            "assessment_versions": _count_by(versions, "version"),
        }

    assessments = [
        item for item in finding_items if item.get("type") == "model_risk"
    ]
    if not assessments:
        return {
            "assessment_count": 0,
            "average_score": 0.0,
            "latest_score": 0.0,
            "latest_severity": "NO_DATA",
            "by_severity": {},
            "by_indicator": {},
            "assessment_versions": {},
        }

    latest = max(assessments, key=lambda item: item.get("timestamp") or "")
    indicators = [
        {"indicator": indicator}
        for assessment in assessments
        for indicator in assessment.get("indicators", [])
    ]
    versions = [
        {"version": (assessment.get("detail") or {}).get("assessment_version", "unknown")}
        for assessment in assessments
    ]
    return {
        "assessment_count": len(assessments),
        "average_score": round(
            _average([item.get("risk_score", 0.0) for item in assessments]), 3
        ),
        "latest_score": round(float(latest.get("risk_score", 0.0) or 0.0), 3),
        "latest_severity": latest.get("severity", "UNKNOWN"),
        "by_severity": _count_by(assessments, "severity"),
        "by_indicator": _count_by(indicators, "indicator"),
        "assessment_versions": _count_by(versions, "version"),
    }


def _risk_register_summary(
    risks: list[dict[str, Any]], generated_at: str
) -> dict[str, Any]:
    actionable = [
        risk for risk in risks if risk.get("status") in {"OPEN", "IN_PROGRESS"}
    ]
    active = [risk for risk in risks if risk.get("status") != "RESOLVED"]
    priority = [
        risk
        for risk in actionable
        if risk.get("severity") in {"HIGH", "CRITICAL"}
    ]
    return {
        "evaluated_at": generated_at,
        "total_risks": len(risks),
        "active_risks": len(active),
        "actionable_risks": len(actionable),
        "accepted_risks": sum(
            1 for risk in risks if risk.get("status") == "ACCEPTED"
        ),
        "resolved_risks": sum(
            1 for risk in risks if risk.get("status") == "RESOLVED"
        ),
        "overdue_risks": sum(
            1
            for risk in actionable
            if risk.get("due_at") and risk["due_at"] < generated_at
        ),
        "unassigned_high_or_critical": sum(
            1
            for risk in actionable
            if not risk.get("owner")
            and risk.get("severity") in {"HIGH", "CRITICAL"}
        ),
        "by_status": _count_by(risks, "status"),
        "by_severity": _count_by(risks, "severity"),
        "actionable_by_severity": _count_by(actionable, "severity"),
        "by_type": _count_by(risks, "finding_type"),
        "priority_risks": _risk_rows(priority),
        "actionable_risk_rows": _risk_rows(actionable),
    }


def _trustworthiness_summary(
    metrics: list[dict[str, Any]], as_of: str | None = None
) -> dict[str, Any]:
    trust_metrics = [
        metric for metric in metrics if metric.get("metric_name") == "trustworthiness_score"
    ]
    if not trust_metrics:
        return {
            "latest_score": 0.0,
            "latest_level": "NO_DATA",
            "average_score": 0.0,
            "trend": "NO_DATA",
            "drift": _metric_drift_summary(
                [], "trustworthiness_score",
                direction="higher_is_better", metric_min=0.0, metric_max=100.0, as_of=as_of,
            ),
            "by_level": {},
            "metric_count": 0,
        }

    latest = trust_metrics[0]
    latest_score = float(latest.get("metric_value", 0.0) or 0.0)
    # Trustworthiness is higher-is-better on a 0-100 scale; robust drift replaces
    # the previous last-two-point delta.
    drift = _metric_drift_summary(
        metrics, "trustworthiness_score",
        direction="higher_is_better", metric_min=0.0, metric_max=100.0, as_of=as_of,
    )

    by_level: dict[str, int] = {}
    for metric in trust_metrics:
        level = metric.get("dimensions", {}).get("level") or "UNKNOWN"
        by_level[level] = by_level.get(level, 0) + 1

    return {
        "latest_score": round(latest_score, 3),
        "latest_level": latest.get("dimensions", {}).get("level", "UNKNOWN"),
        "average_score": round(_average([metric.get("metric_value", 0.0) for metric in trust_metrics]), 3),
        "trend": drift["trend"],
        "drift": drift,
        "by_level": by_level,
        "metric_count": len(trust_metrics),
    }


def _continuous_monitoring(
    finding_records: list[dict[str, Any]],
    metrics: list[dict[str, Any]],
    schedules: list[dict[str, Any]],
    monitoring_runs: list[dict[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    ordered = sorted(finding_records, key=lambda record: record.get("timestamp") or "")
    midpoint = len(ordered) // 2
    previous = ordered[:midpoint]
    current = ordered[midpoint:]

    previous_average = _average([record.get("score", 0.0) for record in previous])
    current_average = _average([record.get("score", 0.0) for record in current])
    delta = current_average - previous_average if previous else 0.0
    # Aggregate risk score is higher-is-worse on a 0-10 scale; robust per-artifact
    # drift over the persisted risk_score history replaces the split-half delta.
    drift = _metric_drift_summary(
        metrics, "risk_score",
        direction="higher_is_worse", metric_min=0.0, metric_max=10.0, as_of=generated_at,
    )

    return {
        "trend": drift["trend"],
        "drift": drift,
        "current_average": round(current_average, 3),
        "previous_average": round(previous_average, 3),
        "delta": round(delta, 3),
        "metrics": metrics,
        "total_schedules": len(schedules),
        "enabled_schedules": sum(1 for schedule in schedules if schedule.get("enabled")),
        "overdue_schedules": sum(
            1
            for schedule in schedules
            if schedule.get("enabled")
            and (schedule.get("next_run_at") or "") <= generated_at
        ),
        "total_runs": len(monitoring_runs),
        "runs_by_status": _count_by(monitoring_runs, "status"),
        "failed_runs": sum(
            1 for run in monitoring_runs if run.get("status") == "FAILED"
        ),
        "latest_run_at": monitoring_runs[0].get("started_at") if monitoring_runs else None,
    }


def _governance_summary(
    latest_governance: dict[str, Any] | None,
    governance_evaluations: list[dict[str, Any]],
) -> dict[str, Any]:
    if latest_governance is None:
        return {
            "status": "NO_EVIDENCE",
            "control_summary": {},
            "open_gaps": [],
            "evaluations": 0,
        }

    return {
        "status": latest_governance.get("status", "UNKNOWN"),
        "control_summary": latest_governance.get("summary", {}),
        "open_gaps": latest_governance.get("gaps", []),
        "evaluations": len(governance_evaluations),
    }


def _standards_coverage(
    finding_items: list[dict[str, Any]],
    latest_governance: dict[str, Any] | None,
) -> dict[str, Any]:
    by_framework: dict[str, int] = {framework: 0 for framework in FRAMEWORKS}
    controls_by_framework = {framework: set() for framework in FRAMEWORKS}

    for finding in finding_items:
        for mapped in finding.get("mapping", {}).get("controls", []):
            framework = _canonical_framework(mapped.get("standard"))
            if framework:
                by_framework[framework] = by_framework.get(framework, 0) + 1
                controls_by_framework.setdefault(framework, set()).update(mapped.get("controls", []))

    if latest_governance:
        for control in latest_governance.get("controls", []):
            if control.get("status") != "satisfied":
                continue
            for framework_name, standard_controls in control.get("standards", {}).items():
                framework = _canonical_framework(framework_name)
                if framework:
                    by_framework[framework] = by_framework.get(framework, 0) + 1
                    controls_by_framework.setdefault(framework, set()).update(standard_controls)

    covered = sorted([framework for framework, count in by_framework.items() if count > 0])
    uncovered = sorted([framework for framework in FRAMEWORKS if by_framework.get(framework, 0) == 0])
    return {
        "frameworks": FRAMEWORKS,
        "covered_frameworks": covered,
        "uncovered_frameworks": uncovered,
        "by_framework": by_framework,
        "controls_by_framework": {
            framework: sorted(controls)
            for framework, controls in controls_by_framework.items()
            if controls
        },
        "framework_profiles": _framework_profiles(),
    }


def _supply_chain_summary(
    models: list[dict[str, Any]],
    finding_items: list[dict[str, Any]],
    advisories: list[dict[str, Any]],
    advisory_feed_snapshots: list[dict[str, Any]],
    evaluated_at: str,
) -> dict[str, Any]:
    scans = [model.get("vulnerability_scan") or {} for model in models]
    feed_summary = _advisory_feed_summary(
        advisory_feed_snapshots, scans, advisories, evaluated_at
    )
    return {
        "registered_models": len(models),
        "models_by_risk": _count_by(models, "risk_level"),
        "models_with_training_artifacts": sum(1 for model in models if model.get("training_artifacts")),
        "models_with_deployment_pipeline": sum(1 for model in models if model.get("deployment_pipeline")),
        "models_with_dependency_discovery": sum(
            1 for model in models if model.get("dependency_discovery")
        ),
        "models_with_provenance_attestations": sum(
            1 for model in models if model.get("provenance_attestations")
        ),
        "models_with_vulnerability_scans": sum(1 for scan in scans if scan),
        "models_with_known_vulnerabilities": sum(
            1 for scan in scans if scan.get("match_count", 0) > 0
        ),
        "known_vulnerability_matches": sum(
            int(scan.get("match_count", 0) or 0) for scan in scans
        ),
        "vulnerability_advisories": len(advisories),
        "active_vulnerability_advisories": sum(
            1 for advisory in advisories if not advisory.get("withdrawn_at")
        ),
        "vulnerability_scans_by_status": _count_by(scans, "status"),
        "supply_chain_findings": sum(1 for finding in finding_items if finding.get("type") == "supply_chain"),
        **feed_summary,
    }


def _advisory_feed_summary(
    snapshots: list[dict[str, Any]],
    scans: list[dict[str, Any]],
    advisories: list[dict[str, Any]],
    evaluated_at: str,
) -> dict[str, Any]:
    latest_by_feed = {}
    for snapshot in snapshots:
        current = latest_by_feed.get(snapshot.get("feed_id"))
        if current is None or int(snapshot.get("sequence", 0)) > int(
            current.get("sequence", 0)
        ):
            latest_by_feed[snapshot.get("feed_id")] = snapshot

    feeds = [
        {
            "feed_id": snapshot.get("feed_id"),
            "sequence": snapshot.get("sequence"),
            "expires_at": snapshot.get("expires_at"),
            "key_id": snapshot.get("key_id"),
            "sha256": snapshot.get("sha256"),
        }
        for snapshot in latest_by_feed.values()
    ]
    scan_intelligence = [
        scan.get("advisory_intelligence") or {}
        for scan in scans
        if scan.get("advisory_intelligence")
    ]
    if not feeds:
        for scan in scans:
            for feed in (scan.get("advisory_intelligence") or {}).get("feeds", []):
                current = latest_by_feed.get(feed.get("feed_id"))
                if current is None or int(feed.get("sequence", 0)) > int(
                    current.get("sequence", 0)
                ):
                    latest_by_feed[feed.get("feed_id")] = dict(feed)
        feeds = list(latest_by_feed.values())

    stale = [
        feed
        for feed in feeds
        if feed.get("expires_at") and feed["expires_at"] <= evaluated_at
    ]
    authenticated_records = sum(
        1
        for advisory in advisories
        if (advisory.get("metadata") or {}).get("feed_id")
    )
    unverified_records = len(advisories) - authenticated_records
    if not advisories and scan_intelligence:
        authenticated_records = max(
            int(item.get("authenticated_advisory_records", 0) or 0)
            for item in scan_intelligence
        )
        unverified_records = max(
            int(item.get("unverified_advisory_records", 0) or 0)
            for item in scan_intelligence
        )
    scan_statuses = {item.get("status") for item in scan_intelligence}
    if not feeds:
        status = "UNVERIFIED"
    elif stale:
        status = "STALE"
    elif unverified_records or "MIXED" in scan_statuses:
        status = "MIXED"
    else:
        status = "AUTHENTICATED"
    return {
        "advisory_feed_status": status,
        "advisory_feed_snapshots": len(snapshots),
        "verified_advisory_feeds": len(feeds),
        "stale_advisory_feeds": len(stale),
        "authenticated_advisory_records": authenticated_records,
        "unverified_advisory_records": unverified_records,
        "advisory_feeds": feeds,
    }


def _flatten_findings(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for record in records:
        for finding in record.get("findings", []):
            item = dict(finding)
            item["artifact_id"] = record.get("artifact_id")
            item["timestamp"] = record.get("timestamp")
            if "risk_score" not in item and "score" in record:
                item["risk_score"] = record.get("score")
            items.append(item)
    return items


def _safe_list_models(
    datastore: object,
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
) -> list[dict[str, Any]]:
    if registered_by:
        list_models = getattr(datastore, "list_models", None)
        if not list_models:
            return []
        try:
            return list_models(limit=1000, registered_by=registered_by, real_models_only=True)
        except Exception:
            return []
    selected_id = model_id or artifact_id
    if selected_id:
        get_model = getattr(datastore, "get_model", None)
        if not get_model:
            return []
        try:
            model = get_model(selected_id)
            return [model] if model else []
        except Exception:
            return []
    list_models = getattr(datastore, "list_models", None)
    if not list_models:
        return []
    try:
        return list_models(limit=1000, real_models_only=True)
    except Exception:
        return []


def _safe_list_monitoring_schedules(
    datastore: object, artifact_id: str | None = None
) -> list[dict[str, Any]]:
    list_schedules = getattr(datastore, "list_monitoring_schedules", None)
    if not list_schedules:
        return []
    try:
        return list_schedules(limit=1000, artifact_id=artifact_id)
    except Exception:
        return []


def _safe_list_monitoring_runs(
    datastore: object, artifact_id: str | None = None
) -> list[dict[str, Any]]:
    list_runs = getattr(datastore, "list_monitoring_runs", None)
    if not list_runs:
        return []
    try:
        return list_runs(limit=1000, artifact_id=artifact_id)
    except Exception:
        return []


def _safe_list_risks(
    datastore: object, artifact_id: str | None = None
) -> list[dict[str, Any]]:
    list_risks = getattr(datastore, "list_risks", None)
    if not list_risks:
        return []
    try:
        return list_risks(limit=10000, artifact_id=artifact_id)
    except Exception:
        return []


def _safe_list_advisories(datastore: object) -> list[dict[str, Any]]:
    list_advisories = getattr(datastore, "list_advisories", None)
    if not list_advisories:
        return []
    try:
        return list_advisories(limit=100000)
    except Exception:
        return []


def _safe_list_advisory_feed_snapshots(
    datastore: object,
) -> list[dict[str, Any]]:
    list_snapshots = getattr(datastore, "list_advisory_feed_snapshots", None)
    if not list_snapshots:
        return []
    try:
        return list_snapshots(limit=10000)
    except Exception:
        return []


def _safe_list_control_evidence(
    datastore: object, artifact_id: str | None = None
) -> list[dict[str, Any]]:
    list_evidence = getattr(datastore, "list_control_evidence", None)
    if not list_evidence:
        return []
    try:
        return list_evidence(limit=100000, artifact_id=artifact_id)
    except Exception:
        return []


def _safe_list_agent_sessions(
    datastore: object, artifact_id: str | None = None
) -> list[dict[str, Any]]:
    list_sessions = getattr(datastore, "list_agent_sessions", None)
    if not list_sessions:
        return []
    try:
        return list_sessions(limit=100000, artifact_id=artifact_id)
    except Exception:
        return []


def _safe_list_tool_invocations(
    datastore: object, artifact_id: str | None = None
) -> list[dict[str, Any]]:
    list_invocations = getattr(datastore, "list_tool_invocations", None)
    if not list_invocations:
        return []
    try:
        return list_invocations(limit=100000, artifact_id=artifact_id)
    except Exception:
        return []


def _safe_list_report_snapshots(
    datastore: object, artifact_id: str | None = None
) -> list[dict[str, Any]]:
    list_snapshots = getattr(datastore, "list_assurance_report_snapshots", None)
    if not list_snapshots:
        return []
    try:
        return list_snapshots(limit=10000, artifact_id=artifact_id)
    except Exception:
        return []


def _governance_evidence_summary(
    evidence: list[dict[str, Any]], generated_at: str
) -> dict[str, Any]:
    expired = [
        item
        for item in evidence
        if item.get("expires_at") and item["expires_at"] <= generated_at
    ]
    return {
        "evaluated_at": generated_at,
        "total_evidence": len(evidence),
        "pending_evidence": sum(
            1 for item in evidence if item.get("status") == "PENDING"
        ),
        "approved_evidence": sum(
            1 for item in evidence if item.get("status") == "APPROVED"
        ),
        "rejected_evidence": sum(
            1 for item in evidence if item.get("status") == "REJECTED"
        ),
        "expired_evidence": len(expired),
        "expired_approved_evidence": sum(
            1 for item in expired if item.get("status") == "APPROVED"
        ),
        "by_control": _count_by(evidence, "control_id"),
        "by_type": _count_by(evidence, "evidence_type"),
    }


def _agentic_runtime_summary(
    sessions: list[dict[str, Any]], invocations: list[dict[str, Any]]
) -> dict[str, Any]:
    decisions = _count_by(invocations, "decision")
    return {
        "total_sessions": len(sessions),
        "active_sessions": sum(
            1 for session in sessions if session.get("status") == "ACTIVE"
        ),
        "sessions_by_status": _count_by(sessions, "status"),
        "total_decisions": len(invocations),
        "decisions_by_outcome": decisions,
        "denied_decisions": decisions.get("DENY", 0),
        "approval_required_decisions": decisions.get("REQUIRE_APPROVAL", 0),
        "allowed_external_calls": sum(
            1
            for invocation in invocations
            if invocation.get("decision") == "ALLOW"
            and invocation.get("external_call")
        ),
        "decisions_by_tool": _count_by(invocations, "tool"),
    }


def _report_snapshot_summary(
    snapshots: list[dict[str, Any]],
) -> dict[str, Any]:
    signed = sum(1 for snapshot in snapshots if snapshot.get("signature"))
    return {
        "total_snapshots": len(snapshots),
        "signed_snapshots": signed,
        "unsigned_snapshots": len(snapshots) - signed,
        "by_scope": _count_by(snapshots, "scope_type"),
        "snapshot_versions": _count_by(snapshots, "snapshot_version"),
        "report_versions": _count_by(snapshots, "report_version"),
        "latest_created_at": snapshots[0].get("created_at") if snapshots else None,
    }


def _model_inventory_summary(models: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total_models": len(models),
        "by_risk": _count_by(models, "risk_level"),
        "by_source": _count_by(models, "source"),
        "by_publisher": _count_by(
            [{"publisher": model.get("publisher") or "UNDECLARED"} for model in models],
            "publisher",
        ),
        "by_registrant": _count_by(
            [{"registered_by": model.get("registered_by") or "UNDECLARED"} for model in models],
            "registered_by",
        ),
        "distinct_publishers": len(
            {model.get("publisher") for model in models if model.get("publisher")}
        ),
        "distinct_registrants": len(
            {model.get("registered_by") for model in models if model.get("registered_by")}
        ),
        "models": [
            {
                "model_id": model.get("model_id"),
                "model_name": model.get("model_name"),
                "version": model.get("version"),
                "source": model.get("source"),
                "publisher": model.get("publisher"),
                "registered_by": model.get("registered_by"),
                "provenance_score": model.get("provenance_score"),
                "risk_level": model.get("risk_level"),
                "created_at": model.get("created_at"),
                "known_vulnerability_matches": int(
                    (model.get("vulnerability_scan") or {}).get("match_count", 0) or 0
                ),
            }
            for model in models[:100]
        ],
    }


def _technical_explainability(
    scope: dict[str, Any],
    models: list[dict[str, Any]],
    finding_items: list[dict[str, Any]],
    governance_evaluations: list[dict[str, Any]],
    control_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    governance_by_artifact = _latest_governance_by_artifact(governance_evaluations)
    evidence_by_id = {item.get("id"): item for item in control_evidence if item.get("id")}
    registry_by_artifact = {
        str(model.get("model_id")): model
        for model in models
        if model.get("model_id")
    }
    artifact_ids = {
        str(item.get("artifact_id"))
        for item in finding_items
        if item.get("artifact_id") is not None
    }
    artifact_ids.update(str(item) for item in governance_by_artifact if item is not None)
    artifact_ids.update(registry_by_artifact)
    artifacts = []
    for artifact_id in sorted(artifact_ids):
        if not artifact_id or artifact_id == "None":
            continue
        model = registry_by_artifact.get(artifact_id)
        artifacts.append(
            _artifact_explainability(
                artifact_id,
                model,
                finding_items,
                governance_by_artifact.get(artifact_id),
                evidence_by_id,
            )
        )

    return {
        "summary": {
            "artifact_count": len(artifacts),
            "registry_record_count": len(registry_by_artifact),
            "finding_count": len(finding_items),
            "governance_evaluation_count": len(governance_evaluations),
            "control_evidence_count": len(control_evidence),
        },
        "analysis_basis": {
            "scope_type": scope.get("type"),
            "llm06_basis": (
                "LLM06 Excessive Agency is assessed from declared tools, permissions, autonomy, "
                "workflow, delegation, policy constraints, and mitigating controls. "
                "It is not inferred from model weights alone."
            ),
            "binary_file_analysis": {
                "hashes_and_dependency_inventory": True,
                "reverse_engineers_model_weights": False,
                "notes": [
                    "Uploaded or fetched artifacts are hashed for integrity and provenance.",
                    "Dependency manifests and exact package coordinates are discovered when possible.",
                    "Agentic risk analyzers read structured artifact declarations and runtime evidence rather than dissecting weights.",
                ],
            },
            "storage_locations": [
                {
                    "name": "Registered model records",
                    "location": "models table",
                    "details": "Core registry fields plus metadata_json-backed evidence captured at registration.",
                },
                {
                    "name": "Risk findings",
                    "location": "findings table",
                    "details": "Analyzer outputs persisted per artifact_id, including explainable detail payloads.",
                },
                {
                    "name": "Governance evaluations",
                    "location": "audit_logs table",
                    "details": "Latest control evaluation per artifact with missing evidence and mapped standards.",
                },
                {
                    "name": "Control evidence",
                    "location": "control_evidence table",
                    "details": "Approved, pending, or rejected evidence records bound to controls and artifact ids.",
                },
                {
                    "name": "Agent runtime evidence",
                    "location": "agent_sessions and tool_invocation_decisions tables",
                    "details": "Observed runtime policy decisions complement declared agentic evidence.",
                },
            ],
            "declared_agent_fields": list(_AGENT_DECLARATION_FIELDS),
        },
        "artifacts": artifacts[:50],
    }


def _artifact_explainability(
    artifact_id: str,
    model: dict[str, Any] | None,
    finding_items: list[dict[str, Any]],
    governance: dict[str, Any] | None,
    evidence_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    artifact_findings = sorted(
        [
            item
            for item in finding_items
            if str(item.get("artifact_id") or "") == artifact_id
        ],
        key=lambda item: item.get("timestamp") or "",
        reverse=True,
    )
    latest_by_type: dict[str, dict[str, Any]] = {}
    for finding in artifact_findings:
        latest_by_type.setdefault(str(finding.get("type") or "unknown"), finding)

    provenance = _provenance_explainability(model)
    declarations = _declaration_summary(model)
    return {
        "artifact_id": artifact_id,
        "model_id": (model or {}).get("model_id"),
        "model_name": (model or {}).get("model_name") or artifact_id,
        "registry_record_present": model is not None,
        "source": (model or {}).get("source"),
        "source_url": (model or {}).get("source_url"),
        "registered_by": (model or {}).get("registered_by"),
        "publisher": (model or {}).get("publisher"),
        "declarations": declarations,
        "provenance": provenance,
        "findings": [
            _finding_explainability(finding)
            for finding in latest_by_type.values()
        ],
        "governance": _governance_explainability(governance, evidence_by_id),
    }


def _provenance_explainability(model: dict[str, Any] | None) -> dict[str, Any]:
    if not model:
        return {
            "available": False,
            "provenance_score": None,
            "risk_level": None,
            "dimensions": [],
            "trust_caps": [],
            "assessment_complete": False,
        }
    assessment = (
        ((model.get("metadata") or {}).get("provenance_assessment"))
        if isinstance(model.get("metadata"), dict)
        else None
    ) or {}
    dimensions = assessment.get("dimensions") or {}
    return {
        "available": bool(assessment),
        "provenance_score": assessment.get("provenance_score", model.get("provenance_score")),
        "point_estimate": assessment.get("point_estimate"),
        "upper_confidence_bound": assessment.get("upper_confidence_bound"),
        "confidence": assessment.get("confidence"),
        "risk_level": assessment.get("risk_level", model.get("risk_level")),
        "assessment_complete": assessment.get("assessment_complete"),
        "dimensions": _dimension_rows(dimensions),
        "trust_caps": list(assessment.get("trust_caps") or []),
        "indicators": list(assessment.get("indicators") or []),
    }


def _declaration_summary(model: dict[str, Any] | None) -> dict[str, Any]:
    if not model:
        return {
            "present_count": 0,
            "total_count": len(_AGENT_DECLARATION_FIELDS),
            "fields": [],
            "registry_fields": [],
        }
    fields = []
    for field in _AGENT_DECLARATION_FIELDS:
        value = _artifact_field(model, field)
        fields.append(
            {
                "field": field,
                "present": _has_evidence(value),
                "summary": _value_preview(value),
            }
        )
    registry_fields = [
        ("model_id", model.get("model_id")),
        ("model_name", model.get("model_name")),
        ("version", model.get("version")),
        ("source", model.get("source")),
        ("source_url", model.get("source_url")),
        ("publisher", model.get("publisher")),
        ("sha256", model.get("sha256")),
        ("registered_by", model.get("registered_by")),
    ]
    return {
        "present_count": sum(1 for field in fields if field["present"]),
        "total_count": len(fields),
        "fields": fields,
        "registry_fields": [
            {"field": name, "present": _has_evidence(value), "summary": _value_preview(value)}
            for name, value in registry_fields
        ],
    }


def _finding_explainability(finding: dict[str, Any]) -> dict[str, Any]:
    raw_detail = finding.get("detail")
    # Some finding producers (e.g. deployment_verifier) set "detail" to a plain
    # human-readable string rather than a structured dict; treat those as
    # having no structured sub-fields instead of crashing on .get().
    detail = raw_detail if isinstance(raw_detail, dict) else {}
    detail_summary = raw_detail if isinstance(raw_detail, str) else None
    tool_results = list(detail.get("tool_results") or [])
    return {
        "finding_type": finding.get("type"),
        "severity": finding.get("severity"),
        "risk_score": finding.get("risk_score"),
        "timestamp": finding.get("timestamp"),
        "summary": detail_summary or finding.get("title"),
        "methodology": detail.get("methodology"),
        "confidence": detail.get("confidence"),
        "assessment_complete": detail.get("assessment_complete"),
        "dimensions": _dimension_rows(detail.get("dimensions") or {}),
        "interactions": list(detail.get("interactions") or []),
        "triggered_factors": list(detail.get("factors") or []),
        "control_assessment": detail.get("control_assessment") or {},
        "score_gates": list(detail.get("score_gates") or []),
        "policy_violations": list(detail.get("policy_violations") or []),
        "workflow_risks": list(detail.get("workflow_risks") or []),
        "evidence": detail.get("evidence") or {},
        "tool_results": tool_results[:25],
        "highest_risk_tool": detail.get("highest_risk_tool"),
        "highest_risk_tier": detail.get("highest_risk_tier"),
    }


def _governance_explainability(
    governance: dict[str, Any] | None,
    evidence_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if governance is None:
        return {
            "status": "NO_EVALUATION",
            "evaluated_at": None,
            "missing_controls": [],
            "satisfied_controls": 0,
            "missing_controls_count": 0,
        }
    missing_controls = []
    for control in governance.get("controls", []):
        if control.get("status") != "missing":
            continue
        evidence_records = [
            evidence_by_id[evidence_id]
            for evidence_id in control.get("evidence_record_ids", [])
            if evidence_id in evidence_by_id
        ]
        missing = list(control.get("missing_evidence") or [])
        provided = list(control.get("provided_evidence") or [])
        missing_controls.append(
            {
                "control_id": control.get("id"),
                "title": control.get("title"),
                "objective": control.get("objective"),
                "domain": control.get("domain"),
                "missing_evidence": missing,
                "provided_evidence": provided,
                "why_missing": (
                    f"Missing evidence fields: {', '.join(missing) or 'none recorded'}. "
                    f"Currently provided: {', '.join(provided) or 'none'}."
                ),
                "evidence_record_ids": list(control.get("evidence_record_ids") or []),
                "evidence_records": [
                    {
                        "id": record.get("id"),
                        "status": record.get("status"),
                        "evidence_type": record.get("evidence_type"),
                        "reference": record.get("reference"),
                        "evidence_fields": list(record.get("evidence_fields") or []),
                    }
                    for record in evidence_records
                ],
                "standards": control.get("standards") or {},
            }
        )
    return {
        "status": governance.get("status"),
        "evaluated_at": governance.get("timestamp"),
        "missing_controls": missing_controls[:50],
        "satisfied_controls": sum(
            1 for control in governance.get("controls", []) if control.get("status") == "satisfied"
        ),
        "missing_controls_count": len(missing_controls),
    }


def _latest_governance_by_artifact(
    governance_evaluations: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    latest = {}
    for evaluation in governance_evaluations:
        details = evaluation.get("details") or {}
        artifact_id = str(details.get("artifact_id") or "")
        if not artifact_id:
            continue
        current = latest.get(artifact_id)
        timestamp = details.get("timestamp") or ""
        if current is None or timestamp >= str(current.get("timestamp") or ""):
            latest[artifact_id] = details
    return latest


def _dimension_rows(dimensions: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for name, payload in dimensions.items():
        payload = payload if isinstance(payload, dict) else {"value": payload}
        rows.append(
            {
                "name": name,
                "score": payload.get("score"),
                "value": payload.get("value"),
                "confidence": payload.get("confidence"),
                "lower_bound": payload.get("lower_bound"),
                "upper_bound": payload.get("upper_bound"),
                "signals": payload.get("signals"),
                "checks": payload.get("checks"),
                "risk_count": payload.get("risk_count"),
            }
        )
    return rows


def _artifact_field(model: dict[str, Any], field: str) -> Any:
    if field in model:
        return model.get(field)
    metadata = model.get("metadata")
    if isinstance(metadata, dict):
        return metadata.get(field)
    return None


def _value_preview(value: Any) -> str:
    if value is None:
        return "Not declared"
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    if isinstance(value, str):
        return value.strip() or "Not declared"
    if isinstance(value, dict):
        return f"{len(value)} field{'s' if len(value) != 1 else ''} declared" if value else "Not declared"
    if isinstance(value, (list, tuple, set)):
        size = len(value)
        return f"{size} item{'s' if size != 1 else ''} declared" if size else "Not declared"
    return str(value)


def _has_evidence(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _assurance_questions(report: dict[str, Any]) -> dict[str, Any]:
    scope = report.get("scope", {})
    summary = report.get("executive_summary", {})
    governance = report.get("governance", {})
    trust = report.get("trustworthiness", {})
    monitoring = report.get("continuous_monitoring", {})
    supply = report.get("supply_chain", {})
    compliance = report.get("compliance", {})
    inventory = report.get("model_inventory", {})
    alerts = report.get("monitoring_alerts", {})
    scope_type = scope.get("type", "PORTFOLIO")

    if scope_type == "MODEL":
        scope_answer = (
            f"This report is scoped to model {scope.get('model_id')} and its linked assurance evidence."
        )
    elif scope_type == "REGISTRANT":
        scope_answer = (
            f"This report is scoped to models registered by {scope.get('registered_by')}."
        )
    elif scope_type == "ARTIFACT":
        scope_answer = (
            f"This report is scoped to artifact {scope.get('artifact_id')} and its linked assurance evidence."
        )
    else:
        scope_answer = "This report covers the full assurance portfolio currently stored in the framework."

    supply_answer = (
        f"{inventory.get('total_models', 0)} models are in scope, "
        f"{supply.get('models_with_provenance_attestations', 0)} have provenance attestations, and "
        f"{supply.get('known_vulnerability_matches', 0)} known dependency vulnerability matches are currently recorded."
    )
    attention_answer = (
        f"Overall status is {_humanize_label(summary.get('overall_status', 'UNKNOWN'))}, with "
        f"{summary.get('open_governance_gaps', 0)} governance gaps, "
        f"{summary.get('active_high_or_critical_risks', 0)} active high-or-critical managed risks, and "
        f"{alerts.get('total_alerts', 0)} monitoring alerts."
    )
    control_answer = (
        f"Compliance status is {_humanize_label(compliance.get('status', 'NO_EVALUATION'))} and governance status is "
        f"{_humanize_label(governance.get('status', 'NO_EVIDENCE'))}."
    )
    trend_answer = (
        f"Trustworthiness trend is {_humanize_label(trust.get('trend', 'NO_DATA'))} and monitoring trend is "
        f"{_humanize_label(monitoring.get('trend', 'NO_DATA'))}."
    )
    return {
        "what_is_in_scope": {"answer": scope_answer},
        "can_we_trust_the_supply_chain": {"answer": supply_answer},
        "what_needs_attention_now": {"answer": attention_answer},
        "are_controls_and_evidence_sufficient": {"answer": control_answer},
        "what_is_changing_over_time": {"answer": trend_answer},
    }


def _recommended_actions(report: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    summary = report.get("executive_summary", {})
    report.get("governance", {})
    compliance = report.get("compliance", {})
    supply = report.get("supply_chain", {})
    trust = report.get("trustworthiness", {})
    monitoring = report.get("continuous_monitoring", {})
    risk_register = report.get("risk_register", {})

    if summary.get("active_high_or_critical_risks", 0):
        actions.append(
            {
                "priority": "P1",
                "title": "Contain high-risk findings",
                "anchor": "priority-risks",
                "link_text": (
                    f"{summary.get('active_high_or_critical_risks', 0)} active high-or-critical managed risks"
                ),
                "reason": (
                    f"{summary.get('active_high_or_critical_risks', 0)} active high-or-critical managed risks remain unresolved."
                ),
            }
        )
    if summary.get("open_governance_gaps", 0):
        actions.append(
            {
                "priority": "P1",
                "title": "Close governance evidence gaps",
                "anchor": "control-gaps",
                "link_text": (
                    f"{summary.get('open_governance_gaps', 0)} governance controls"
                ),
                "reason": (
                    f"{summary.get('open_governance_gaps', 0)} governance controls are still missing evidence."
                ),
            }
        )
    if risk_register.get("overdue_risks", 0):
        actions.append(
            {
                "priority": "P1",
                "title": "Escalate overdue risks",
                "anchor": "priority-risks",
                "link_text": (
                    f"{risk_register.get('overdue_risks', 0)} actionable risks"
                ),
                "reason": (
                    f"{risk_register.get('overdue_risks', 0)} actionable risks are past due."
                ),
            }
        )
    if supply.get("stale_advisory_feeds", 0):
        actions.append(
            {
                "priority": "P2",
                "title": "Refresh advisory intelligence",
                "anchor": "supply-chain-summary",
                "reason": (
                    f"{supply.get('stale_advisory_feeds', 0)} advisory feeds are stale and may understate exposure."
                ),
            }
        )
    if trust.get("trend") == "WORSENING" or monitoring.get("trend") == "WORSENING":
        actions.append(
            {
                "priority": "P2",
                "title": "Investigate degrading assurance trends",
                "anchor": "risk-score-context",
                "reason": (
                    f"Trust trend is {_humanize_label(trust.get('trend', 'NO_DATA'))} and monitoring trend is {_humanize_label(monitoring.get('trend', 'NO_DATA'))}."
                ),
            }
        )
    if compliance.get("status") in {"CONTROL_GAPS_IDENTIFIED", "NO_EVALUATION"}:
        actions.append(
            {
                "priority": "P2",
                "title": "Re-run compliance evidence review",
                "anchor": "control-gaps",
                "link_text": (
                    f"{compliance.get('summary', {}).get('open_control_gaps', 0)} control gaps"
                ),
                "reason": (
                    f"Compliance posture is {_humanize_label(compliance.get('status', 'NO_EVALUATION'))}."
                ),
            }
        )
    return actions


def _risk_score_context(report: dict[str, Any]) -> dict[str, Any]:
    score = float((report.get("executive_summary") or {}).get("current_risk_score", 0.0) or 0.0)
    bands = [
        {"label": "LOW", "minimum": 0.0, "maximum": 3.0, "description": "Routine exposure with limited immediate concern."},
        {"label": "MEDIUM", "minimum": 3.0, "maximum": 6.0, "description": "Elevated exposure that warrants remediation planning."},
        {"label": "HIGH", "minimum": 6.0, "maximum": 8.0, "description": "Material exposure requiring active containment and ownership."},
        {"label": "CRITICAL", "minimum": 8.0, "maximum": 10.0, "description": "Severe exposure needing immediate action and executive attention."},
    ]
    current_band = "LOW"
    next_threshold = None
    for band in bands:
        lower = band["minimum"]
        upper = band["maximum"]
        if score >= lower and (band["label"] == "CRITICAL" or score < upper):
            current_band = band["label"]
            next_threshold = None if band["label"] == "CRITICAL" else upper
            break
    return {
        "scale_label": "0-10",
        "minimum": 0.0,
        "maximum": 10.0,
        "higher_is_worse": True,
        "methodology": "severity_weighted_mean_with_floor_and_density",
        "bands": bands,
        "current_score": round(score, 3),
        "current_band": current_band,
        "next_threshold": next_threshold,
    }


def _visualizations(report: dict[str, Any], metrics: list[dict[str, Any]]) -> dict[str, Any]:
    posture = report.get("risk_posture", {})
    compliance = report.get("compliance", {})
    inventory = report.get("model_inventory", {})
    return {
        "risk_by_severity": {
            "kind": "bar",
            "title": "Findings by severity",
            "series": _dict_to_series(posture.get("by_severity", {})),
        },
        "risk_by_type": {
            "kind": "bar",
            "title": "Findings by type",
            "series": _dict_to_series(posture.get("by_type", {})),
        },
        "trustworthiness_trend": {
            "kind": "line",
            "title": "Trustworthiness over time",
            "series": _metric_series(metrics, "trustworthiness_score"),
        },
        "risk_score_trend": {
            "kind": "line",
            "title": "Aggregate risk score over time",
            "series": _metric_series(metrics, "risk_score"),
        },
        "framework_coverage": {
            "kind": "bar",
            "title": "Framework coverage",
            "series": [
                {
                    "label": name,
                    "value": float((framework or {}).get("coverage_percent", 0.0) or 0.0),
                    "status": (framework or {}).get("status"),
                }
                for name, framework in (compliance.get("frameworks") or {}).items()
            ],
        },
        "models_by_risk": {
            "kind": "bar",
            "title": "Models by risk level",
            "series": _dict_to_series(inventory.get("by_risk", {})),
        },
    }


def render_assurance_report_html(report: dict[str, Any]) -> str:
    summary = report.get("executive_summary", {})
    scope = report.get("scope", {})
    inventory = report.get("model_inventory", {})
    questions = report.get("assurance_questions", {})
    actions = report.get("recommended_actions", [])
    visualizations = report.get("visualizations", {})
    governance = report.get("governance", {})
    governance_evidence = report.get("governance_evidence", {})
    compliance = report.get("compliance", {})
    risk_register = report.get("risk_register", {})
    standards = report.get("standards_coverage", {})
    trust = report.get("trustworthiness", {})
    monitoring = report.get("continuous_monitoring", {})
    supply = report.get("supply_chain", {})
    technical = report.get("technical_explainability", {})
    alerts = report.get("monitoring_alerts", {})
    risk_score_context = report.get("risk_score_context", {})
    compliance_gaps = (compliance.get("open_control_gaps") or [])[:100]
    priority_risks = (risk_register.get("priority_risks") or [])[:100]
    framework_rows = "".join(
        f"""
        <tr>
          <td>{_framework_link(name, record.get('source_url'))}</td>
          <td>{escape(str(record.get('version') or ''))}</td>
          <td>{escape(_humanize_label(record.get('status') or ''))}</td>
          <td>{escape(str(record.get('applicable_controls') or 0))}</td>
          <td>{escape(str(record.get('satisfied_controls') or 0))}</td>
          <td>{escape(str(record.get('missing_controls') or 0))}</td>
          <td>{escape(str(record.get('coverage_percent') or 0))}%</td>
        </tr>
        """
        for name, record in (compliance.get("frameworks") or {}).items()
    ) or '<tr><td colspan="7">No frameworks in scope.</td></tr>'
    scope_badge = escape(_scope_badge_label(scope))
    category_panels = "".join(
        [
            _html_stat_panel(
                "Supply Chain And Provenance",
                [
                    ("Models in scope", inventory.get("total_models", 0)),
                    (
                        "Provenance attestations",
                        supply.get("models_with_provenance_attestations", 0),
                    ),
                    (
                        "Known vulnerability matches",
                        supply.get("known_vulnerability_matches", 0),
                    ),
                    ("Advisory feed status", _humanize_label(supply.get("advisory_feed_status", "UNVERIFIED"))),
                    ("Distinct publishers", inventory.get("distinct_publishers", 0)),
                ],
            ),
            _html_stat_panel(
                "Risk And Monitoring",
                [
                    ("Overall status", _humanize_label(summary.get("overall_status", "UNKNOWN"))),
                    ("Finding items", report.get("risk_posture", {}).get("finding_items", 0)),
                    (
                        "Active high or critical risks",
                        summary.get("active_high_or_critical_risks", 0),
                        "priority-risks",
                    ),
                    ("Monitoring trend", _humanize_label(monitoring.get("trend", "NO_DATA"))),
                    ("Open alerts", alerts.get("total_alerts", 0), "monitoring-alerts"),
                ],
            ),
            _html_stat_panel(
                "Governance And Compliance",
                [
                    ("Governance status", _humanize_label(governance.get("status", "NO_EVIDENCE"))),
                    ("Open governance gaps", summary.get("open_governance_gaps", 0), "control-gaps"),
                    ("Compliance status", _humanize_label(compliance.get("status", "NO_EVALUATION"))),
                    (
                        "Approved evidence",
                        governance_evidence.get("approved_evidence", 0),
                    ),
                    (
                        "Covered frameworks",
                        len(standards.get("covered_frameworks", [])),
                    ),
                ],
            ),
            _html_stat_panel(
                "Accountability And Scope",
                [
                    ("Scope type", _humanize_label(scope.get("type", "PORTFOLIO"))),
                    ("Distinct registrants", inventory.get("distinct_registrants", 0)),
                    ("Prepared from snapshots", report.get("report_snapshots", {}).get("total_snapshots", 0)),
                    ("Overdue risks", risk_register.get("overdue_risks", 0), "priority-risks"),
                    ("Latest trust level", _humanize_label(trust.get("latest_level", "NO_DATA"))),
                ],
            ),
        ]
    )

    question_cards = "".join(
        f"""
        <article class="question-card">
          <h3>{escape(title.replace('_', ' ').title())}</h3>
          <p>{escape((details or {{}}).get('answer', 'Unknown.'))}</p>
        </article>
        """
        for title, details in questions.items()
    )
    chart_blocks = "".join(
        _render_chart_block(chart)
        for chart in visualizations.values()
        if chart.get("series")
    )
    action_items = "".join(
        _render_action_item(item)
        for item in actions
    ) or "<li>No immediate actions identified from current evidence.</li>"
    risk_rows = "".join(
        f"""
        <tr>
          <td>{escape(str(risk.get('title') or risk.get('indicator') or 'Unnamed risk'))}</td>
          <td>{escape(str(risk.get('artifact_id') or 'Unknown'))}</td>
          <td>{escape(str(risk.get('severity') or 'UNKNOWN'))}</td>
          <td>{escape(str(risk.get('status') or 'UNKNOWN'))}</td>
          <td>{escape(str(risk.get('owner') or 'Unassigned'))}</td>
          <td>{escape(str(risk.get('due_at') or 'Unscheduled'))}</td>
          <td>{escape(str(risk.get('risk_score') if risk.get('risk_score') is not None else 'N/A'))}</td>
        </tr>
        """
        for risk in priority_risks
    ) or '<tr><td colspan="7">No active high-or-critical managed risks are currently recorded.</td></tr>'
    control_gap_rows = "".join(
        f"""
        <tr>
          <td>{_framework_link(gap.get('framework') or 'Unknown', gap.get('framework_source_url') or '')}</td>
          <td>{escape(str(gap.get('control_id') or 'Unknown'))}</td>
          <td>{escape(str(gap.get('title') or 'Untitled control'))}</td>
          <td>{escape(', '.join(gap.get('missing_evidence') or []) or 'Unspecified')}</td>
          <td>{_reference_list_html(gap.get('reference_details') or [], gap.get('references') or [])}</td>
        </tr>
        """
        for gap in compliance_gaps
    ) or '<tr><td colspan="5">No open control gaps are currently recorded.</td></tr>'
    alert_rows = "".join(
        f"""
        <tr>
          <td>{escape(str(alert.get('severity') or 'UNKNOWN'))}</td>
          <td>{escape(str(alert.get('id') or 'unknown'))}</td>
          <td>{escape(str(alert.get('message') or ''))}</td>
        </tr>
        """
        for alert in (alerts.get("alerts") or [])[:100]
    ) or '<tr><td colspan="3">No monitoring alerts are currently active.</td></tr>'
    risk_band_rows = "".join(
        f"""
        <tr class="{('current-band' if band.get('label') == risk_score_context.get('current_band') else '')}">
          <td>{escape(str(band.get('label') or 'UNKNOWN'))}</td>
          <td>{escape(_band_range_label(band))}</td>
          <td>{escape(str(band.get('description') or ''))}</td>
        </tr>
        """
        for band in risk_score_context.get("bands", [])
    )
    model_rows = "".join(
        f"""
        <tr>
          <td>{escape(str(model.get('model_name') or model.get('model_id') or 'Unknown'))}</td>
          <td>{escape(str(model.get('source') or 'Unknown'))}</td>
          <td>{escape(str(model.get('registered_by') or 'Undeclared'))}</td>
          <td>{escape(str(model.get('publisher') or 'Undeclared'))}</td>
          <td>{escape(_humanize_label(str(model.get('risk_level') or 'UNKNOWN')))}</td>
          <td>{escape(_provenance_score_label(model.get('provenance_score')))}</td>
        </tr>
        """
        for model in inventory.get("models", [])[:15]
    ) or '<tr><td colspan="6">No models in scope.</td></tr>'
    explainability_section = _render_explainability_html(technical)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escape(report.get('report_type', 'AI Assurance Report'))}</title>
    <style>
      body {{ margin: 0; font-family: "Avenir Next", "Segoe UI", sans-serif; background: #f3f1ea; color: #18212f; }}
      main {{ width: min(1180px, calc(100vw - 40px)); margin: 0 auto; padding: 28px 0 40px; }}
      header {{ padding: 28px; border-radius: 28px; background: linear-gradient(180deg, rgba(255,255,255,0.96), rgba(245,249,247,0.96)); border: 1px solid #d7e0e6; }}
      h1, h2, h3 {{ margin: 0; letter-spacing: 0; }}
      p, li, td, th {{ line-height: 1.5; }}
      .hero {{ display: grid; gap: 18px; grid-template-columns: 1.3fr 0.9fr; }}
      .stat-grid, .question-grid, .chart-grid {{ display: grid; gap: 14px; }}
      .panel-grid {{ display: grid; gap: 14px; grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 18px; }}
      .stat-grid {{ grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 18px; }}
      .question-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 18px; }}
      .chart-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 18px; }}
      .card, .question-card, .chart-card, .panel {{ background: white; border: 1px solid #dde4ea; border-radius: 20px; padding: 18px; }}
      a.inline-link {{ color: #0f766e; font-weight: 700; text-decoration: none; }}
      a.inline-link:hover {{ text-decoration: underline; }}
      .eyebrow {{ text-transform: uppercase; font-size: 11px; font-weight: 800; letter-spacing: 0.16em; color: #4a5b70; }}
      .stat-value {{ margin-top: 8px; font-size: 30px; font-weight: 800; }}
      .muted {{ color: #5f6f83; }}
      .section {{ margin-top: 20px; }}
      .key-value {{ display: grid; gap: 10px; margin-top: 14px; }}
      .key-value div {{ display: flex; justify-content: space-between; gap: 14px; border-bottom: 1px solid #e8edf1; padding-bottom: 10px; font-size: 14px; }}
      .detail-table th, .detail-table td {{ vertical-align: top; }}
      .current-band td {{ background: #ecfdf5; }}
      details.explainer {{ margin-top: 14px; border: 1px solid #dde4ea; border-radius: 16px; background: #fff; padding: 14px 16px; }}
      details.explainer summary {{ cursor: pointer; font-weight: 700; }}
      .mini-grid {{ display: grid; gap: 14px; grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 14px; }}
      .stack {{ display: grid; gap: 10px; }}
      .subtle-card {{ border: 1px solid #e8edf1; border-radius: 14px; padding: 14px; background: #fbfcfd; }}
      table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
      th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e8edf1; font-size: 14px; }}
      th {{ font-size: 12px; text-transform: uppercase; color: #55657a; }}
      ul {{ margin: 12px 0 0; padding-left: 18px; }}
      .chip {{ display: inline-flex; align-items: center; border-radius: 999px; background: #eef4f8; padding: 4px 9px; font-size: 12px; font-weight: 700; color: #334155; }}
      svg text {{ font-family: inherit; fill: #5f6f83; font-size: 11px; }}
      @media (max-width: 900px) {{ .hero, .stat-grid, .question-grid, .chart-grid, .panel-grid {{ grid-template-columns: 1fr; }} }}
    </style>
  </head>
  <body>
    <main>
      <header>
        <div class="hero">
          <div>
            <div class="eyebrow">AI Assurance Framework</div>
            <h1 style="margin-top:10px; font-size:40px;">{escape(report.get('report_type', 'AI Assurance Report'))}</h1>
            <p class="muted" style="margin-top:12px;">Generated {escape(report.get('generated_at', 'unknown'))}. Scope: <span class="chip">{scope_badge}</span></p>
            <div class="question-grid">
              {question_cards}
            </div>
          </div>
          <aside class="panel">
            <div class="eyebrow">Decision Summary</div>
            <div class="stat-grid" style="grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 14px;">
              <div class="card"><div class="eyebrow">Status</div><div class="stat-value" style="font-size:24px;">{escape(str(summary.get('overall_status', 'UNKNOWN')))}</div></div>
              <div class="card"><div class="eyebrow">Models</div><div class="stat-value" style="font-size:24px;">{inventory.get('total_models', 0)}</div></div>
              <div class="card"><div class="eyebrow">Trust</div><div class="stat-value" style="font-size:24px;">{escape(str(trust.get('latest_level', 'NO_DATA')))}</div></div>
              <div class="card"><div class="eyebrow">Alerts</div><div class="stat-value" style="font-size:24px;"><a class="inline-link" href="#monitoring-alerts">{alerts.get('total_alerts', 0)}</a></div></div>
            </div>
            <div class="section">
              <div class="eyebrow">Immediate Actions</div>
              <ul>{action_items}</ul>
            </div>
          </aside>
        </div>
      </header>

      <section class="section">
        <div class="stat-grid">
          <div class="card"><div class="eyebrow">Governance</div><div class="stat-value">{escape(_humanize_label(str(governance.get('status', 'NO_EVIDENCE'))))}</div></div>
          <div class="card"><div class="eyebrow">Risk Score</div><div class="stat-value"><a class="inline-link" href="#risk-score-context">{summary.get('current_risk_score', 0.0)} {_humanize_label(str(risk_score_context.get('current_band', 'UNKNOWN')))}</a></div></div>
          <div class="card"><div class="eyebrow">Trend</div><div class="stat-value">{escape(_humanize_label(str(monitoring.get('trend', 'NO_DATA'))))}</div></div>
          <div class="card" id="supply-chain-summary"><div class="eyebrow">Supply Chain</div><div class="stat-value">{escape(_humanize_label(str(supply.get('advisory_feed_status', 'UNVERIFIED'))))}</div></div>
        </div>
      </section>

      <section class="section">
        <h2>Assurance Categories</h2>
        <div class="panel-grid">{category_panels}</div>
      </section>

      <section class="section">
        <h2>Charts</h2>
        <div class="chart-grid">{chart_blocks or '<div class="chart-card"><p class="muted">No chartable data is currently available for this scope.</p></div>'}</div>
      </section>

      <section class="section panel" id="risk-score-context">
        <h2>Risk Score Context</h2>
        <p class="muted" style="margin-top:12px;">
          Aggregate risk score is calculated on a 0-10 scale where higher values are worse. The current score is
          <strong> {risk_score_context.get('current_score', 0.0)} </strong>
          and falls in the <strong>{escape(str(risk_score_context.get('current_band', 'UNKNOWN')))}</strong> band.
          {f" The next escalation threshold begins at {risk_score_context.get('next_threshold')}." if risk_score_context.get('next_threshold') is not None else " This is already in the highest severity band."}
        </p>
        <table class="detail-table">
          <thead>
            <tr><th>Band</th><th>Score Range</th><th>Meaning</th></tr>
          </thead>
          <tbody>{risk_band_rows}</tbody>
        </table>
      </section>

      <section class="section panel" id="priority-risks">
        <h2>Priority Risk Queue</h2>
        <p class="muted" style="margin-top:12px;">
          Active managed risks at HIGH or CRITICAL severity, prioritized for containment and remediation.
        </p>
        <table class="detail-table">
          <thead>
            <tr><th>Risk</th><th>Artifact</th><th>Severity</th><th>Status</th><th>Owner</th><th>Due</th><th>Score</th></tr>
          </thead>
          <tbody>{risk_rows}</tbody>
        </table>
      </section>

      <section class="section panel" id="control-gaps">
        <h2>Control Gaps</h2>
        <p class="muted" style="margin-top:12px;">
          Governance controls still missing required evidence for the current report scope.
        </p>
        <table class="detail-table">
          <thead>
            <tr><th>Framework</th><th>Control</th><th>Title</th><th>Missing Evidence</th><th>References</th></tr>
          </thead>
          <tbody>{control_gap_rows}</tbody>
        </table>
      </section>

      <section class="section panel" id="framework-coverage">
        <h2>Framework Coverage Detail</h2>
        <table class="detail-table">
          <thead>
            <tr><th>Framework</th><th>Version</th><th>Status</th><th>Applicable</th><th>Satisfied</th><th>Missing</th><th>Coverage</th></tr>
          </thead>
          <tbody>{framework_rows}</tbody>
        </table>
      </section>

      <section class="section panel" id="monitoring-alerts">
        <h2>Monitoring Alerts</h2>
        <table class="detail-table">
          <thead>
            <tr><th>Severity</th><th>Alert ID</th><th>Message</th></tr>
          </thead>
          <tbody>{alert_rows}</tbody>
        </table>
      </section>

      <section class="section panel" id="models-in-scope">
        <h2>Models In Scope</h2>
        <table>
          <thead>
            <tr><th>Model</th><th>Source</th><th>Registered By</th><th>Publisher</th><th>Risk</th><th>Provenance</th></tr>
          </thead>
          <tbody>{model_rows}</tbody>
        </table>
      </section>

      <section class="section panel" id="technical-explainability">
        <h2>Technical Explainability</h2>
        {explainability_section}
      </section>
    </main>
  </body>
</html>
"""


def _count_by(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(field) or "UNKNOWN"
        counts[value] = counts.get(value, 0) + 1
    return counts


def _report_scope(
    artifact_id: str | None = None,
    model_id: str | None = None,
    registered_by: str | None = None,
) -> dict[str, Any]:
    filters = {
        "artifact_id": str(artifact_id or "").strip() or None,
        "model_id": str(model_id or "").strip() or None,
        "registered_by": str(registered_by or "").strip() or None,
    }
    selected = [key for key, value in filters.items() if value]
    if len(selected) > 1:
        raise ValueError("Choose only one report scope filter: artifact_id, model_id, or registered_by.")
    if filters["model_id"]:
        return {"type": "MODEL", "model_id": filters["model_id"]}
    if filters["registered_by"]:
        return {"type": "REGISTRANT", "registered_by": filters["registered_by"]}
    if filters["artifact_id"]:
        return {"type": "ARTIFACT", "artifact_id": filters["artifact_id"]}
    return {"type": "PORTFOLIO", "artifact_id": None}


def _scope_single_artifact(scope: dict[str, Any]) -> str | None:
    if scope.get("type") == "ARTIFACT":
        return scope.get("artifact_id")
    if scope.get("type") == "MODEL":
        return scope.get("model_id")
    return None


def _scope_artifact_ids(
    scope: dict[str, Any], models: list[dict[str, Any]]
) -> set | None:
    if scope.get("type") == "PORTFOLIO":
        return None
    if scope.get("type") == "REGISTRANT":
        return {
            str(model.get("model_id")).strip()
            for model in models
            if model.get("model_id")
        }
    if scope.get("type") == "MODEL":
        return {scope.get("model_id")}
    return {scope.get("artifact_id")}


def _filter_rows_by_artifact_ids(
    rows: list[dict[str, Any]], artifact_ids: set | None
) -> list[dict[str, Any]]:
    if artifact_ids is None:
        return rows
    return [row for row in rows if row.get("artifact_id") in artifact_ids]


def _filter_report_snapshots_by_scope(
    snapshots: list[dict[str, Any]], scope: dict[str, Any]
) -> list[dict[str, Any]]:
    scope_type = scope.get("type")
    if scope_type == "PORTFOLIO":
        return snapshots
    if scope_type == "ARTIFACT":
        artifact_id = scope.get("artifact_id")
        return [snapshot for snapshot in snapshots if snapshot.get("artifact_id") == artifact_id]
    if scope_type == "MODEL":
        model_id = scope.get("model_id")
        return [
            snapshot
            for snapshot in snapshots
            if (snapshot.get("report") or {}).get("scope", {}).get("model_id") == model_id
            or snapshot.get("artifact_id") == model_id
        ]
    if scope_type == "REGISTRANT":
        registered_by = scope.get("registered_by")
        return [
            snapshot
            for snapshot in snapshots
            if (snapshot.get("report") or {}).get("scope", {}).get("registered_by") == registered_by
        ]
    return snapshots


def _average(values: list[Any]) -> float:
    numeric = [float(value or 0.0) for value in values]
    if not numeric:
        return 0.0
    return sum(numeric) / len(numeric)


def _canonical_framework(framework: str | None) -> str | None:
    if framework is None:
        return None
    return FRAMEWORK_ALIASES.get(framework, framework)


def _framework_profiles() -> dict[str, dict[str, str]]:
    return {
        profile["name"]: {
            "version": profile["version"],
            "source_url": profile["source_url"],
        }
        for profile in STANDARD_PROFILES.values()
    }


def _dict_to_series(counts: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"label": str(label), "value": float(value or 0.0)}
        for label, value in counts.items()
        if float(value or 0.0) > 0
    ]


def _metric_series(metrics: list[dict[str, Any]], metric_name: str) -> list[dict[str, Any]]:
    points = [
        {
            "t": metric.get("created_at"),
            "value": float(metric.get("metric_value", 0.0) or 0.0),
            "artifact_id": metric.get("artifact_id"),
        }
        for metric in metrics
        if metric.get("metric_name") == metric_name
    ]
    return sorted(points, key=lambda item: item.get("t") or "")


def _render_chart_block(chart: dict[str, Any]) -> str:
    kind = chart.get("kind")
    title = escape(str(chart.get("title", "Chart")))
    if kind == "line":
        svg = _svg_line_chart(chart.get("series", []))
    else:
        svg = _svg_bar_chart(chart.get("series", []))
    return f'<article class="chart-card"><h3>{title}</h3><div style="margin-top:12px;">{svg}</div></article>'


def _scope_badge_label(scope: dict[str, Any]) -> str:
    scope_type = scope.get("type")
    if scope_type == "MODEL":
        return f"Model {scope.get('model_id')}"
    if scope_type == "REGISTRANT":
        return f"Registrant {scope.get('registered_by')}"
    if scope_type == "ARTIFACT":
        return f"Artifact {scope.get('artifact_id')}"
    return "Portfolio"


def _html_stat_panel(title: str, rows: list[tuple]) -> str:
    rendered = []
    for row in rows:
        if len(row) == 3:
            label, value, anchor = row
            value_html = f'<a class="inline-link" href="#{escape(str(anchor))}">{escape(str(value))}</a>'
        else:
            label, value = row
            value_html = escape(str(value))
        rendered.append(f"<div><span>{escape(str(label))}</span><strong>{value_html}</strong></div>")
    items = "".join(rendered)
    return (
        f'<article class="panel"><div class="eyebrow">{escape(title)}</div>'
        f'<div class="key-value">{items}</div></article>'
    )


def _render_action_item(item: dict[str, Any]) -> str:
    priority = escape(str(item.get("priority", "P3")))
    title = escape(str(item.get("title", "Action")))
    reason = escape(str(item.get("reason", "")))
    anchor = str(item.get("anchor") or "").strip()
    link_text = str(item.get("link_text") or "").strip()
    if anchor and link_text:
        escaped_link_text = escape(link_text)
        linked_reason = reason.replace(
            escaped_link_text,
            f'<a class="inline-link" href="#{escape(anchor)}">{escaped_link_text}</a>',
            1,
        )
    elif anchor:
        linked_reason = f'{reason} <a class="inline-link" href="#{escape(anchor)}">View details</a>'
    else:
        linked_reason = reason
    return f"<li><strong>{priority}</strong> {title}: {linked_reason}</li>"


def _band_range_label(band: dict[str, Any]) -> str:
    minimum = band.get("minimum", 0.0)
    maximum = band.get("maximum", 10.0)
    if band.get("label") == "CRITICAL":
        return f"{minimum:.1f} - {maximum:.1f}"
    return f"{minimum:.1f} - <{maximum:.1f}"


def _risk_rows(risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ordered = sorted(
        risks,
        key=lambda risk: (
            severity_order.get(str(risk.get("severity") or "LOW").upper(), 9),
            str(risk.get("due_at") or "9999-12-31T23:59:59Z"),
            str(risk.get("artifact_id") or ""),
            str(risk.get("title") or risk.get("indicator") or ""),
        ),
    )
    rows = []
    for risk in ordered[:250]:
        details = risk.get("details") or {}
        rows.append(
            {
                "id": risk.get("id"),
                "artifact_id": risk.get("artifact_id"),
                "finding_type": risk.get("finding_type"),
                "indicator": risk.get("indicator"),
                "title": risk.get("title"),
                "severity": risk.get("severity"),
                "status": risk.get("status"),
                "owner": risk.get("owner"),
                "due_at": risk.get("due_at"),
                "risk_score": details.get("risk_score"),
            }
        )
    return rows


def _framework_link(name: str, url: str) -> str:
    label = escape(str(name or "Unknown"))
    href = escape(str(url or ""))
    if not href:
        return label
    return f'<a class="inline-link" href="{href}" target="_blank" rel="noreferrer">{label}</a>'


def _reference_list_html(
    reference_details: list[dict[str, Any]], fallback_references: list[str]
) -> str:
    details = reference_details or [
        {"label": reference, "summary": reference, "url": ""}
        for reference in fallback_references
    ]
    items = []
    for detail in details:
        label = escape(str(detail.get("label") or ""))
        summary = escape(str(detail.get("summary") or label))
        url = escape(str(detail.get("url") or ""))
        if url:
            items.append(
                f'<a class="inline-link" href="{url}" target="_blank" rel="noreferrer" title="{summary}">{label}</a>'
            )
        else:
            items.append(f'<span title="{summary}">{label}</span>')
    return ", ".join(items) or "None"


def _render_explainability_html(explainability: dict[str, Any]) -> str:
    basis = explainability.get("analysis_basis") or {}
    summary = explainability.get("summary") or {}
    storage_rows = "".join(
        f"<tr><td>{escape(str(item.get('name') or 'Unknown'))}</td><td>{escape(str(item.get('location') or ''))}</td><td>{escape(str(item.get('details') or ''))}</td></tr>"
        for item in (basis.get("storage_locations") or [])
    ) or '<tr><td colspan="3">No storage metadata available.</td></tr>'
    artifact_blocks = "".join(
        _render_explainability_artifact_html(artifact)
        for artifact in (explainability.get("artifacts") or [])
    ) or '<p class="muted" style="margin-top:12px;">No artifact-level explainability is currently available for this scope.</p>'
    binary = basis.get("binary_file_analysis") or {}
    return f"""
      <p class="muted" style="margin-top:12px;">
        {escape(str(basis.get('llm06_basis') or 'Unknown.'))}
      </p>
      <div class="mini-grid">
        <div class="subtle-card">
          <div class="eyebrow">Evidence Summary</div>
          <div class="key-value">
            <div><span>Artifacts summarized</span><strong>{escape(str(summary.get('artifact_count', 0)))}</strong></div>
            <div><span>Registry records</span><strong>{escape(str(summary.get('registry_record_count', 0)))}</strong></div>
            <div><span>Governance evaluations</span><strong>{escape(str(summary.get('governance_evaluation_count', 0)))}</strong></div>
            <div><span>Control evidence records</span><strong>{escape(str(summary.get('control_evidence_count', 0)))}</strong></div>
          </div>
        </div>
        <div class="subtle-card">
          <div class="eyebrow">File And Weight Analysis</div>
          <div class="key-value">
            <div><span>Hashes and dependency inventory</span><strong>{escape(_humanize_label(binary.get('hashes_and_dependency_inventory')))}</strong></div>
            <div><span>Reverse engineers model weights</span><strong>{escape(_humanize_label(binary.get('reverse_engineers_model_weights')))}</strong></div>
          </div>
          <ul>
            {''.join(f"<li>{escape(str(note))}</li>" for note in (binary.get('notes') or []))}
          </ul>
        </div>
      </div>
      <div class="section">
        <h3>Where The Evidence Lives</h3>
        <table class="detail-table">
          <thead><tr><th>Evidence Source</th><th>Location</th><th>What AIAF Reads</th></tr></thead>
          <tbody>{storage_rows}</tbody>
        </table>
      </div>
      <div class="section stack">
        {artifact_blocks}
      </div>
    """


def _render_explainability_artifact_html(artifact: dict[str, Any]) -> str:
    declarations = (artifact.get("declarations") or {}).get("fields") or []
    registry_fields = (artifact.get("declarations") or {}).get("registry_fields") or []
    provenance = artifact.get("provenance") or {}
    governance = artifact.get("governance") or {}
    findings = artifact.get("findings") or []
    registry_rows = "".join(
        f"<tr><td>{escape(str(item.get('field') or ''))}</td><td>{escape(_humanize_label(item.get('present')))}</td><td>{escape(str(item.get('summary') or ''))}</td></tr>"
        for item in registry_fields
    ) or '<tr><td colspan="3">No registry record is linked to this artifact.</td></tr>'
    declaration_rows = "".join(
        f"<tr><td>{escape(str(item.get('field') or ''))}</td><td>{escape(_humanize_label(item.get('present')))}</td><td>{escape(str(item.get('summary') or ''))}</td></tr>"
        for item in declarations
    ) or '<tr><td colspan="3">No agentic declarations are stored for this artifact.</td></tr>'
    provenance_rows = "".join(
        f"<tr><td>{escape(str(item.get('name') or ''))}</td><td>{escape(str(item.get('score') if item.get('score') is not None else 'N/A'))}</td><td>{escape(str(item.get('lower_bound') if item.get('lower_bound') is not None else 'N/A'))}</td><td>{escape(str(item.get('upper_bound') if item.get('upper_bound') is not None else 'N/A'))}</td><td>{escape(str(item.get('confidence') if item.get('confidence') is not None else 'N/A'))}</td></tr>"
        for item in (provenance.get("dimensions") or [])
    ) or '<tr><td colspan="5">No provenance dimension breakdown is available.</td></tr>'
    trust_caps = "".join(
        f"<li><strong>{escape(str(item.get('gate') or 'cap'))}</strong>: maximum score {escape(str(item.get('maximum_score') or ''))}. {escape(str(item.get('reason') or ''))}</li>"
        for item in (provenance.get("trust_caps") or [])
    ) or "<li>No trust caps currently suppress the provenance score.</li>"
    missing_controls = "".join(
        f"<li><strong>{escape(str(item.get('control_id') or 'Unknown'))}</strong> {escape(str(item.get('title') or ''))}: {escape(str(item.get('why_missing') or ''))}</li>"
        for item in (governance.get("missing_controls") or [])
    ) or "<li>No missing controls in the latest governance evaluation.</li>"
    finding_blocks = "".join(_render_finding_explainability_html(finding) for finding in findings) or "<p class=\"muted\">No persisted analyzer findings are currently linked to this artifact.</p>"
    return f"""
      <details class="explainer">
        <summary>{escape(str(artifact.get('model_name') or artifact.get('artifact_id') or 'Artifact'))} ({escape(str(artifact.get('artifact_id') or 'unknown'))})</summary>
        <div class="mini-grid">
          <div class="subtle-card">
            <div class="eyebrow">Registry Fields</div>
            <table class="detail-table">
              <thead><tr><th>Field</th><th>Present</th><th>Value Summary</th></tr></thead>
              <tbody>{registry_rows}</tbody>
            </table>
          </div>
          <div class="subtle-card">
            <div class="eyebrow">Agentic Declarations Used By AIAF</div>
            <p class="muted" style="margin-top:8px;">Present {escape(str((artifact.get('declarations') or {}).get('present_count', 0)))} of {escape(str((artifact.get('declarations') or {}).get('total_count', 0)))} expected agentic fields.</p>
            <table class="detail-table">
              <thead><tr><th>Field</th><th>Present</th><th>Value Summary</th></tr></thead>
              <tbody>{declaration_rows}</tbody>
            </table>
          </div>
        </div>
        <div class="mini-grid">
          <div class="subtle-card">
            <div class="eyebrow">Provenance Dimension Scores</div>
            <p class="muted" style="margin-top:8px;">Score {escape(str(provenance.get('provenance_score') if provenance.get('provenance_score') is not None else 'N/A'))} with risk level {escape(_humanize_label(provenance.get('risk_level')))}.</p>
            <table class="detail-table">
              <thead><tr><th>Dimension</th><th>Score</th><th>Lower</th><th>Upper</th><th>Confidence</th></tr></thead>
              <tbody>{provenance_rows}</tbody>
            </table>
          </div>
          <div class="subtle-card">
            <div class="eyebrow">Trust Caps And Missing Controls</div>
            <p class="muted" style="margin-top:8px;">These are the conservative gates and governance gaps that keep scores or coverage low.</p>
            <ul>{trust_caps}</ul>
            <ul>{missing_controls}</ul>
          </div>
        </div>
        <div class="section stack">{finding_blocks}</div>
      </details>
    """


def _render_finding_explainability_html(finding: dict[str, Any]) -> str:
    dimension_rows = "".join(
        f"<tr><td>{escape(str(item.get('name') or ''))}</td><td>{escape(str(item.get('score') if item.get('score') is not None else 'N/A'))}</td><td>{escape(str(item.get('value') if item.get('value') is not None else ''))}</td><td>{escape(str(item.get('risk_count') if item.get('risk_count') is not None else ''))}</td></tr>"
        for item in (finding.get("dimensions") or [])
    ) or '<tr><td colspan="4">No dimension breakdown is available.</td></tr>'
    interaction_rows = "".join(
        f"<tr><td>{escape(str(item.get('indicator') or ''))}</td><td>{escape(str(item.get('severity') or ''))}</td><td>{escape(str(item.get('bonus') if item.get('bonus') is not None else ''))}</td><td>{escape(str(item.get('detail') or ''))}</td></tr>"
        for item in (finding.get("interactions") or [])
    ) or '<tr><td colspan="4">No interaction escalations were triggered.</td></tr>'
    factor_rows = "".join(
        f"<tr><td>{escape(str(item.get('indicator') or ''))}</td><td>{escape(str(item.get('dimension') or ''))}</td><td>{escape(str(item.get('severity') or ''))}</td><td>{escape(str(item.get('detail') or ''))}</td></tr>"
        for item in (finding.get("triggered_factors") or [])[:25]
    ) or '<tr><td colspan="4">No triggered factors were recorded.</td></tr>'
    control_rows = "".join(
        f"<tr><td>{escape(str(item.get('control') or ''))}</td><td>{escape(str(item.get('status') or ''))}</td><td>{escape(str(item.get('strength') if item.get('strength') is not None else ''))}</td><td>{escape(str(item.get('evidence_quality') if item.get('evidence_quality') is not None else ''))}</td></tr>"
        for item in ((finding.get("control_assessment") or {}).get("controls") or [])
    ) or '<tr><td colspan="4">No residual-risk control assessment is available.</td></tr>'
    return f"""
      <article class="subtle-card">
        <div class="eyebrow">{escape(_humanize_label(finding.get('finding_type')))}</div>
        <p class="muted" style="margin-top:8px;">
          Score {escape(str(finding.get('risk_score') if finding.get('risk_score') is not None else 'N/A'))},
          severity {escape(_humanize_label(finding.get('severity')))},
          methodology {escape(str(finding.get('methodology') or 'unknown'))},
          confidence {escape(str(finding.get('confidence') if finding.get('confidence') is not None else 'N/A'))}.
        </p>
        <table class="detail-table">
          <thead><tr><th>Dimension</th><th>Score</th><th>Value</th><th>Extra</th></tr></thead>
          <tbody>{dimension_rows}</tbody>
        </table>
        <table class="detail-table">
          <thead><tr><th>Interaction</th><th>Severity</th><th>Bonus</th><th>Detail</th></tr></thead>
          <tbody>{interaction_rows}</tbody>
        </table>
        <table class="detail-table">
          <thead><tr><th>Triggered Factor</th><th>Category</th><th>Severity</th><th>Detail</th></tr></thead>
          <tbody>{factor_rows}</tbody>
        </table>
        <table class="detail-table">
          <thead><tr><th>Residual-Risk Control</th><th>Status</th><th>Strength</th><th>Evidence Quality</th></tr></thead>
          <tbody>{control_rows}</tbody>
        </table>
      </article>
    """


def _humanize_label(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "Unknown"
    if "_" in text:
        return text.replace("_", " ").upper()
    return text


def _provenance_score_label(value: Any) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "Not scored"
    if score >= 85:
        band = "Low provenance risk"
    elif score >= 70:
        band = "Moderate provenance risk"
    elif score >= 50:
        band = "High provenance risk"
    else:
        band = "Critical provenance risk"
    rounded = int(round(score))
    return f"{rounded}/100 ({band})"


def _svg_bar_chart(series: list[dict[str, Any]]) -> str:
    if not series:
        return '<p class="muted">No data.</p>'
    width = 520
    row_height = 28
    left = 130
    right = 16
    top = 12
    max_value = max(float(item.get("value", 0.0) or 0.0) for item in series) or 1.0
    height = top + len(series) * row_height + 18
    bars = []
    for index, item in enumerate(series[:12]):
        label = escape(str(item.get("label", "")))
        value = float(item.get("value", 0.0) or 0.0)
        y = top + index * row_height
        bar_width = ((width - left - right) * value) / max_value
        bars.append(
            f'<text x="4" y="{y + 15}">{label}</text>'
            f'<rect x="{left}" y="{y + 4}" width="{bar_width:.2f}" height="12" rx="6" fill="#0f766e"></rect>'
            f'<text x="{left + bar_width + 8:.2f}" y="{y + 15}">{escape(str(round(value, 2)))}</text>'
        )
    return f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">{"".join(bars)}</svg>'


def _svg_line_chart(series: list[dict[str, Any]]) -> str:
    if len(series) < 2:
        return '<p class="muted">Not enough historical points yet.</p>'
    width = 520
    height = 220
    left = 36
    right = 12
    top = 12
    bottom = 34
    values = [float(item.get("value", 0.0) or 0.0) for item in series]
    min_value = min(values)
    max_value = max(values)
    span = max(max_value - min_value, 1.0)
    coords = []
    for index, item in enumerate(series[:24]):
        x = left + ((width - left - right) * index / max(len(series[:24]) - 1, 1))
        y = top + ((height - top - bottom) * (1 - ((float(item.get("value", 0.0) or 0.0) - min_value) / span)))
        coords.append((x, y, item))
    path = " ".join(
        f"{'M' if idx == 0 else 'L'} {x:.2f} {y:.2f}"
        for idx, (x, y, _) in enumerate(coords)
    )
    dots = "".join(
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3" fill="#b42318"></circle>'
        for x, y, _ in coords
    )
    labels = "".join(
        f'<text x="{x:.2f}" y="{height - 10}">{escape(str((item.get("t") or "")[5:10]))}</text>'
        for x, _, item in coords[:: max(len(coords) // 4, 1)]
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">'
        f'<line x1="{left}" y1="{height - bottom}" x2="{width - right}" y2="{height - bottom}" stroke="#d7e0e6"/>'
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{height - bottom}" stroke="#d7e0e6"/>'
        f'<path d="{path}" fill="none" stroke="#b42318" stroke-width="3" stroke-linecap="round"/>'
        f"{dots}{labels}</svg>"
    )
