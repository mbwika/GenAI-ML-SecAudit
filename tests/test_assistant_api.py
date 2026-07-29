import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _make_store(tmp_path):
    ensure_src()
    from aiaf.data.store import DataStore

    return DataStore(db_path=str(tmp_path / "assistant.db"))


def test_assistant_capabilities_expose_mvp_contract(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import assistant as assistant_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(assistant_api, "get_store", lambda: store)

    result = assistant_api.assistant_capabilities(api_key="dev-key")

    assert result["assistant_version"] == "0.1.0-mvp"
    assert "generate_governance_report" in result["supported_intents"]
    assert "create_report_snapshot" in result["supported_intents"]
    assert result["mode"] == "deterministic-orchestrated"
    assert result["llm_intent_enabled"] is False
    assert result["llm_endpoint_configured"] is False
    assert result["write_actions_enabled"] == ["create_report_snapshot"]
    assert result["write_authorization"]["confirmation_required"] == ["create_report_snapshot"]
    assert result["actor_attribution"]["request_actor_supported"] is True


def test_assistant_query_generates_governance_report(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import assistant as assistant_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(assistant_api, "get_store", lambda: store)

    request = assistant_api.AssistantQueryRequest(
        message="Generate a governance report for artifact artifact-123",
    )

    result = assistant_api.assistant_query(request, api_key="dev-key")

    assert result["status"] == "completed"
    assert result["intent"] == "generate_governance_report"
    assert result["scope"]["artifact_id"] == "artifact-123"
    assert "Governance Report" in result["answer_markdown"]
    assert result["actions_taken"][0]["type"] == "reporting.assurance_report"


def test_assistant_query_requests_clarification_for_conflicting_scope(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import assistant as assistant_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(assistant_api, "get_store", lambda: store)

    request = assistant_api.AssistantQueryRequest(
        message="Generate a governance report",
        scope_hint=assistant_api.AssistantScopeHint(
            artifact_id="artifact-1",
            model_id="model-1",
        ),
    )

    result = assistant_api.assistant_query(request, api_key="dev-key")

    assert result["status"] == "needs_clarification"
    assert "one scope at a time" in result["clarification_question"]


def test_assistant_query_compares_latest_snapshots(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import assistant as assistant_api
    from aiaf.core.report_snapshot_engine import AssuranceReportSnapshotEngine

    store = _make_store(tmp_path)
    monkeypatch.setattr(assistant_api, "get_store", lambda: store)

    snapshot_engine = AssuranceReportSnapshotEngine(store)
    snapshot_engine.create(created_by="tester")
    snapshot_engine.create(created_by="tester")

    request = assistant_api.AssistantQueryRequest(
        message="Compare the latest two snapshots",
    )

    result = assistant_api.assistant_query(request, api_key="dev-key")

    assert result["status"] == "completed"
    assert result["intent"] == "compare_snapshots"
    assert "Snapshot Comparison" in result["answer_markdown"]
    assert result["actions_taken"][0]["type"] == "reporting.snapshots.list"


def test_assistant_query_can_create_snapshot(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import assistant as assistant_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(assistant_api, "get_store", lambda: store)

    request = assistant_api.AssistantQueryRequest(
        message="Create a snapshot for artifact artifact-99",
        role="governance-analyst",
    )

    pending = assistant_api.assistant_query(request, api_key="dev-key")

    assert pending["status"] == "needs_confirmation"
    assert pending["intent"] == "create_report_snapshot"
    assert pending["actor"]["role"] == "governance-analyst"
    assert pending["actor"]["attribution_label"] == "role:governance-analyst"
    assert pending["authorization"]["confirmation_required"] is True

    request.confirm_action_id = pending["authorization"]["confirmation_id"]
    result = assistant_api.assistant_query(request, api_key="dev-key")

    assert result["status"] == "completed"
    assert "Snapshot Created" in result["answer_markdown"]
    assert "Created by: role:governance-analyst" in result["answer_markdown"]
    assert result["actions_taken"][0]["type"] == "reporting.snapshots.create"


def test_assistant_query_requires_write_authority_for_snapshot(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import assistant as assistant_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(assistant_api, "get_store", lambda: store)

    request = assistant_api.AssistantQueryRequest(
        message="Create a snapshot for artifact artifact-101",
    )

    result = assistant_api.assistant_query(request, api_key="dev-key")

    assert result["status"] == "needs_clarification"
    assert result["authorization"]["policy_basis"] == "missing_write_authority"
    assert "authenticated identity or a declared governance role" in result["clarification_question"]


def test_assistant_query_prefers_authenticated_actor_headers(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import assistant as assistant_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(assistant_api, "get_store", lambda: store)

    request = assistant_api.AssistantQueryRequest(
        message="Create a snapshot for artifact artifact-77",
        actor=assistant_api.AssistantActorHint(
            display_name="Policy Team",
            role="governance-analyst",
        ),
    )

    pending = assistant_api.assistant_query(
        request,
        x_aiaf_principal_id="u-123",
        x_aiaf_principal_name="Alex Chen",
        x_aiaf_auth_provider="oidc",
        x_aiaf_auth_subject="alex@example.com",
        x_aiaf_authenticated="true",
        api_key="dev-key",
    )

    assert pending["status"] == "needs_confirmation"
    assert pending["authorization"]["policy_basis"] == "step_up_confirmation"

    request.confirm_action_id = pending["authorization"]["confirmation_id"]
    result = assistant_api.assistant_query(
        request,
        x_aiaf_principal_id="u-123",
        x_aiaf_principal_name="Alex Chen",
        x_aiaf_auth_provider="oidc",
        x_aiaf_auth_subject="alex@example.com",
        x_aiaf_authenticated="true",
        api_key="dev-key",
    )

    assert result["status"] == "completed"
    assert result["actor"]["authenticated"] is True
    assert result["actor"]["principal_id"] == "u-123"
    assert result["actor"]["display_name"] == "Alex Chen"
    assert result["actor"]["attribution_mode"] == "authenticated"
    assert result["actor"]["attribution_label"] == "principal:u-123"
    assert "Created by: principal:u-123" in result["answer_markdown"]

    snapshots = store.list_assurance_report_snapshots(limit=1, artifact_id="artifact-77")
    assert snapshots[0]["created_by"] == "principal:u-123"
