"""Deterministic orchestration engine for the AIAF assistant MVP."""

from __future__ import annotations

import re
import uuid
from typing import Any

from .assistant_actor import normalize_actor
from .assistant_authorization import evaluate_write_policy
from .assistant_prompts import (
    ASSISTANT_MODE,
    ASSISTANT_VERSION,
    SUGGESTED_PROMPTS,
    SUPPORTED_INTENTS,
)
from .assistant_workflows import (
    compare_snapshots,
    create_report_snapshot,
    explain_missing_evidence,
    generate_governance_report,
    help_response,
    summarize_agent_authorization,
    summarize_compliance_posture,
    summarize_rag_inventory,
)

_SCOPE_PATTERNS = {
    "artifact_id": re.compile(r"\bartifact(?:\s+id)?\s+([A-Za-z0-9._:/-]+)", re.I),
    "model_id": re.compile(r"\bmodel(?:\s+id)?\s+([A-Za-z0-9._:/-]+)", re.I),
    "registered_by": re.compile(r"\bregistrant(?:\s+id)?\s+([A-Za-z0-9._@:/-]+)", re.I),
}


class AssistantEngine:
    """Constrained assistant facade that maps user asks to safe workflows."""

    def __init__(self, datastore: object):
        self.datastore = datastore

    def capabilities(self) -> dict[str, Any]:
        return {
            "assistant_version": ASSISTANT_VERSION,
            "mode": ASSISTANT_MODE,
            "llm_intent_enabled": False,
            "llm_model_name": None,
            "llm_endpoint_configured": False,
            "supported_intents": list(SUPPORTED_INTENTS),
            "suggested_prompts": list(SUGGESTED_PROMPTS),
            "write_actions_enabled": ["create_report_snapshot"],
            "write_authorization": {
                "confirmation_required": ["create_report_snapshot"],
                "declared_roles_allowed": [
                    "governance-analyst",
                    "governance-admin",
                    "compliance-lead",
                    "platform-owner",
                ],
            },
            "actor_attribution": {
                "request_actor_supported": True,
                "legacy_role_supported": True,
                "authenticated_headers_supported": [
                    "X-AIAF-Principal-Id",
                    "X-AIAF-Principal-Name",
                    "X-AIAF-Auth-Provider",
                    "X-AIAF-Auth-Subject",
                    "X-AIAF-Authenticated",
                ],
            },
        }

    def query(
        self,
        *,
        message: str,
        scope_hint: dict[str, Any] | None = None,
        role: str | None = None,
        actor: dict[str, Any] | None = None,
        confirm_action_id: str | None = None,
        history: list[dict[str, Any]] | None = None,
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = str(message or "").strip()
        conversation_id = str(conversation_id or "").strip() or str(uuid.uuid4())
        actor = normalize_actor(actor, legacy_role=role)
        if not normalized:
            return self._clarification(
                conversation_id=conversation_id,
                message=normalized,
                actor=actor,
                question="What would you like me to do in AIAF? For example: generate a governance report or explain missing evidence.",
            )

        resolution = self._resolve_request(normalized, scope_hint or {})
        scope = resolution["scope"]
        intent = resolution["intent"]
        if resolution.get("clarification_question"):
            return self._clarification(
                conversation_id=conversation_id,
                message=normalized,
                actor=actor,
                question=resolution["clarification_question"],
            )
        if scope.get("_error"):
            return self._clarification(
                conversation_id=conversation_id,
                message=normalized,
                actor=actor,
                question=scope["_error"],
            )
        authorization = evaluate_write_policy(
            intent=intent,
            scope=scope,
            actor=actor,
            confirm_action_id=confirm_action_id,
        )
        if authorization["decision"] == "needs_clarification":
            return self._clarification(
                conversation_id=conversation_id,
                message=normalized,
                actor=actor,
                question=authorization["question"],
                authorization=authorization,
            )
        if authorization["decision"] == "needs_confirmation":
            return self._confirmation(
                conversation_id=conversation_id,
                message=normalized,
                actor=actor,
                intent=intent,
                scope=scope,
                question=authorization["question"],
                authorization=authorization,
            )

        result = self._run_workflow(intent, scope, role=role, actor=actor)
        payload = {
            "status": "completed",
            "assistant_version": ASSISTANT_VERSION,
            "mode": ASSISTANT_MODE,
            "llm_intent_enabled": False,
            "llm_model_name": None,
            "llm_endpoint_configured": False,
            "conversation_id": conversation_id,
            "intent": intent,
            "scope": scope,
            "role": role,
            "actor": actor,
            "authorization": authorization,
            "history_used": bool(history),
            "intent_resolution_source": resolution.get("source", "deterministic"),
            "suggested_prompts": list(SUGGESTED_PROMPTS),
            **result,
        }
        self._audit("assistant_query_completed", scope, normalized, payload)
        return payload

    def _run_workflow(
        self,
        intent: str,
        scope: dict[str, str | None],
        *,
        role: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if intent == "generate_governance_report":
            return generate_governance_report(self.datastore, scope)
        if intent == "summarize_compliance_posture":
            return summarize_compliance_posture(self.datastore, scope)
        if intent == "explain_missing_evidence":
            return explain_missing_evidence(self.datastore, scope)
        if intent == "compare_snapshots":
            return compare_snapshots(self.datastore, scope)
        if intent == "create_report_snapshot":
            return create_report_snapshot(self.datastore, scope, actor=actor)
        if intent == "summarize_agent_authorization":
            return summarize_agent_authorization(self.datastore, scope)
        if intent == "summarize_rag_inventory":
            return summarize_rag_inventory(self.datastore, scope)
        return help_response()

    def _resolve_intent(self, message: str) -> str:
        text = message.casefold()
        if (
            ("snapshot" in text and any(word in text for word in ("create", "save", "store")))
            or "save this report" in text
        ):
            return "create_report_snapshot"
        if "snapshot" in text and any(word in text for word in ("compare", "change", "difference", "latest two")):
            return "compare_snapshots"
        if any(word in text for word in ("missing evidence", "missing control", "evidence gap", "approval blocker", "approval blockers")):
            return "explain_missing_evidence"
        if "compliance" in text:
            return "summarize_compliance_posture"
        if "authorization" in text or ("agent" in text and "decision" in text):
            return "summarize_agent_authorization"
        if "rag" in text or "retrieval" in text or "vector store" in text:
            return "summarize_rag_inventory"
        if "governance" in text or "assurance report" in text or ("report" in text and "generate" in text):
            return "generate_governance_report"
        return "help"

    def _resolve_request(
        self, message: str, scope_hint: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "intent": self._resolve_intent(message),
            "scope": self._resolve_scope(message, scope_hint),
            "clarification_question": None,
            "source": "deterministic",
        }

    def _resolve_scope(
        self, message: str, scope_hint: dict[str, Any]
    ) -> dict[str, str | None]:
        scope = {
            "artifact_id": self._normalize_scope_value(scope_hint.get("artifact_id")),
            "model_id": self._normalize_scope_value(scope_hint.get("model_id")),
            "registered_by": self._normalize_scope_value(scope_hint.get("registered_by")),
        }
        for field, pattern in _SCOPE_PATTERNS.items():
            if scope[field]:
                continue
            match = pattern.search(message)
            if match:
                scope[field] = self._normalize_scope_value(match.group(1))

        selected = [name for name, value in scope.items() if value]
        if len(selected) > 1:
            return {
                "_error": "I can only work with one scope at a time. Please choose one of artifact, model, or registrant.",
            }
        return scope

    def _clarification(
        self,
        *,
        conversation_id: str,
        message: str,
        actor: dict[str, Any] | None,
        question: str,
        authorization: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "status": "needs_clarification",
            "assistant_version": ASSISTANT_VERSION,
            "mode": ASSISTANT_MODE,
            "conversation_id": conversation_id,
            "intent": "help",
            "scope": {"artifact_id": None, "model_id": None, "registered_by": None},
            "role": actor.get("role") if actor else None,
            "actor": actor,
            "authorization": authorization or {
                "decision": "needs_clarification",
                "write_intent": False,
                "confirmation_required": False,
                "confirmation_id": None,
                "policy_basis": "clarification",
            },
            "title": "Need one more detail",
            "summary": question,
            "clarification_question": question,
            "answer_markdown": f"## Need one more detail\n\n{question}",
            "actions_taken": [],
            "artifacts": [],
            "follow_ups": list(SUGGESTED_PROMPTS[:3]),
            "limits": [],
            "suggested_prompts": list(SUGGESTED_PROMPTS),
        }
        self._audit("assistant_query_needs_clarification", payload["scope"], message, payload)
        return payload

    def _confirmation(
        self,
        *,
        conversation_id: str,
        message: str,
        actor: dict[str, Any] | None,
        intent: str,
        scope: dict[str, Any],
        question: str,
        authorization: dict[str, Any],
    ) -> dict[str, Any]:
        payload = {
            "status": "needs_confirmation",
            "assistant_version": ASSISTANT_VERSION,
            "mode": ASSISTANT_MODE,
            "conversation_id": conversation_id,
            "intent": intent,
            "scope": scope,
            "role": actor.get("role") if actor else None,
            "actor": actor,
            "authorization": authorization,
            "title": "Confirm write action",
            "summary": question,
            "clarification_question": question,
            "answer_markdown": "\n".join(
                [
                    "## Confirm write action",
                    "",
                    question,
                    "",
                    f"- Requested action: {intent}",
                    f"- Scope: {scope}",
                    f"- Actor: {(actor or {}).get('attribution_label', 'aiaf-assistant')}",
                ]
            ),
            "actions_taken": [],
            "artifacts": [],
            "follow_ups": [],
            "limits": [
                "Write actions need explicit confirmation in this assistant version.",
            ],
            "suggested_prompts": list(SUGGESTED_PROMPTS),
        }
        self._audit("assistant_query_needs_confirmation", payload["scope"], message, payload)
        return payload

    def _audit(
        self,
        event_type: str,
        scope: dict[str, Any],
        message: str,
        payload: dict[str, Any],
    ) -> None:
        save_audit_log = getattr(self.datastore, "save_audit_log", None)
        if not save_audit_log:
            return
        artifact_id = scope.get("artifact_id") or scope.get("model_id")
        save_audit_log(
            {
                "event_type": event_type,
                "artifact_id": artifact_id,
                "details": {
                    "message": message,
                    "intent": payload.get("intent"),
                    "scope": scope,
                    "status": payload.get("status"),
                    "actor": payload.get("actor"),
                    "authorization": payload.get("authorization"),
                    "actions_taken": payload.get("actions_taken", []),
                },
            }
        )

    @staticmethod
    def _normalize_scope_value(value: Any) -> str | None:
        text = str(value or "").strip()
        return text or None
