"""Prompt and product copy contracts for the AIAF assistant.

The community assistant is deterministic: it maps known request patterns onto
predefined AIAF workflows and does not call an inference backend. Pro extends
the same Ask AIAF experience with optional LLM-backed intent resolution.
"""

ASSISTANT_VERSION = "0.1.0-mvp"
ASSISTANT_MODE = "deterministic-orchestrated"

SYSTEM_CONTRACT = (
    "You are the AI Assurance Framework assistant. "
    "You do not invent findings or evidence. "
    "You explain only from AIAF workflows and persisted evidence."
)

SUPPORTED_INTENTS = (
    "generate_governance_report",
    "summarize_compliance_posture",
    "explain_missing_evidence",
    "compare_snapshots",
    "create_report_snapshot",
    "summarize_agent_authorization",
    "summarize_rag_inventory",
    "help",
)

SUGGESTED_PROMPTS = (
    "Generate a governance report for artifact hiring-assistant-prod",
    "What evidence is missing before approval?",
    "Summarize compliance posture for model mistral-ops",
    "Compare the latest two governance snapshots",
    "Create a new snapshot for the current scope",
    "Summarize recent agent authorization decisions",
    "Show the riskiest RAG stores",
)
