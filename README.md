# AI Assurance Framework (AIAF Sentry)

AI Assurance Framework (AIAF) is an open-source, evidence-driven assurance
platform designed to improve the security, trustworthiness, resilience, and
governance of Artificial Intelligence systems through continuous assurance
methodologies.

The framework enables organizations to assess AI security risks, validate governance controls, monitor AI deployments, and strengthen AI supply chain integrity across the lifecycle of modern AI systems.

**AIAF Sentry** is the Apache-2.0 Community package: the open assurance and
evidence layer across models, RAG, agents, runtime, deployment, and compliance.
Future commercial tiers build on top of this core, but Sentry itself is fully
usable today.

## Key Capabilities

- External Model Intake & Adoption Triage (graded adoption verdict for unknown models)
- Full Red-Team Evaluation via garak (120+ adversarial probes) and PyRIT (custom campaigns)
- Live Behavioral Probing (10 prompt injection / jailbreak / extraction probes at triage time)
- Artifact Serialization Scanning (non-executing pickle/safetensors/ONNX safety scan)
- HuggingFace Model Card Enrichment (PROVIDER_DECLARED facts auto-pulled from model cards)
- Sigstore / OpenSSF Model Signing Verification (INDEPENDENTLY_VERIFIED identity evidence)
- CycloneDX 1.7 ML-BOM Export and Import
- Evidence-Origin Labeling (every fact weighted by how it was obtained)
- AI Security Risk Assessment
- Uncertainty-Aware Model Impact and Exposure Assessment (inherent / residual / confidence-bounded)
- Prompt Injection Detection
- Jailbreak Analysis
- Agentic AI Security Validation (authority, blast-radius, workflow, and delegation analysis)
- Runtime Agent Tool Authorization
- Agent Containment Controls (suspend, quarantine, block specific tools)
- Per-Tool Invocation Risk Scoring
- RAG Backend Security Posture (access control, tenant isolation, index freshness, embedding provenance)
- Bias & Fairness Assessment
- Hallucination & Factual-Reliability Risk
- AI Supply Chain Security (provenance scoring, signed attestations, OSV-style advisory matching)
- Scheduled Continuous Security Operations Execution (run due jobs, create incidents, export to SIEM)
- Training-Data Assurance and Membership-Inference Signals
- Trustworthiness Scoring
- Continuous AI Assurance
- Compliance Mapping
- Governance Reporting

## Free/Paid Boundary

The community edition keeps the advisory policy engine and /v1/pep API so operators can evaluate policy decisions and inspect evidence. Inline request-blocking PEP gateway middleware is not distributed here; it lives in the Professional/Enterprise package aiaf_pro.enforcement because runtime enforcement is a paid control-plane capability.

## Foundation Artifacts

- [Technical Architecture](architecture.md)
- [Threat Model](threat_model.md)
- [Security Control Catalog](security_control_catalog.md)

## Alignment

The framework aligns with:

- NIST AI Risk Management Framework (AI RMF)
- NIST Secure Software Development Framework (SSDF)
- OWASP Top 10 for LLM Applications (2025)
- MITRE ATLAS
- CIS Controls v8
- EU AI Act (Regulation 2024/1689)
- ISO/IEC 42001:2023 (AI Management Systems)
- Secure-by-Design Principles

## Vision

To advance secure, trustworthy, and resilient AI adoption through practical open-source assurance technologies that support innovation, economic competitiveness, and national security objectives.

## Quickstart

### Fastest path: Docker Compose

Prerequisites:

- Docker
- Docker Compose

From the repository root:

```bash
cd deploy/docker
docker compose up --build
```

Then open:

- Dashboard: `http://localhost:8000/`
- API docs: `http://localhost:8000/docs`

Default API key:

- `changeme` when using Compose defaults

Optional: seed a realistic demo workspace in a second terminal:

```bash
cd /path/to/AI-Assurance-Framework
PYTHONPATH=src python scripts/seed_demo_data.py
```

That seeds:

- sample model inventory
- risk findings and metrics
- approved governance evidence
- assurance report snapshots
- RAG inventory with trusted and untrusted documents
- agent runtime authorization sessions and decisions

### Local development setup

Prerequisites:

- Python 3.10+ and `pip`
- Node 18+ only if you want to modify the dashboard frontend

(Optional) Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

- Install runtime dependencies:

```bash
pip install -r requirements.txt
```

- (Optional) Install developer tools for linting:

```bash
pip install ruff
```

## Execution

### Run the API locally

From the repository root you can run the FastAPI server in development mode:

```bash
./scripts/run_local.sh
# or
PYTHONPATH=src python -m aiaf.cli run --host 0.0.0.0 --port 8000
```

Then open the dashboard at **http://localhost:8000/** — a React single-page
console (Overview · Adoption Triage · Risk Analyzer · Governance & Compliance ·
Model Registry · RAG Inventory · Agent Authorization · Architecture · API Explorer)
that reflects the running framework, with trend lines, drift-over-time charts,
live auto-refresh, curated retrieval and authorization views, and a CycloneDX-backed
runtime-component inventory. Interactive API docs are at `/docs`.
Enter the API key (default `dev-key`) in the dashboard header.

To populate a useful demo workspace after first boot:

```bash
PYTHONPATH=src python scripts/seed_demo_data.py
```

The dashboard is a Vite + React + Tailwind + Recharts app in [`frontend/`](frontend/),
built into `src/aiaf/web/` and served by FastAPI. The compiled output is committed,
so the server renders the UI without a Node toolchain. To modify the dashboard:

```bash
cd frontend
npm install
npm run dev     # hot-reload dev server, proxies the API to :8000
npm run build   # recompiles into src/aiaf/web/ for FastAPI to serve
```

If the build is missing, `GET /` returns a short hint with the build command
instead of the dashboard; the JSON API stays fully available.

The API provides a minimal health endpoint:

```
GET /health -> { "status": "ok" }
GET /v1/info -> basic project info
```

For persistent or shared deployments, set `AIAF_PG_DSN` to a PostgreSQL connection URI.
The PostgreSQL backend stores model provenance, registration jobs, security
findings, governance audit evidence, and historical risk and trust metrics.

Model registration automatically inspects bounded dependency manifests inside
directories and archives, including `requirements*.txt`, `pyproject.toml`,
`Pipfile.lock`, and `package.json`. Discovered records and source manifests are
included in the model inventory and AI-BOM.

Vulnerability intelligence is imported as OSV-style JSON through the protected
API and stored locally for reproducible scans. Importing new advisories
automatically rescans registered models. Exact dependency versions are matched
against introduced, fixed, last-affected, and explicit affected-version data;
unresolved ranges are reported as partial coverage rather than treated as safe.

Set `AIAF_ADVISORY_FEED_KEY` and optionally `AIAF_ADVISORY_FEED_KEY_ID` to
import authenticated advisory feeds. Signed envelopes bind feed identity,
monotonic sequence, source, freshness window, and exact advisory content.
Expired feeds, invalid signatures, rollback, and same-sequence content changes
are rejected. Once signed-feed governance is active, unverified manual imports
are blocked; existing mixed-trust catalogs remain visible in reports and alerts.
Historical feed verification requires retaining the key associated with each key
ID until asymmetric or managed-key verification is implemented.

Set `AIAF_ATTESTATION_KEY` and optionally `AIAF_ATTESTATION_KEY_ID` to issue and
verify signed provenance statements. The current HMAC-SHA256 implementation is
intended for organization-controlled integrity verification; protect and rotate
the shared key through the deployment secret manager.

Set `AIAF_REPORT_SIGNING_KEY` and optionally `AIAF_REPORT_SIGNING_KEY_ID` to
issue HMAC-signed assurance report snapshots. Unsigned snapshots remain
SHA-256-verifiable; signed snapshots additionally bind their identity, scope,
version, digest, creator, timestamp, and key ID. Use a separate managed secret
from the model provenance key and rotate it according to governance policy.

For asymmetric signing, set `AIAF_REPORT_SIGNING_PRIVATE_KEY_PEM`,
`AIAF_REPORT_SIGNING_PUBLIC_KEY_PEM`, and `AIAF_REPORT_SIGNING_KEY_ID`.
When a private key PEM is present, AIAF signs report snapshots with `ED25519`
and verifies them with the configured public key. Keep the private key in the
deployment secret manager, distribute only the public key to verifiers, and
retain each historical key ID until all snapshots signed with it have aged out
of your retention window. PEM values may be provided as multi-line secrets or
with literal `\n` escapes. Example operator flow:

```bash
openssl genpkey -algorithm ed25519 -out report-signing-private.pem
openssl pkey -in report-signing-private.pem -pubout -out report-signing-public.pem
export AIAF_REPORT_SIGNING_PRIVATE_KEY_PEM="$(cat report-signing-private.pem)"
export AIAF_REPORT_SIGNING_PUBLIC_KEY_PEM="$(cat report-signing-public.pem)"
export AIAF_REPORT_SIGNING_KEY_ID="fedramp-ed25519-2026q2"
```

### Run continuous assurance

Create schedules through `POST /v1/monitoring/schedules`, then run the worker
as a separate process. It executes due risk and governance assessments and
persists every run and its next execution time.

```bash
PYTHONPATH=src python -m aiaf.cli monitor --poll-seconds 30
```

Use `--once` for cron jobs, container jobs, or a single scheduler tick.

For Phase D security operations, AIAF now also exposes a first-class schedule
executor for recurring security work:

- `POST /v1/ops/schedules/{schedule_id}/execute` — execute one scheduled job now
- `POST /v1/ops/schedules/execute-due` — execute all due jobs (or a filtered subset)

Supported job types include red-team runs, telemetry batch ingest, anomaly
scans, vulnerability scans, and assurance report snapshots. Scheduled anomaly
and vulnerability runs can automatically open incidents in the local incident
tracker.

## What Sentry Includes Today

The Community package includes:

- framework, CLI, API, and dashboard
- garak / PyRIT adapters
- AI-BOM / CycloneDX
- RAG taint gate
- agent authorization
- egress firewall
- context provenance
- deployment verification
- incident packages
- compliance evidence packs
- standards mappings
- SIEM / OSCAL / SARIF exports
- SQLite by default, PostgreSQL when configured

### Run Red-Team Evaluation (garak / PyRIT)

AIAF can run a full adversarial red-team evaluation against any live
OpenAI-compatible model endpoint using
[garak](https://github.com/NVIDIA/garak) (120+ probes) or
[Microsoft PyRIT](https://github.com/Azure/PyRIT). Results are persisted
to the model record and automatically incorporated into the next adoption
triage verdict.

**Step 1 — install the tools** in the same virtual environment as AIAF:

```bash
# garak — required for the full probe library
pip install garak

# PyRIT — optional, for custom red-team campaigns
pip install pyrit
```

**Step 2 — start a live model endpoint.** Both tools require an
OpenAI-compatible chat completions API. Local options:

```bash
# Ollama (simplest — exposes http://localhost:11434/v1)
ollama serve && ollama pull llama3

# or: vLLM, LM Studio, llama.cpp --server, etc.
```

**Step 3 — launch the evaluation.**

*From the dashboard:* open the **Adoption** tab, select a model, enter the
endpoint URL, and click **Launch red-team**. Choose **Quick** (4 probe
families, ~2–10 min) or **Full** (all 12 families, ~30–90 min). The job
runs in the background; the panel polls every 10 seconds. When it
completes, click **Run adoption triage** to incorporate the findings.

*From the API:*

```bash
# Start a quick garak scan (returns immediately with a job_id)
curl -X POST http://localhost:8000/v1/interop/models/YOUR_MODEL_ID/redteam \
  -H "X-API-Key: dev-key" -H "Content-Type: application/json" \
  -d '{
    "endpoint_url": "http://localhost:11434/v1",
    "backend": "garak",
    "model_name": "llama3",
    "depth": "quick"
  }'

# Poll for status / results
curl http://localhost:8000/v1/interop/models/YOUR_MODEL_ID/redteam/JOB_ID \
  -H "X-API-Key: dev-key"

# Re-run triage — garak findings are now in the adoption verdict
curl -X POST http://localhost:8000/v1/intake/triage \
  -H "X-API-Key: dev-key" -H "Content-Type: application/json" \
  -d '{"model_id": "YOUR_MODEL_ID"}'
```

*Run garak directly* (useful for debugging outside AIAF):

```bash
OPENAI_API_BASE=http://localhost:11434/v1 OPENAI_API_KEY="${OPENAI_API_KEY:?set OPENAI_API_KEY}" \
  python -m garak \
    --model_type openai --model_name llama3 \
    --probes promptinject,dan,leakage,encoding \
    --generations 3
```

**Probe families and what they test:**

| Family | Category | Severity | Tests for |
|---|---|---|---|
| `promptinject` | Prompt injection | HIGH | Injected instructions hijacking model behaviour |
| `encoding` | Prompt injection | HIGH | Same attack via Base64, ROT13, Unicode tricks |
| `dan` | Jailbreak | CRITICAL | "Do Anything Now" and instruction-override variants |
| `jailbreak` | Jailbreak | CRITICAL | Role-play and fictional framing safety bypass |
| `gcg` | Jailbreak | CRITICAL | Greedy Coordinate Gradient adversarial suffixes |
| `leakage` | Information disclosure | HIGH | Training data extraction and memorisation |
| `replay` | System-prompt extraction | MEDIUM | System prompt reconstruction via repetition |
| `continuation` | Harmful content | HIGH | Harmful narrative continuation |
| `malwaregen` | Harmful content | CRITICAL | Exploit code and malware elicitation |
| `realtoxicityprompts` | Harmful content | HIGH | Toxic content generation |
| `xss` | Prompt injection | HIGH | XSS payloads in model output |

**Verdict caps from red-team findings:**

| Finding severity | Adoption verdict cap |
|---|---|
| CRITICAL or HIGH | `DO_NOT_APPROVE` |
| MEDIUM | `PILOT_ONLY` |
| garak not installed | Evidence gap only (no cap) |
| Partial results (timeout) | Completeness gap |

If garak is not installed, triage records an evidence gap but does not
block adoption — absence of the tool does not imply a clean model.

### Run tests

Run the unit tests (uses `pytest`):

```bash
python -m pytest -q
```

### API Surface

- `POST /models/register`: register uploaded models or Hugging Face model URLs.
  Optional form fields include `publisher`, `license`, `training_data`,
  `dependencies`, `training_artifacts`, `deployment_pipeline`, and `version`
  for richer supply-chain evidence.
- `GET /jobs/{job_id}`: inspect long-running registration jobs.
- `GET /models/{model_id}/mbom`: export the model's AIAF AI-BOM with discovered dependencies and lineage evidence.
- `GET /models/{model_id}/vulnerabilities`: inspect the model's persisted dependency vulnerability evidence.
- `POST /models/{model_id}/vulnerabilities/scan`: refresh one model against the current local advisory catalog.
- `POST /models/{model_id}/attestations`: issue and persist a schema-2 signed statement binding model identity, artifact digest, source, and per-evidence digests (dependency inventory, training lineage, deployment pipeline, AI-BOM, composite manifest). The envelope is strict, so the verifier output is persisted **separately** (bound to the statement by its `attestation_sha256`) rather than inside the signed attestation. HMAC assurance is symmetric authentication, not non-repudiation.
- `POST /models/{model_id}/attestations/verify`: dual-read verification — schema-2 envelopes are checked against an explicit identity and freshness policy; legacy schema-1 attestations continue to verify through the v1 path.
- `GET /models/{model_id}/attestations`: list persisted provenance attestations.
- `POST /models/{model_id}/attestations/verify`: verify signature and model/AI-BOM integrity against the current registry record.
- `POST /v1/intake/triage`: run External Model Intake adoption triage for a
  registered model. AIAF assembles its provenance, aggregated risk, governance
  control coverage, and dependency-vulnerability evidence — each fact tagged by
  evidence origin (`user_entered`, `provider_declared`, `artifact_derived`,
  `locally_observed`, `independently_verified`) — and returns a graded adoption
  verdict (`DO_NOT_APPROVE`, `INSUFFICIENT_EVIDENCE`, `PILOT_ONLY`,
  `APPROVE_WITH_CONDITIONS`, `APPROVE_FOR_SCOPED_USE`) with origin-tagged reasons,
  conditions to satisfy, an explicit list of evidence that could not be obtained,
  and a conservative decision confidence. Identity that rests only on operator-typed
  claims cannot earn a clean approval; a verified signed attestation can.
- `GET /v1/intake/{model_id}`: return the most recent persisted adoption verdict.
- `GET /`: React single-page operational dashboard (Overview, Adoption Triage, Risk Analyzer, Governance & Compliance, Model Registry, RAG Inventory, Agent Authorization, Architecture, API Explorer) with trend lines, drift-over-time charts, live auto-refresh, and curated views for retrieval inventory and runtime tool authorization — backed entirely by the public API.
- `GET /v1/reporting/metrics`: time-series of historical assurance metrics grouped by metric name (oldest-first), powering the dashboard trend and drift charts.
- `GET /v1/architecture`: inspect the implemented architecture catalog and layer/component map.
- `POST /v1/risk/analyze`: run the security analysis layer through the risk engine.
  Model assessments use `model_risk_profile` evidence for impact level, domain,
  deployment exposure, data classification, user access, capabilities, access
  controls, output validation, safety evaluations, and human oversight. The v2
  model- and agent-risk scorers are uncertainty-aware: they separate inherent,
  residual, and confidence-bounded risk, expose score gates and explainable
  factors, and report the conservative upper-bound 0-10 score. Findings are
  emitted only at MEDIUM severity or higher (agent risk also requires that the
  artifact is agentic); below that, and for every assessment including zero-risk
  results, the outcome is retained as a historical trend metric.
- `POST /v1/supply-chain/advisories/import`: import OSV-style advisories and optionally rescan all registered models.
- `GET /v1/supply-chain/advisories`: list or filter the local advisory catalog by ecosystem and package.
- `POST /v1/supply-chain/advisories/feeds/import`: verify and import a signed, freshness-bound advisory feed and optionally rescan registered models. Dual-read — schema-2 feeds are bound to an engine-derived hash chain (each feed must cryptographically link to the stored head digest and advance the sequence by one) and evaluated for freshness at the current time; legacy schema-1 feeds keep their monotonic-sequence replay protection. HMAC assurance is symmetric authentication, not non-repudiation.
- `GET /v1/supply-chain/advisories/feeds`: list durable feed snapshot metadata without embedding full advisory content.
- `GET /v1/supply-chain/advisories/feeds/status`: inspect authenticated, mixed, stale, or unverified advisory intelligence state.
- `GET /v1/supply-chain/advisories/feeds/{snapshot_id}`: retrieve one persisted signed feed snapshot.
- `POST /v1/supply-chain/advisories/feeds/{snapshot_id}/verify`: recheck envelope signature, freshness, digest, and persisted metadata consistency.
- `POST /v1/supply-chain/scan`: scan an arbitrary dependency inventory against the local catalog.
- `GET /v1/risks`: list and filter deduplicated managed risks by lifecycle status, artifact, or severity.
- `GET /v1/risks/{risk_id}`: inspect recurrence, ownership, due date, standards mappings, and disposition evidence for one risk.
- `PATCH /v1/risks/{risk_id}`: assign or transition a risk through `OPEN`, `IN_PROGRESS`, `ACCEPTED`, and `RESOLVED`; accepted and resolved risks require rationale, severity-specific `remediation_sla` hours set initial due dates, and recurring resolved detections reopen with a fresh deadline.
- `GET /v1/agentic/policy-profiles`: inspect reusable restricted, standard, and development agent policy profiles.
- `POST /v1/agentic/validate`: validate agent policy, workflow reachability, termination, cycles, untrusted data flow, and privilege transitions; persist the evaluation as an audit event and historical metric.
- `POST /v1/agentic/sessions`: create an active runtime session only after static policy and workflow validation; the effective policy is snapshotted for the session.
- `GET /v1/agentic/sessions`: list runtime sessions and their current status and external-call usage.
- `POST /v1/agentic/sessions/{session_id}/authorize`: authorize an idempotent tool invocation against the session policy, workflow step, permissions, input-validation evidence, approval requirements, session status, and external-call budget.
- `PATCH /v1/agentic/sessions/{session_id}`: revoke or close an active agent session.
- `GET /v1/agentic/invocations`: inspect durable `ALLOW`, `DENY`, and `REQUIRE_APPROVAL` decisions.
- `POST /v1/monitoring/schedules`: register a recurring assurance target and interval.
- `GET /v1/monitoring/schedules`: list enabled or disabled assessment schedules.
- `PATCH /v1/monitoring/schedules/{schedule_id}`: update, pause, or reschedule a target.
- `POST /v1/monitoring/run-due`: execute all schedules due at the requested time.
- `POST /v1/monitoring/schedules/{schedule_id}/run`: immediately execute one target.
- `GET /v1/monitoring/runs`: inspect durable assessment run history and results.
- `GET /v1/governance/controls`: inspect the executable AI assurance control catalog.
- `POST /v1/governance/evaluate`: evaluate governance controls and write an audit log.
- `POST /v1/governance/evidence`: submit a SHA-256-bound evidence reference scoped to specific fields of one assurance control.
- `GET /v1/governance/evidence`: list evidence and review health by artifact, control, or status.
- `POST /v1/governance/evidence/{evidence_id}/review`: independently approve or reject pending evidence with a durable rationale; self-review is prohibited and expired evidence cannot be approved.
- `GET /v1/reporting/summary`: aggregate findings, audit logs, and historical metrics. Pass `artifact_id` to isolate one AI system.
- `GET /v1/reporting/assurance-report`: export an evidence-driven AI assurance compliance report as JSON or markdown, including aggregate and model risk posture, schedule and run health, governance status, standards coverage, supply-chain evidence, and trustworthiness trends. Pass `artifact_id` to scope all evidence to one AI system; omitting it produces the portfolio report.
- Standards coverage includes versioned framework sources and exact NIST AI RMF subcategories and MITRE ATLAS technique identifiers. Missing governance controls are reported as gaps and do not count as compliance evidence.
- `GET /v1/reporting/compliance`: return a framework-scoped evidence matrix with AIAF control status, provided and missing evidence, mapped standard references, risk findings, and derived coverage percentages. Results measure evidence completeness and do not assert certification. The optional `artifact_id` applies the same system boundary as the assurance report.
- `GET /v1/reporting/alerts`: return prioritized continuous-monitoring alerts derived from risk, trustworthiness, governance, standards, and supply-chain evidence. Use `artifact_id` for system-specific alerts.
- `POST /v1/reporting/snapshots`: retain the current portfolio or artifact-scoped report as append-only JSON with a canonical SHA-256 digest; provide `created_by`, optional `artifact_id`, and `sign=true` when a report signing key is configured.
- `GET /v1/reporting/snapshots`: list snapshot metadata without embedding each full report; filter by `artifact_id` when needed.
- `GET /v1/reporting/snapshots/{snapshot_id}`: retrieve the immutable point-in-time report and its digest or signature metadata.
- `POST /v1/reporting/snapshots/{snapshot_id}/verify`: recompute report integrity, scope, schema-version, and optional HMAC-signature checks and retain the verification audit event.

### Linting

If you installed `ruff`, run:

```bash
ruff check .
```
## Technical Architecture

┌─────────────────────────────────────────────────────────┐
│                  AI Assurance Framework                 │
└─────────────────────────────────────────────────────────┘

                    ┌───────────────┐
                    │ User Portal   │
                    └───────┬───────┘
                            │
                            ▼

┌─────────────────────────────────────────────────────────┐
│                 API Gateway Layer                       │
│                   FastAPI Services                      │
└─────────────────────────────────────────────────────────┘

                            │
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼

┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│ Risk/Register  │ │ Governance     │ │ Reporting      │
│ Agentic Engine │ │ Engine         │ │ Engine         │
└──────┬─────────┘ └──────┬─────────┘ └──────┬─────────┘
       │                  │                  │
       ▼                  ▼                  ▼

┌─────────────────────────────────────────────────────────┐
│                Security Analysis Layer                  │
├─────────────────────────────────────────────────────────┤
│ Prompt Injection Detection                              │
│ Jailbreak Analysis                                      │
│ Model Risk Assessment                                   │
│ Agent Risk Assessment                                   │
│ Tool Invocation Risk Engine                             │
│ Workflow Security Validator                             │
│ Workflow Graph Security Analyzer                        │
│ Agent Policy Constraint Evaluator                       │
│ Runtime Tool Authorization                              │
│ Supply Chain Validation                                 │
│ Dependency Risk Analysis                                │
│ Dependency Vulnerability Matching                       │
│ Signed Advisory Feed Verification                       │
│ Data Leakage Detection                                  │
│ Adversarial Testing                                     │
│ Trustworthiness Scoring                                 │
└─────────────────────────────────────────────────────────┘

                            │
                            ▼

┌─────────────────────────────────────────────────────────┐
│                 Knowledge & Mapping Layer               │
├─────────────────────────────────────────────────────────┤
│ OWASP Top 10 for LLMs                                   │
│ MITRE ATLAS                                             │
│ NIST AI RMF                                             │
│ NIST SSDF                                               │
│ CIS Controls                                            │
│ AI Assurance Control Catalog                            │
│ Independent Evidence Review                             │
└─────────────────────────────────────────────────────────┘

                            │
                            ▼

┌─────────────────────────────────────────────────────────┐
│                  Data & Analytics Layer                 │
├─────────────────────────────────────────────────────────┤
│ PostgreSQL                                              │
│ Vector Database                                         │
│ Training Artifacts                                      │
│ Deployment Pipelines                                    │
│ Audit Logs                                              │
│ Security Findings                                       │
│ Historical Metrics                                      │
│ Managed Risk Register                                   │
│ Vulnerability Advisory Catalog                          │
│ Signed Advisory Feed Snapshots                          │
│ Control Evidence Repository                             │
│ Compliance Report Export                                │
│ Immutable Assurance Report Snapshots                    │
│ Continuous Monitoring Alerts                            │
└─────────────────────────────────────────────────────────┘

## License

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for
attribution and trademark information.

"AIAF Sentry", "AIAF Vanguard" and "AIAF Aegis" are trademarks of Code & Security. The
Apache-2.0 license covers the source code; it does not grant rights to the
project name or marks.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request — all contributions require a signed
Contributor License Agreement ([CLA.md](CLA.md)).
