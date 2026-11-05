# Vartija core

The reusable, challenge-agnostic layer between **ARCC-X** (operations) and **CyberGRC-AI**
(governance). It takes a signed incident event and carries it to a human-approved,
evidence-linked regulatory report, with every step sealed in a tamper-evident log.

Built **before** Since AI Hackathon 2026 and disclosed as prior work. The challenge-specific
product is built on top of it at the event.

```
ARCC-X ──signed event──▶ /events ──▶ case + regulatory clock starts
                                        │
CyberGRC-AI ◀──asset/risk/control context┤
                                        ▼
                     AI assessment (advisory, cited, validated)
                                        ▼
                  conflicts surfaced ─▶ human confirms duties
                                        ▼
                       report draft (fields ↔ evidence)
                                        ▼
            AI requests ─▶ humans approve ─▶ action executed
                                        ▼
                    hash-chained audit log + export pack
```

## Quick start (2 minutes)

```bash
pip install -e ".[dev]"
python -m pytest -q             # 59 tests: flow, tampering, policy, AI guardrails, ingestion, retrieval, checks, dashboard, JWT, access, uploads
python scripts/demo.py          # narrated stage demo (telecom story)
python scripts/demo.py --story plc   # CRA story (set nothing else; it switches sector itself)
python scripts/eval.py          # scenario evaluation: precision/recall per flag
uvicorn vartija_core.api:app --reload --port 8001   # API docs at http://localhost:8001/docs
```

No model needed: `VARTIJA_LLM=rules` (the default) runs a deterministic engine. To use a model:

```bash
VARTIJA_LLM=ollama VARTIJA_LLM_MODEL=llama3.1 uvicorn vartija_core.api:app        # local
VARTIJA_LLM=openai VARTIJA_LLM_BASE_URL=https://.../v1 VARTIJA_LLM_API_KEY=... \
  VARTIJA_LLM_MODEL=... uvicorn vartija_core.api:app                              # any OpenAI-compatible API
```

If the model fails or returns junk, the rule engine answers and the response says
`engine: "rules (fallback: ...)"`. The demo cannot die on stage because of an LLM.

## What is where

| Path | What | Change it at the event? |
| --- | --- | --- |
| `vartija_core/` | Engine: intake, clock, approvals, audit chain, agents, API | Rarely |
| `config/regimes/*.yaml` | Legal regimes: deadlines and report fields (NIS2-FI, CRA, GDPR) | Add sector rules (DORA, IACS E26...) |
| `config/sectors/*.yaml` | Sector overlays: org details, regimes in scope, significance hints | **Yes, first thing** |
| `config/policy.yaml` | Which actions need which approvals | Yes, to match the company |
| `config/conflicts.yaml` | Known tensions between actions/obligations | Yes, add domain conflicts |
| `config/prompts/*.md` | Agent prompts, versioned | **Yes, this is your AI work** |
| `corpus/*.md` | Citable passages for retrieval | Add the company's policies/standards |
| `seed/grc.yaml` | Demo governance data | Replace with challenge data |
| `scenarios/*.yaml` | Labelled cases for `eval.py` | **Yes, 30+ for the challenge** |
| `ui/RegulatoryClock.tsx` | Signature screen, drop into the React app | Restyle to the company |

## Integrating with your two prototypes

### ARCC-X → Vartija (the event contract)

POST `/events` with an HMAC signature. Use `vartija_core/client.py` (`send_event`) or
reimplement the 10 lines in ARCC-X's language:

```
X-Vartija-Timestamp: <unix seconds>
X-Vartija-Signature: sha256=HMAC_SHA256(secret, "<timestamp>.<raw body>")
```

```json
{
  "event_id": "evt-7f3a...",            // unique; a resend is a harmless duplicate
  "schema_version": "1.0",
  "source": "arcc-x",
  "event_type": "auth.credential_stuffing",
  "occurred_at": "2026-11-07T03:12:00+02:00",   // timezone required
  "detected_at": "2026-11-07T03:20:00+02:00",   // optional: when you became aware
  "correlation_id": "portal-incident-42",       // groups events into one case
  "asset_id": "web-portal-01",                  // key into CyberGRC-AI assets
  "severity": "high",                           // info|low|medium|high|critical
  "confidence": 0.9,                            // separate from severity
  "summary": "Credential stuffing; 4,200 accounts accessed.",
  "attributes": {"users_affected": 4200, "outage_minutes": 0, "malicious": true,
                 "cross_border": true, "personal_data": true,
                 "actively_exploited": false, "product_affected": false,
                 "iocs": ["185.220.101.0/24"]},
  "evidence_refs": ["s3://evidence/portal/auth.log#L1200-1450"],  // pointers, never raw logs or secrets
  "data_classification": "confidential"
}
```

The `attributes` keys above are the ones the rule engine reads. Send what ARCC-X knows;
missing keys lower confidence instead of failing.

### CyberGRC-AI ↔ Vartija

1. **Same database, separate tables.** Point `VARTIJA_DATABASE_URL` at CyberGRC-AI's
   PostgreSQL. Tables are prefixed `vartija_`. For Alembic, import `vartija_core.models` in
   `env.py` and include `vartija_core.db.Base.metadata`.
2. **Mount the API** in CyberGRC-AI's FastAPI app:
   ```python
   from vartija_core.api import create_app, current_principal
   vartija = create_app(grc_provider=CyberGrcDbProvider(SessionLocal))
   vartija.dependency_overrides[current_principal] = your_jwt_principal  # REQUIRED: replaces demo headers
   app.mount("/vartija", vartija)
   ```
3. **Governance context.** Implement `GrcContextProvider.context_for(asset_id)` against
   your Asset/Risk/Control/Finding models (sketch at the bottom of `vartija_core/grc.py`).
4. **Close the loop.** Replace the `open_corrective_action` executor in `api.py` with a call
   that creates a corrective action in CyberGRC-AI and updates residual risk.
5. **UI.** Add `ui/RegulatoryClock.tsx` to the React app; the case, approval and report
   views read the JSON from `/cases/{id}`, `/cases/{id}/reports` and `/actions/*`.

Or run it as a separate container: `docker-compose.vartija.yml`.

## API summary

| Method | Path | Who | Purpose |
| --- | --- | --- | --- |
| POST | `/events` | ARCC-X (signed) | Ingest an event; opens or extends a case |
| GET | `/cases`, `/cases/{id}` | user | Cases with events, GRC context, latest assessment |
| GET | `/cases/{id}/clock` | user | Every deadline, status and the next one due |
| POST | `/cases/{id}/assess` | user | AI assessment: flags, confidence, citations, conflicts, actions |
| POST | `/cases/{id}/flags` | human only | Confirm which reporting duties apply |
| POST | `/cases/{id}/milestones` | human only | Record e.g. `corrective_measure` (starts the CRA final-report clock) |
| POST | `/cases/{id}/reports` | user | Draft a report for a regime and stage |
| POST | `/cases/{id}/actions` | anyone, incl. AI | Request an action (policy decides what approval it needs) |
| POST | `/actions/{id}/decide` | human with role | Approve or reject |
| POST | `/actions/{id}/execute` | user | Run an approved action, once |
| GET | `/cases/{id}/audit`, `/audit/verify` | user | Audit trail; whole-chain verification |
| GET | `/cases/{id}/export` | user | Audit pack for auditors and the jury |

## Trust guarantees (the pitch, and the tests that prove each one)

| Guarantee | Test |
| --- | --- |
| Unsigned, wrongly signed or replayed events are rejected | `test_duplicate_and_bad_signatures` |
| A resent event never creates a second case | same |
| The clock runs from detection, before anyone decides | `test_full_flow` |
| AI can request but never approve; requester can't self-approve; unknown actions refused | `test_full_flow`, `test_policy_rules` |
| Only humans confirm which legal duties apply | `test_only_humans_confirm_flags` |
| Citations not in the retrieved law are rejected and force human review | `test_hallucinated_citations_and_actions_are_rejected` |
| The model never sees personal data; regulator drafts stay minimised | same + `test_ai_drafted_report_fields_are_marked_and_minimised` |
| Attacker text in logs is fenced as data | `test_injected_log_text_is_fenced_as_data` |
| Model failure or garbage output falls back to rules | `test_model_failure_falls_back_to_rules`, `test_garbage_model_output_falls_back` |
| Editing or deleting any audit row is detected | `test_tampering_is_detected` |
| Conflicts are surfaced, not resolved | `test_conflicts_surface` |

## Document ingestion, retrieval and deterministic checks (added 2026-11-05, pre-event)

Generic building blocks for any rule book, standard, law or SOP. Nothing here is domain-specific.

```bash
pip install -e ".[dev,docs]"                                   # docs = pypdf for PDF input
python scripts/ingest_docs.py rules.pdf --prefix src --tags src # -> corpus/src.md + src.refs.json
python scripts/pack_to_pdf.py vartija-audit-pack-<id>.json        # exported JSON pack -> PDF
VARTIJA_RETRIEVER=hybrid uvicorn vartija_core.api:app --port 8001   # tfidf (default) | bm25 | hybrid
```

| Module | What it adds |
| --- | --- |
| `docingest.py` | `.pdf/.html/.md/.txt` → paragraphs that **keep the document's own numbering** (`src:9.2.1`, `src:23(4)`), parents, page-header stripping, duplicate-number warnings, cross-reference extraction. Heading patterns are regexes; add one per document style with `--heading`. |
| `rag.py` | `code_tokenize` keeps identifiers like `A-60`, `II-2/9.2.3`, `62443-4-2` intact. `BM25Retriever` for exact terms. `HybridRetriever` fuses BM25 + TF-IDF + optional embeddings (`embed=` any function, e.g. Ollama or pgvector), and `expand=1` follows cross-references. `make_retriever` picks via `VARTIJA_RETRIEVER`. |
| `citations.py` | `verify_citations`: the cited passage must exist, must have been retrieved, **and the quoted words must appear in it** (tolerant of PDF spacing/dashes, strict on changed numbers). Every rejection carries a reason for the UI. |
| `quantities.py` | `check_requirement("not less than 60 min", "1 h")`: numeric requirement checks **in code, not in the model**, with unit conversion (length, time, mass, force, pressure, power, energy, flow, vibration, …) and a readable message. Returns `ok=None` when it can't decide. |

Tests: `tests/test_upgrades.py` (21 tests). The model's job is to *extract* requirement and
value text and to *cite with a quote*; these modules decide whether it was right.

## Dashboard, auth and embeddings (added 2026-11-05, pre-event)

```bash
uvicorn vartija_core.api:app --reload --port 8001
# open http://localhost:8001/dashboard
```

**Dashboard** (`vartija_core/static/dashboard.html`, one file, no build step): case list, live
regulatory clock, AI assessment with citations, rejected citations and conflicts, "confirm
duties" (humans only), action requests with approve/reject/execute, report draft with
evidence counts, events, audit trail and whole-chain verification, JSON audit-pack export.
The "Acting as" menu switches demo users so you can show that the AI can't approve and
nobody approves their own request. **Load demo incident** calls `POST /demo/seed`.

| Setting | Values | Default |
| --- | --- | --- |
| `VARTIJA_DEMO` | `auto` (on only while `VARTIJA_EVENT_SECRET` is the dev default), `1`, `0` | `auto` |
| `VARTIJA_AUTH` | `headers` (demo X-User/X-Roles) or `jwt` (HS256 bearer token) | `headers` |
| `VARTIJA_JWT_SECRET`, `VARTIJA_JWT_USER_CLAIM`, `VARTIJA_JWT_ROLES_CLAIM` | the secret CyberGRC-AI signs with; claim names | —, `sub`, `roles` |
| `VARTIJA_EMBED`, `VARTIJA_EMBED_MODEL` | `none`, `ollama`, `openai`; e.g. `nomic-embed-text` | `none` |

- **JWT** (`auth_jwt.py`): standard library only. Checks signature, `exp`, `nbf`. Roles are
  lower-cased with spaces → `_` ("GRC Manager" → `grc_manager`); map them in `policy.yaml`.
  A token with `"kind": "ai"` is an AI principal and can never approve or confirm duties.
- **Embeddings** (`embeddings.py`): used by `VARTIJA_RETRIEVER=hybrid`. Probed at start-up;
  if Ollama is down the API starts anyway and `/health` says why.
- New route `GET /cases/{id}/actions` lists a case's action requests.

Tests: `tests/test_dashboard_auth.py` (10 tests).

### Two views with role-based access (`config/access.yaml`)

| View | Who (default roles) | Shows |
| --- | --- | --- |
| **Executive** | `management`, `ceo`, `executive`, `board`, `admin` | One-line status (green/amber/red), four plain numbers (legal deadlines on track, items that could cost us, time saved, decisions waiting on you), risks in plain words, approve/reject buttons, "record intact" proof, and an editable "time saved" calculator |
| **Engineer** | `ciso`, `soc_lead`, `legal`, `it_admin`, `engineer`, `analyst`, `grc_manager`, `risk_analyst`, `auditor`, `admin` | Everything above the hood: cases, clock, assessment, citations, actions, reports, audit trail |

Enforced by the API: executive roles get **403** on case data, engineer roles get 403 on
`/exec/summary`, AI agents never get the executive view. Approving is open to whoever the
policy names, so a CEO signs off from the executive screen. `GET /me` returns the views a
user may open; the dashboard shows only those (both, with a switch, for `admin`).
"Time saved" = automated steps recorded in the audit log × minutes each takes by hand ×
hourly cost; the defaults in `access.yaml` are placeholders, replace them with the
customer's figures. Tests: `tests/test_access_exec.py`.

## Adding challenge material from the dashboard (Sources panel)

Engineer view → **Sources** → choose files → **Upload**. No restart needed.

| File type | What happens |
| --- | --- |
| `.pdf .md .txt .html` (rules, standards, policies) | Split into paragraphs that keep the document's numbering, cross-references found, added to the searchable corpus at once. Cite as `<prefix>:<number>`, e.g. `ssr:9.2`. |
| `.csv .xlsx .json .yaml .zip .docx .pptx .xml .png .jpg .dxf .ifc .step` (data packs) | Stored unchanged with a SHA-256 fingerprint as evidence. Not parsed or executed. |

- Stored under `VARTIJA_UPLOAD_DIR` (default `./data`), which is **git-ignored**: challenge material
  is usually confidential (Since AI ToS 5.8). Uploads survive restarts. Size limit `VARTIJA_MAX_UPLOAD_MB` (50).
- Each upload and removal is written to the audit chain (who, file, fingerprint).
- Only people in the engineer view can add or remove sources; AI agents and executive logins cannot.
- If the upload says "duplicate numbers", the document's headings don't match the default patterns:
  open **Options** and add a heading regex, e.g. `^Rule (?P<num>\d+(?:\.\d+)*)\s+(?P<title>.*)$`.
- Scanned PDFs have no text layer; run OCR first.

API: `GET /sources`, `POST /sources` (multipart `file`, optional `prefix`, `heading`), `DELETE /sources/{name}`.
Tests: `tests/test_sources.py`.

## Re-skin drill (practise this twice before the event; target under 2 hours)

1. Copy the closest `config/sectors/*.yaml`, rename, set org, markets, regimes, hints. Set `VARTIJA_SECTOR`.
2. Add the company's own documents (security policy, standards, sector rules) to `corpus/` as `## [id] Title` sections.
3. Replace `seed/grc.yaml` with their assets, risks, controls (or anonymised examples from the briefing).
4. Edit `config/policy.yaml` roles to match their organisation chart.
5. Write 10 scenarios from their domain into `scenarios/`, labels first, then run `eval.py`.
6. Tune `config/prompts/significance.md`; switch to a model; re-run `eval.py` and compare against `rules`.
7. Restyle `RegulatoryClock.tsx` and record the demo once.

## Before the event: checklist

- [ ] Commit and tag: `git tag pre-event-2026-11-05` in your repo; mention the tag in the submission.
- [ ] Replace corpus summaries with official text (EUR-Lex: NIS2, CRA, GDPR; Finlex: Cybersecurity Act 124/2025; Traficom guidance). Keep the IDs.
- [ ] Have the legal/GRC teammate verify every field in `config/regimes/*.yaml` against the real forms.
- [ ] Write 30+ scenarios **independently of the rules** (one person writes, another runs). The 9 included here were written alongside the rules, so 100% on them proves the plumbing, not accuracy.
- [ ] Wire ARCC-X to `send_event` and CyberGRC-AI to a real `GrcContextProvider`.
- [ ] Replace demo header auth with your JWT dependency.
- [ ] Pick one primary model and one fallback; measure both with `eval.py`.
- [ ] Build case, approval and report screens around the JSON; mobile approval view.
- [ ] Prepare n8n (escalation) and ElevenLabs (voice call) accounts; keep them as optional executors.
- [ ] Rehearse the re-skin drill for two sectors.

## Known limits (say these honestly if asked)

- Deadlines and report fields are paraphrased from the law; verify before real use. The
  CRA final-report clock models the exploited-vulnerability case (14 days after a fix);
  severe incidents use one month after notification.
- `submit_report` records submission; it does not file with Traficom or ENISA, whose
  portals are web forms. A human files and Vartija proves who approved what, when.
- The hash chain proves tampering, it does not prevent it. Anchor the chain head (from
  `/audit/verify`) outside the database for real use.
- Retrieval defaults to TF-IDF; `VARTIJA_RETRIEVER=hybrid` adds BM25 and cross-reference expansion. Dense embeddings are pluggable (`embed=`) but none is bundled.
- Redaction is regex-based: emails, phone numbers, Finnish personal ID codes, IBANs.
