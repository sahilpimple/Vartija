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
python -m pytest -q             # 18 tests: flow, tampering, policy, AI guardrails
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
- Retrieval is TF-IDF; switch to pgvector embeddings if the corpus grows or needs semantic match.
- Redaction is regex-based: emails, phone numbers, Finnish personal ID codes, IBANs.
