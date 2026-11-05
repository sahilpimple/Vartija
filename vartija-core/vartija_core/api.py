"""HTTP API.

Mount inside CyberGRC-AI's FastAPI app::

    from vartija_core.api import create_app
    app.mount("/vartija", create_app(grc_provider=MyCyberGrcProvider(...)))

or run it standalone: ``uvicorn vartija_core.api:app --reload``.

AUTH: ``current_principal`` reads demo headers (X-User, X-User-Kind, X-Roles). Replace it
with CyberGRC-AI's JWT dependency via ``app.dependency_overrides[current_principal]``
before showing anyone a real deployment. Every decision is still enforced in
``approvals.py`` regardless of what the UI shows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from pathlib import Path
import uuid
from datetime import timedelta

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import approvals, audit
from .agents import Assessor, ReportDrafter
from .clock import compute_clock
from .config import Config, load_config
from .db import create_all, make_engine, make_session_factory
from .grc import GrcContextProvider, YamlGrcProvider
from .ingest import EventIn, ingest
from .llm import LLM, make_llm
from .models import ActionRequest, Approval, Assessment, AuditEntry, Case, Event, ReportDraft, as_utc
from .auth_jwt import jwt_principal_dependency
from . import sources as src
from .docingest import load_refs
from .embeddings import make_embedder
from .rag import load_corpus, make_retriever
from .security import SignatureError, verify
from .settings import Settings, get_settings


# --------------------------------------------------------------------------- auth
@dataclass
class Principal:
    name: str
    kind: Literal["human", "ai", "system"]
    roles: list[str]


def current_principal(x_user: str | None = Header(default=None), x_user_kind: str = Header(default="human"),
                      x_roles: str = Header(default="")) -> Principal:
    """DEMO ONLY. Override with the host application's real authentication."""
    if not x_user:
        raise HTTPException(401, "missing X-User header (demo auth)")
    if x_user_kind not in {"human", "ai", "system"}:
        raise HTTPException(400, "X-User-Kind must be human, ai or system")
    return Principal(x_user, x_user_kind, [r.strip() for r in x_roles.split(",") if r.strip()])


# --------------------------------------------------------------------------- bodies
class AssessIn(BaseModel):
    apply_flags: bool = Field(default=False, description="A human confirms the AI's flags so the clocks start counting for them.")


class ConfirmFlagsIn(BaseModel):
    flags: dict[str, bool]
    reason: str = Field(min_length=3)


class ActionIn(BaseModel):
    action: str
    params: dict = Field(default_factory=dict)
    rationale: str = ""


class DecisionIn(BaseModel):
    decision: Literal["approve", "reject"]
    role: str
    comment: str = ""


class ReportIn(BaseModel):
    regime: str
    stage: str
    language: str = "en"


class MilestoneIn(BaseModel):
    key: Literal["corrective_measure"]
    at: datetime | None = None
    note: str = ""


# --------------------------------------------------------------------------- app
def create_app(settings: Settings | None = None, *, grc_provider: GrcContextProvider | None = None,
               llm: LLM | None = None, config: Config | None = None) -> FastAPI:
    settings = settings or get_settings()
    config = config or load_config(settings.config_dir)
    config.sector(settings.sector)  # fail fast on a typo in VARTIJA_SECTOR
    engine = make_engine(settings.database_url)
    create_all(engine)
    factory = make_session_factory(engine)
    grc = grc_provider or YamlGrcProvider(settings.seed_dir / "grc.yaml")
    model = llm or make_llm(settings)
    embed, embed_status = (make_embedder(settings) if settings.embed_backend.lower() not in {"", "none", "off"}
                           else (None, "embeddings off"))
    def build_retriever():
        chunks = load_corpus(settings.corpus_dir) + src.load_uploaded_corpus(settings.upload_dir)
        refs = {**load_refs(settings.corpus_dir), **src.load_uploaded_refs(settings.upload_dir)}
        return make_retriever(chunks, embed=embed, refs=refs)

    retriever = build_retriever()
    assessor = Assessor(config, retriever, model, settings.config_dir / "prompts")
    drafter = ReportDrafter(config, model, settings.config_dir / "prompts")

    app = FastAPI(title="Vartija core", version="0.1.0",
                  description="Signed incident intake, regulatory clock, approval gate, tamper-evident audit log.")
    app.state.settings, app.state.config, app.state.session_factory = settings, config, factory
    app.state.engine = engine
    if settings.auth_mode == "jwt":
        app.dependency_overrides[current_principal] = jwt_principal_dependency(
            settings.jwt_secret, Principal, settings.jwt_user_claim, settings.jwt_roles_claim)

    access = _load_access(settings.config_dir)

    def _views_of(who: Principal) -> list[str]:
        if not access.get("views"):
            return ["engineer", "executive"]          # no access.yaml: everything open (old behaviour)
        if who.kind in {"ai", "system"}:
            return ["engineer"]                       # agents work on cases; they never get the board view
        mine = set(who.roles)
        return [v for v, roles in access["views"].items() if mine & set(roles)]

    def engineer_view(who: Principal = Depends(current_principal)) -> Principal:
        if "engineer" not in _views_of(who):
            raise HTTPException(403, "your role does not have access to the engineer view")
        return who

    def executive_view(who: Principal = Depends(current_principal)) -> Principal:
        if "executive" not in _views_of(who):
            raise HTTPException(403, "your role does not have access to the executive view")
        return who

    def db() -> Session:
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_case(session: Session, case_id: str) -> Case:
        case = session.get(Case, case_id)
        if case is None:
            raise HTTPException(404, "case not found")
        return case

    def events_of(session: Session, case_id: str) -> list[Event]:
        return list(session.scalars(select(Event).where(Event.case_id == case_id).order_by(Event.occurred_at)))

    # -- executors: what an APPROVED action actually does --------------------------
    @approvals.register_executor("submit_report")
    def _submit_report(session: Session, req: ActionRequest) -> dict:
        regime, stage = req.params.get("regime"), req.params.get("stage")
        draft = session.get(ReportDraft, req.params.get("draft_id", ""))
        if not draft or draft.case_id != req.case_id or draft.regime != regime or draft.stage != stage:
            raise ValueError("submit_report needs a matching draft_id for this case, regime and stage")
        case = session.get(Case, req.case_id)
        when = datetime.now(timezone.utc).isoformat()
        case.milestones = {**(case.milestones or {}), f"{regime}:{stage}": when}
        case.status = "reported"
        # The prototype records submission. Sending to Traficom/ENISA is done by a human
        # (their portals are web forms); wire an API here only when one exists.
        return {"recorded_submission": f"{regime}:{stage}", "at": when, "draft_id": draft.id,
                "completeness": draft.completeness}

    @approvals.register_executor("open_corrective_action")
    def _corrective(session: Session, req: ActionRequest) -> dict:
        # Replace with a call into CyberGRC-AI (or Jira) that creates the corrective action.
        return {"corrective_action": req.params.get("title", "Follow-up from incident"), "created": True}

    # -- routes ------------------------------------------------------------------
    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "sector": settings.sector, "llm": model.name, "corpus_chunks": len(retriever.chunks),
                "retriever": type(retriever).__name__, "embeddings": embed_status, "auth": settings.auth_mode,
                "demo": settings.demo_enabled}

    @app.get("/me")
    def me(who: Principal = Depends(current_principal)) -> dict:
        return {"name": who.name, "kind": who.kind, "roles": who.roles, "views": _views_of(who)}

    @app.get("/exec/summary")
    def exec_summary(session: Session = Depends(db), who: Principal = Depends(executive_view)) -> dict:
        """Plain-language overview for executives: status, four numbers, risks, decisions, proof."""
        names = access.get("action_names") or {}
        plain = lambda a: names.get(a, a.replace("_", " ").capitalize())  # noqa: E731
        risks: list[dict] = []
        open_stages = on_track = 0
        waiting: list[dict] = []
        cases = session.scalars(select(Case).order_by(Case.detected_at.desc())).all()
        for c in cases:
            clk = compute_clock(c, config)
            for r in clk["regimes"]:
                if r["applies"] is False:
                    continue
                for st in r["stages"]:
                    if st["completed_at"] or st["status"] in {"waiting", "not_applicable", "done", "done_late"}:
                        continue
                    open_stages += 1
                    if st["status"] == "overdue":
                        risks.append({"level": "red", "case_id": c.id, "text": f"{st['label']} to {r['authority']} is overdue",
                                      "detail": f"{c.title} · was due {st['due_at']}"})
                    else:
                        on_track += 1
                        if st["status"] == "due_soon":
                            risks.append({"level": "amber", "case_id": c.id, "due_at": st["due_at"],
                                          "text": f"{st['label']} to {r['authority']} is due soon",
                                          "detail": f"{c.title}"})
            latest = session.scalars(select(Assessment).where(Assessment.case_id == c.id)
                                     .order_by(Assessment.created_at.desc())).first()
            if latest and c.status == "open":
                if any(latest.flags.values()) and not c.flags:
                    risks.append({"level": "amber", "case_id": c.id,
                                  "text": "Possible legal reporting duty not yet confirmed by a person",
                                  "detail": c.title})
                for k in latest.conflicts or []:
                    risks.append({"level": "amber", "case_id": c.id, "text": k.get("title") or k.get("id"),
                                  "detail": k.get("suggestion") or c.title})
            for req in session.scalars(select(ActionRequest).where(ActionRequest.case_id == c.id,
                                                                   ActionRequest.status == "pending_approval")):
                d = _request_dict(session, req)
                voted = {v["approver"] for v in d["votes"]}
                mine = [r for r in d["required_roles"] if r in who.roles]
                done_roles = {v["role"] for v in d["votes"] if v["decision"] == "approve"}
                if mine and who.name not in voted and req.requested_by != who.name:
                    waiting.append({"id": req.id, "action": req.action, "what": plain(req.action), "case": c.title,
                                    "your_role": next((r for r in mine if r not in done_roles), mine[0]),
                                    "approved_by": [f"{v['approver']} ({v['role']})" for v in d["votes"]
                                                    if v["decision"] == "approve"]})
        grouped: dict[tuple, dict] = {}
        for r in risks:  # the same issue on several cases is one line, with a count
            g = grouped.setdefault((r["level"], r["text"]), {**r, "cases": 0, "case_titles": []})
            g["cases"] += 1
            if r["detail"] not in g["case_titles"]:
                g["case_titles"].append(r["detail"])
        risks = list(grouped.values())
        for g in risks:
            if g["cases"] > 1:
                g["detail"] = f"{g['detail']} · on {g['cases']} cases"
        value = access.get("value") or {}
        minutes = value.get("minutes_saved") or {}
        counts: dict[str, int] = {}
        for action in minutes:
            key = "export.created" if action == "export" else action
            counts[action] = len(session.scalars(select(AuditEntry.seq).where(AuditEntry.action == key)).all())
        chain = audit.verify_chain(session).as_dict()
        level = "red" if any(r["level"] == "red" for r in risks) else ("amber" if risks or waiting else "green")
        n_open = sum(1 for c in cases if c.status == "open")
        headline = {"red": "Action needed now: a legal deadline has been missed",
                    "amber": "On track, with items that need attention",
                    "green": "On track: nothing needs your attention"}[level]
        pl = lambda n, w: f"{n} {w}{'' if n == 1 else 's'}"  # noqa: E731
        sub = (f"{pl(len(risks), 'item')} to watch, {pl(len(waiting), 'decision')} waiting on you, "
               f"{pl(n_open, 'open case')}") if cases else "No cases yet"
        return {"level": level, "headline": headline, "subline": sub,
                "deadlines": {"on_track": on_track, "open": open_stages},
                "risks": sorted(risks, key=lambda r: r["level"] != "red")[:8], "risk_count": len(risks),
                "waiting_on_you": waiting,
                "value": {"counts": counts, "minutes_saved": minutes, "hourly_cost": value.get("hourly_cost", 80),
                          "currency": value.get("currency", "EUR")},
                "proof": {"chain_ok": chain["ok"], "entries": chain["entries"]},
                "cases": {"total": len(cases), "open": n_open}}

    @app.get("/sources")
    def list_sources(who: Principal = Depends(engineer_view)) -> dict:
        return {"builtin": src.builtin_sources(settings.corpus_dir),
                "uploaded": src.list_uploads(settings.upload_dir),
                "corpus_chunks": len(retriever.chunks)}

    @app.post("/sources")
    async def upload_source(file: UploadFile = File(...), prefix: str = Form(default=""),
                            heading: str = Form(default=""), session: Session = Depends(db),
                            who: Principal = Depends(engineer_view)) -> dict:
        nonlocal retriever
        if who.kind != "human":
            raise HTTPException(403, "only a person can add sources")
        data = await file.read()
        if len(data) > settings.max_upload_mb * 1024 * 1024:
            raise HTTPException(413, f"file is larger than {settings.max_upload_mb} MB")
        builtin_ids = {c.id.split(":", 1)[0] for c in load_corpus(settings.corpus_dir)}
        try:
            info = src.save_upload(settings.upload_dir, file.filename or "upload", data, prefix=prefix,
                                   heading=heading, reserved_prefixes=builtin_ids, uploaded_by=who.name)
        except src.SourceError as exc:
            raise HTTPException(400, str(exc)) from exc
        if info["kind"] == "document":
            try:
                retriever = build_retriever()
            except ValueError as exc:  # e.g. duplicate ids across files
                src.delete_upload(settings.upload_dir, info["name"])
                raise HTTPException(400, f"could not add to the corpus: {exc}") from exc
            assessor.retriever = retriever
        audit.append(session, action="source.uploaded", actor=who.name, actor_kind="human",
                     payload={k: info[k] for k in ("name", "kind", "sha256", "bytes", "prefix", "paragraphs")
                              if k in info})
        return {**info, "corpus_chunks": len(retriever.chunks)}

    @app.delete("/sources/{name}")
    def delete_source(name: str, session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> dict:
        nonlocal retriever
        if who.kind != "human":
            raise HTTPException(403, "only a person can remove sources")
        try:
            info = src.delete_upload(settings.upload_dir, name)
        except src.SourceError as exc:
            raise HTTPException(404, str(exc)) from exc
        retriever = build_retriever()
        assessor.retriever = retriever
        audit.append(session, action="source.removed", actor=who.name, actor_kind="human",
                     payload={"name": name, "sha256": info.get("sha256")})
        return {"removed": name, "corpus_chunks": len(retriever.chunks)}

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        return (Path(__file__).parent / "static" / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/cases/{case_id}/actions")
    def list_actions(case_id: str, session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> list[dict]:
        get_case(session, case_id)
        rows = session.scalars(select(ActionRequest).where(ActionRequest.case_id == case_id)
                               .order_by(ActionRequest.created_at))
        return [_request_dict(session, r) for r in rows]

    @app.post("/demo/seed", include_in_schema=settings.demo_enabled)
    def demo_seed(session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> dict:
        """Create a sample case from the active sector's story (demo mode only)."""
        if not settings.demo_enabled:
            raise HTTPException(404, "demo mode is off")
        now = datetime.now(timezone.utc)
        corr = f"demo-{uuid.uuid4().hex[:8]}"
        stories = {
            "industrial": [("vuln.exploited_in_wild", "high", 0.8, "plc-line-3",
                            "Threat intel: active exploitation of an auth bypass in PLC firmware 4.2 we ship.",
                            {"actively_exploited": True, "product_affected": True})],
            "maritime": [("malware.detected", "critical", 0.85, "plc-line-3",
                          "Malware found on a delivered vessel's navigation workstation via a supplied USB update.",
                          {"product_affected": True, "malicious": True, "cross_border": True, "users_affected": 3})],
        }
        default = [("auth.anomaly", "medium", 0.6, "web-portal-01",
                    "Login failure rate on the customer portal 40x above baseline.", {"malicious": True}),
                   ("auth.credential_stuffing", "high", 0.9, "web-portal-01",
                    "Credential stuffing confirmed; 4,200 customer accounts accessed.",
                    {"users_affected": 4200, "malicious": True, "cross_border": True, "personal_data": True})]
        case_id = None
        for i, (etype, sev, conf, asset, summary, attrs) in enumerate(stories.get(settings.sector, default)):
            ev = EventIn(event_id=f"evt-{uuid.uuid4().hex}", source="demo-seed", event_type=etype,
                         occurred_at=now - timedelta(minutes=10 - i * 5), correlation_id=corr, asset_id=asset,
                         severity=sev, confidence=conf, summary=summary, attributes=attrs,
                         evidence_refs=[f"demo://{corr}/evidence-{i}"])
            case, _ = ingest(session, ev, ev.model_dump_json().encode(), sector=settings.sector)
            case_id = case.id
        return {"case_id": case_id, "seeded_by": who.name}

    @app.post("/events")
    async def receive_event(request: Request, session: Session = Depends(db),
                            x_vartija_timestamp: str | None = Header(default=None),
                            x_vartija_signature: str | None = Header(default=None)) -> dict:
        raw = await request.body()
        try:
            verify(settings.event_secret, raw, x_vartija_timestamp, x_vartija_signature,
                   settings.max_clock_skew_seconds)
        except SignatureError as exc:
            raise HTTPException(401, f"event rejected: {exc}") from exc
        try:
            event = EventIn.model_validate_json(raw)
        except ValidationError as exc:
            raise HTTPException(422, exc.errors(include_url=False, include_context=False)) from exc
        case, created = ingest(session, event, raw, sector=settings.sector)
        return {"case_id": case.id, "duplicate": not created}

    @app.get("/cases")
    def list_cases(session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> list[dict]:
        cases = session.scalars(select(Case).order_by(Case.detected_at.desc())).all()
        return [{"id": c.id, "title": c.title, "status": c.status, "sector": c.sector,
                 "detected_at": as_utc(c.detected_at).isoformat(), "flags": c.flags} for c in cases]

    @app.get("/cases/{case_id}")
    def case_detail(case_id: str, session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> dict:
        case = get_case(session, case_id)
        latest = session.scalars(select(Assessment).where(Assessment.case_id == case_id)
                                 .order_by(Assessment.created_at.desc())).first()
        return {
            "id": case.id, "title": case.title, "status": case.status, "asset_id": case.asset_id,
            "sector": case.sector, "detected_at": as_utc(case.detected_at).isoformat(), "flags": case.flags,
            "milestones": case.milestones, "grc": grc.context_for(case.asset_id),
            "events": [{"event_id": e.event_id, "type": e.event_type, "severity": e.severity,
                        "confidence": e.confidence, "summary": e.summary, "attributes": e.attributes,
                        "evidence_refs": e.evidence_refs, "occurred_at": as_utc(e.occurred_at).isoformat()}
                       for e in events_of(session, case_id)],
            "latest_assessment": _assessment_dict(latest) if latest else None,
        }

    @app.get("/cases/{case_id}/clock")
    def clock(case_id: str, session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> dict:
        return compute_clock(get_case(session, case_id), config)

    @app.post("/cases/{case_id}/assess")
    def assess(case_id: str, body: AssessIn, session: Session = Depends(db),
               who: Principal = Depends(engineer_view)) -> dict:
        case = get_case(session, case_id)
        events = events_of(session, case_id)
        if not events:
            raise HTTPException(409, "case has no events")
        result = assessor.assess(case, events, grc.context_for(case.asset_id))
        row = Assessment(case_id=case.id, engine=result.engine, prompt_version=result.prompt_version,
                         flags=result.flags, confidence=result.confidence, rationale=result.rationale,
                         citations=result.citations, rejected_citations=result.rejected_citations,
                         conflicts=result.conflicts, recommended_actions=result.recommended_actions,
                         needs_human_review=result.needs_human_review)
        session.add(row)
        session.flush()
        audit.append(session, action="assessment.created", actor=result.engine, actor_kind="ai", case_id=case.id,
                     payload={"assessment_id": row.id, "flags": result.flags, "confidence": result.confidence,
                              "citations": result.citations, "rejected_citations": result.rejected_citations,
                              "prompt_version": result.prompt_version, "context_ids": result.context_ids,
                              "requested_by": who.name})
        if body.apply_flags:
            _confirm(session, case, result.flags, f"accepted assessment {row.id}", who)
        out = _assessment_dict(row)
        out["context_ids"] = result.context_ids
        out["citation_texts"] = {c: retriever.get(c).title for c in result.citations if retriever.get(c)}
        return out

    def _confirm(session: Session, case: Case, flags: dict, reason: str, who: Principal) -> None:
        if who.kind != "human":
            raise HTTPException(403, "only a human can confirm which reporting duties apply")
        case.flags = {k: bool(v) for k, v in flags.items()}
        audit.append(session, action="flags.confirmed", actor=who.name, actor_kind="human", case_id=case.id,
                     payload={"flags": case.flags, "reason": reason})

    @app.post("/cases/{case_id}/flags")
    def confirm_flags(case_id: str, body: ConfirmFlagsIn, session: Session = Depends(db),
                      who: Principal = Depends(engineer_view)) -> dict:
        case = get_case(session, case_id)
        _confirm(session, case, body.flags, body.reason, who)
        return {"flags": case.flags}

    @app.post("/cases/{case_id}/milestones")
    def milestone(case_id: str, body: MilestoneIn, session: Session = Depends(db),
                  who: Principal = Depends(engineer_view)) -> dict:
        if who.kind != "human":
            raise HTTPException(403, "only a human can record milestones")
        case = get_case(session, case_id)
        at = (body.at or datetime.now(timezone.utc)).isoformat()
        case.milestones = {**(case.milestones or {}), body.key: at}
        audit.append(session, action="milestone.recorded", actor=who.name, actor_kind="human", case_id=case.id,
                     payload={"key": body.key, "at": at, "note": body.note})
        return {"milestones": case.milestones}

    @app.post("/cases/{case_id}/actions")
    def request_action(case_id: str, body: ActionIn, session: Session = Depends(db),
                       who: Principal = Depends(engineer_view)) -> dict:
        get_case(session, case_id)
        try:
            req = approvals.request_action(session, config, case_id=case_id, action=body.action, params=body.params,
                                           requested_by=who.name, requested_by_kind=who.kind,
                                           rationale=body.rationale)
        except approvals.PolicyError as exc:
            raise HTTPException(403, str(exc)) from exc
        return _request_dict(session, req)

    @app.post("/actions/{request_id}/decide")
    def decide(request_id: str, body: DecisionIn, session: Session = Depends(db),
               who: Principal = Depends(current_principal)) -> dict:
        if body.role not in who.roles:
            raise HTTPException(403, f"you do not hold the role '{body.role}'")
        try:
            req = approvals.decide(session, config, request_id=request_id, approver=who.name,
                                   approver_kind=who.kind, role=body.role, decision=body.decision,
                                   comment=body.comment)
        except approvals.PolicyError as exc:
            raise HTTPException(403, str(exc)) from exc
        return _request_dict(session, req)

    @app.post("/actions/{request_id}/execute")
    def execute(request_id: str, session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> dict:
        try:
            req = approvals.execute(session, request_id=request_id, actor=who.name, actor_kind=who.kind)
        except approvals.PolicyError as exc:
            raise HTTPException(409, str(exc)) from exc
        return _request_dict(session, req)

    @app.post("/cases/{case_id}/reports")
    def draft_report(case_id: str, body: ReportIn, session: Session = Depends(db),
                     who: Principal = Depends(engineer_view)) -> dict:
        case = get_case(session, case_id)
        regime = config.regimes.get(body.regime)
        if regime is None or regime.id not in config.sector(case.sector).regimes:
            raise HTTPException(404, f"regime '{body.regime}' is not in scope for this sector")
        latest = session.scalars(select(Assessment).where(Assessment.case_id == case_id)
                                 .order_by(Assessment.created_at.desc())).first()
        try:
            fields, completeness, eng = drafter.draft(
                case=case, events=events_of(session, case_id), grc=grc.context_for(case.asset_id),
                regime=regime, stage=body.stage, citations=latest.citations if latest else [],
                language=body.language)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
        draft = ReportDraft(case_id=case.id, regime=regime.id, stage=body.stage, language=body.language,
                            fields=fields, completeness=completeness)
        session.add(draft)
        session.flush()
        audit.append(session, action="report.drafted", actor=eng, actor_kind="ai", case_id=case.id,
                     payload={"draft_id": draft.id, "regime": regime.id, "stage": body.stage,
                              "completeness": completeness, "fields": fields, "requested_by": who.name})
        return {"draft_id": draft.id, "regime": regime.id, "authority": regime.authority, "stage": body.stage,
                "engine": eng, "completeness": completeness, "fields": fields}

    @app.get("/cases/{case_id}/audit")
    def case_audit(case_id: str, session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> list[dict]:
        get_case(session, case_id)
        rows = session.scalars(select(AuditEntry).where(AuditEntry.case_id == case_id).order_by(AuditEntry.seq))
        return [{"seq": r.seq, "ts": r.ts, "actor": r.actor, "actor_kind": r.actor_kind, "action": r.action,
                 "payload": r.payload, "entry_hash": r.entry_hash} for r in rows]

    @app.get("/audit/verify")
    def verify_audit(session: Session = Depends(db), who: Principal = Depends(current_principal)) -> dict:
        return audit.verify_chain(session).as_dict()

    @app.get("/cases/{case_id}/export")
    def export_pack(case_id: str, session: Session = Depends(db), who: Principal = Depends(engineer_view)) -> dict:
        """Audit pack: everything a reviewer needs, plus the chain head to anchor elsewhere."""
        detail = case_detail(case_id, session, who)
        audit.append(session, action="export.created", actor=who.name, actor_kind=who.kind, case_id=case_id,
                     payload={"exported_by": who.name})
        return {
            "case": detail, "clock": compute_clock(get_case(session, case_id), config),
            "reports": [{"draft_id": d.id, "regime": d.regime, "stage": d.stage, "completeness": d.completeness,
                         "fields": d.fields, "created_at": as_utc(d.created_at).isoformat()}
                        for d in session.scalars(select(ReportDraft).where(ReportDraft.case_id == case_id))],
            "audit_trail": case_audit(case_id, session, who),
            "chain": audit.verify_chain(session).as_dict(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    return app


def _load_access(config_dir: Path) -> dict:
    import yaml

    path = Path(config_dir) / "access.yaml"
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}


def _assessment_dict(a: Assessment) -> dict:
    return {"id": a.id, "engine": a.engine, "prompt_version": a.prompt_version, "flags": a.flags,
            "confidence": a.confidence, "rationale": a.rationale, "citations": a.citations,
            "rejected_citations": a.rejected_citations, "conflicts": a.conflicts,
            "recommended_actions": a.recommended_actions, "needs_human_review": a.needs_human_review,
            "created_at": as_utc(a.created_at).isoformat()}


def _request_dict(session: Session, r: ActionRequest) -> dict:
    votes = session.scalars(select(Approval).where(Approval.request_id == r.id)).all()
    return {"id": r.id, "case_id": r.case_id, "action": r.action, "params": r.params, "status": r.status,
            "requested_by": r.requested_by, "requested_by_kind": r.requested_by_kind,
            "required_roles": r.required_roles, "result": r.result,
            "votes": [{"approver": v.approver, "role": v.role, "decision": v.decision} for v in votes]}


def __getattr__(name: str):  # lazily build ``app`` for ``uvicorn vartija_core.api:app``
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
