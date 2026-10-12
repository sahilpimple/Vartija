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

from fastapi import Depends, FastAPI, Header, HTTPException, Request
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
from .rag import Retriever, load_corpus
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
    retriever = Retriever(load_corpus(settings.corpus_dir))
    assessor = Assessor(config, retriever, model, settings.config_dir / "prompts")
    drafter = ReportDrafter(config, model, settings.config_dir / "prompts")

    app = FastAPI(title="Vartija core", version="0.1.0",
                  description="Signed incident intake, regulatory clock, approval gate, tamper-evident audit log.")
    app.state.settings, app.state.config, app.state.session_factory = settings, config, factory
    app.state.engine = engine

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
        return {"ok": True, "sector": settings.sector, "llm": model.name, "corpus_chunks": len(retriever.chunks)}

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
    def list_cases(session: Session = Depends(db), who: Principal = Depends(current_principal)) -> list[dict]:
        cases = session.scalars(select(Case).order_by(Case.detected_at.desc())).all()
        return [{"id": c.id, "title": c.title, "status": c.status, "sector": c.sector,
                 "detected_at": as_utc(c.detected_at).isoformat(), "flags": c.flags} for c in cases]

    @app.get("/cases/{case_id}")
    def case_detail(case_id: str, session: Session = Depends(db), who: Principal = Depends(current_principal)) -> dict:
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
    def clock(case_id: str, session: Session = Depends(db), who: Principal = Depends(current_principal)) -> dict:
        return compute_clock(get_case(session, case_id), config)

    @app.post("/cases/{case_id}/assess")
    def assess(case_id: str, body: AssessIn, session: Session = Depends(db),
               who: Principal = Depends(current_principal)) -> dict:
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
                      who: Principal = Depends(current_principal)) -> dict:
        case = get_case(session, case_id)
        _confirm(session, case, body.flags, body.reason, who)
        return {"flags": case.flags}

    @app.post("/cases/{case_id}/milestones")
    def milestone(case_id: str, body: MilestoneIn, session: Session = Depends(db),
                  who: Principal = Depends(current_principal)) -> dict:
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
                       who: Principal = Depends(current_principal)) -> dict:
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
    def execute(request_id: str, session: Session = Depends(db), who: Principal = Depends(current_principal)) -> dict:
        try:
            req = approvals.execute(session, request_id=request_id, actor=who.name, actor_kind=who.kind)
        except approvals.PolicyError as exc:
            raise HTTPException(409, str(exc)) from exc
        return _request_dict(session, req)

    @app.post("/cases/{case_id}/reports")
    def draft_report(case_id: str, body: ReportIn, session: Session = Depends(db),
                     who: Principal = Depends(current_principal)) -> dict:
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
    def case_audit(case_id: str, session: Session = Depends(db), who: Principal = Depends(current_principal)) -> list[dict]:
        get_case(session, case_id)
        rows = session.scalars(select(AuditEntry).where(AuditEntry.case_id == case_id).order_by(AuditEntry.seq))
        return [{"seq": r.seq, "ts": r.ts, "actor": r.actor, "actor_kind": r.actor_kind, "action": r.action,
                 "payload": r.payload, "entry_hash": r.entry_hash} for r in rows]

    @app.get("/audit/verify")
    def verify_audit(session: Session = Depends(db), who: Principal = Depends(current_principal)) -> dict:
        return audit.verify_chain(session).as_dict()

    @app.get("/cases/{case_id}/export")
    def export_pack(case_id: str, session: Session = Depends(db), who: Principal = Depends(current_principal)) -> dict:
        """Audit pack: everything a reviewer needs, plus the chain head to anchor elsewhere."""
        detail = case_detail(case_id, session, who)
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
