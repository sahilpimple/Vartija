"""Approval gate: policy-as-config for who may authorise which action.

Rules enforced here, not in the UI:
  * Unknown actions are refused (fail closed).
  * AI and system actors may request, never approve.
  * The requester cannot approve their own request.
  * One vote per approver; any rejection rejects the request.
  * Only an approved request can be executed, and only once.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .config import Config
from .models import ActionRequest, Approval


class PolicyError(Exception):
    pass


Executor = Callable[[Session, ActionRequest], dict]
_EXECUTORS: dict[str, Executor] = {}


def register_executor(action: str) -> Callable[[Executor], Executor]:
    """Register the code that actually performs an approved action (call an API, open a ticket...)."""
    def wrap(fn: Executor) -> Executor:
        _EXECUTORS[action] = fn
        return fn
    return wrap


def rule_for(config: Config, action: str) -> dict:
    actions = config.policy.get("actions", {})
    if action not in actions:
        raise PolicyError(f"action '{action}' is not allowed by policy")
    approval = actions[action].get("approval", "none")
    if approval == "none":
        return {"mode": "none", "roles": []}
    if "all_of" in approval:
        return {"mode": "all_of", "roles": list(approval["all_of"])}
    if "any_of" in approval:
        return {"mode": "any_of", "roles": list(approval["any_of"])}
    raise PolicyError(f"bad approval rule for '{action}'")


def request_action(session: Session, config: Config, *, case_id: str, action: str, params: dict,
                   requested_by: str, requested_by_kind: str, rationale: str = "") -> ActionRequest:
    rule = rule_for(config, action)
    req = ActionRequest(
        case_id=case_id, action=action, params=params, requested_by=requested_by,
        requested_by_kind=requested_by_kind, rationale=rationale,
        status="approved" if rule["mode"] == "none" else "pending_approval",
        required_roles=rule["roles"],
    )
    session.add(req)
    session.flush()
    audit.append(session, action="action.requested", actor=requested_by, actor_kind=requested_by_kind,
                 case_id=case_id, payload={"request_id": req.id, "action": action, "params": params,
                                           "rationale": rationale, "required_roles": rule["roles"],
                                           "status": req.status})
    return req


def _approved(rule: dict, votes: list[Approval]) -> bool:
    approving_roles = {v.role for v in votes if v.decision == "approve"}
    if rule["mode"] == "any_of":
        return bool(approving_roles & set(rule["roles"]))
    if rule["mode"] == "all_of":
        return set(rule["roles"]) <= approving_roles
    return True


def decide(session: Session, config: Config, *, request_id: str, approver: str, approver_kind: str,
           role: str, decision: str, comment: str = "") -> ActionRequest:
    req = session.get(ActionRequest, request_id)
    if req is None:
        raise PolicyError("request not found")
    if approver_kind != "human":
        raise PolicyError("only a human can approve or reject an action")
    if req.status != "pending_approval":
        raise PolicyError(f"request is {req.status}, not pending approval")
    if approver == req.requested_by:
        raise PolicyError("the requester cannot approve their own request")
    if decision not in {"approve", "reject"}:
        raise PolicyError("decision must be 'approve' or 'reject'")
    if role not in req.required_roles:
        raise PolicyError(f"role '{role}' cannot decide this action; needs one of {req.required_roles}")
    if session.scalars(select(Approval).where(Approval.request_id == req.id,
                                              Approval.approver == approver)).first():
        raise PolicyError("this approver has already voted")

    session.add(Approval(request_id=req.id, approver=approver, role=role, decision=decision, comment=comment))
    session.flush()
    votes = list(session.scalars(select(Approval).where(Approval.request_id == req.id)))
    if decision == "reject":
        req.status = "rejected"
    elif _approved(rule_for(config, req.action), votes):
        req.status = "approved"
    audit.append(session, action="action.decided", actor=approver, actor_kind="human", case_id=req.case_id,
                 payload={"request_id": req.id, "role": role, "decision": decision, "comment": comment,
                          "status_after": req.status})
    return req


def execute(session: Session, *, request_id: str, actor: str, actor_kind: str = "system") -> ActionRequest:
    req = session.get(ActionRequest, request_id)
    if req is None:
        raise PolicyError("request not found")
    if req.status != "approved":
        raise PolicyError(f"cannot execute: request is {req.status}")
    executor = _EXECUTORS.get(req.action)
    try:
        result = executor(session, req) if executor else {"note": "no executor registered; recorded only"}
        req.status, req.result = "executed", result
    except Exception as exc:  # record the failure; never retry silently
        req.status, req.result = "failed", {"error": str(exc)}
    audit.append(session, action="action.executed", actor=actor, actor_kind=actor_kind, case_id=req.case_id,
                 payload={"request_id": req.id, "action": req.action, "status": req.status, "result": req.result})
    return req
