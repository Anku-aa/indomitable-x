"""Approval queue and review endpoints."""

from fastapi import APIRouter, HTTPException

from core.state import PENDING_APPROVALS, PENDING_CREATED_AT, PENDING_LOCK
from models import AgentQueryRequest, ApprovalRequest
from services.audit_service import _audit_entry, _timestamp, _update_audit_entry
from services.query_service import _approval_trace, _execute, _redact


router = APIRouter()


@router.get("/approvals")
def approvals():
    return {"approvals": [pending for pending in PENDING_APPROVALS.values() if pending["status"] in {"pending_approval", "auto_held_quarantine"}]}


def _quarantine_agent(agent_id: str, reasoning: str):
    """Quarantine an agent and hold its unresolved approvals immediately."""
    from guardian_agent import QUARANTINED_AGENTS, QUARANTINE_REASONS

    QUARANTINED_AGENTS.add(agent_id)
    QUARANTINE_REASONS[agent_id] = reasoning
    held_at = _timestamp()
    with PENDING_LOCK:
        for pending in PENDING_APPROVALS.values():
            if pending["agent_id"] == agent_id and pending["status"] == "pending_approval":
                pending["status"] = "auto_held_quarantine"
                pending["auto_hold_reason"] = "Agent quarantined after this request was submitted"
                pending["auto_held_at"] = held_at
                PENDING_CREATED_AT.pop(pending["id"], None)


@router.post("/approvals/{approval_id}")
def review_approval(approval_id: int, review: ApprovalRequest):
    pending = PENDING_APPROVALS.get(approval_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if pending["status"] != "pending_approval":
        if pending["status"] == "auto_held_quarantine":
            if review.approve and not review.confirm_quarantine_override:
                raise HTTPException(status_code=409, detail="Explicit quarantine override confirmation is required to approve this request")
        else:
            raise HTTPException(status_code=409, detail="Approval request already reviewed")

    pending["reviewer"] = review.reviewer
    pending["reviewed_at"] = _timestamp()
    PENDING_CREATED_AT.pop(approval_id, None)
    original_request = AgentQueryRequest(agent_id=pending["agent_id"], query=pending["query"], target_row_id=pending["target_row_id"])

    if not review.approve:
        pending["status"] = "rejected"
        rejected_policy = {**pending["policy"], "reasons": pending["policy"]["reasons"] + [f"Approval rejected by {review.reviewer}"]}
        rejected_result = {"status": "rejected", "reviewer": review.reviewer}
        if pending.get("audit_id"):
            _update_audit_entry(pending["audit_id"], rejected_policy, rejected_result)
        else:
            _audit_entry(original_request, rejected_policy, rejected_result)
        pending["trace"] = _approval_trace(pending, "REJECTED", "blocked")
        return pending

    try:
        executed = _redact(_execute(pending["parsed_query"], pending["query"], pending["target_row_id"]), pending["policy"]["redact_columns"])
        pending["status"] = "executed"
        pending["result"] = executed
        approved_policy = {**pending["policy"], "decision": "ALLOW"}
        approved_result = {"status": "approved", "reviewer": review.reviewer, "result": executed}
        if pending.get("audit_id"):
            _update_audit_entry(pending["audit_id"], approved_policy, approved_result)
        else:
            _audit_entry(original_request, approved_policy, approved_result)
        pending["trace"] = _approval_trace(pending, "APPROVED", "success")
    except Exception as exc:
        pending["status"] = "execution_error"
        pending["result"] = {"error": str(exc)}
        error_result = {"status": "execution_error", "reviewer": review.reviewer, "error": str(exc)}
        if pending.get("audit_id"):
            _update_audit_entry(pending["audit_id"], pending["policy"], error_result)
        else:
            _audit_entry(original_request, pending["policy"], error_result)
        pending["trace"] = _approval_trace(pending, "APPROVED", "failed")
    return pending
