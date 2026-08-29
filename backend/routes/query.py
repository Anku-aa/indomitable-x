"""Agent query endpoint and governed request lifecycle."""

import time

from fastapi import APIRouter, Depends, HTTPException

from auth import verify_key
from core.auth_dependencies import _agent_for_key, require_api_key
from core.state import PENDING_APPROVALS, PENDING_CREATED_AT, PENDING_LOCK, _approval_ids
from guardian_agent import QUARANTINED_AGENTS, agent_risk_snapshot
from llm import interpret
from models import AgentQueryRequest
from policy_engine import apply_adaptive_risk, evaluate
from services.audit_service import _audit_entry
from services.query_service import _execute, _extract_id, _redact, _trace


router = APIRouter()


@router.post("/agent/query")
def agent_query(request: AgentQueryRequest, api_key: str = Depends(require_api_key)):
    key_agent_id = _agent_for_key(api_key)
    if key_agent_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if request.agent_id is None:
        request.agent_id = key_agent_id
    elif not verify_key(request.agent_id, api_key):
        raise HTTPException(status_code=401, detail="Invalid API key for claimed agent")
    if request.agent_id in QUARANTINED_AGENTS:
        raise HTTPException(status_code=403, detail=f"Agent {request.agent_id} is quarantined")

    parsed_query = interpret(request.query)
    policy = apply_adaptive_risk(
        evaluate(request.agent_id, parsed_query),
        parsed_query,
        agent_risk_snapshot(request.agent_id),
    )
    resolved_target_row_id = _extract_id(request.query, request.target_row_id)

    def lifecycle(database_status=None):
        trace = _trace(parsed_query, policy, database_status)
        trace[1]["agent_id"] = request.agent_id
        return trace

    if policy["decision"] == "DENY":
        result = {
            "status": "denied",
            "parsed_query": parsed_query,
            "adaptive_risk": agent_risk_snapshot(request.agent_id),
            "trace": lifecycle("blocked"),
        }
        _audit_entry(request, policy, result)
        result["adaptive_risk"] = agent_risk_snapshot(request.agent_id)
        return result

    if policy["decision"] == "REQUIRE_APPROVAL":
        with PENDING_LOCK:
            now = time.monotonic()
            for existing_id, existing in PENDING_APPROVALS.items():
                if (
                    existing["status"] == "pending_approval"
                    and existing["agent_id"] == request.agent_id
                    and existing["query"] == request.query
                    and now - PENDING_CREATED_AT.get(existing_id, 0) <= 5
                ):
                    return {
                        "status": "pending_approval",
                        "approval_id": existing_id,
                        "duplicate": True,
                        "trace": lifecycle("pending_approval"),
                    }

            approval_id = next(_approval_ids)
            pending = {
                "id": approval_id,
                "agent_id": request.agent_id,
                "query": request.query,
                "target_row_id": resolved_target_row_id,
                "parsed_query": parsed_query,
                "policy": policy,
                "status": "pending_approval",
            }
            PENDING_APPROVALS[approval_id] = pending
            PENDING_CREATED_AT[approval_id] = now
            result = {"status": "pending_approval", "approval_id": approval_id, "trace": lifecycle("pending_approval")}
        audit_record = _audit_entry(request, policy, result)
        pending["audit_id"] = audit_record["id"]
        result["adaptive_risk"] = agent_risk_snapshot(request.agent_id)
        return result

    try:
        executed = _execute(parsed_query, request.query, resolved_target_row_id)
        executed = _redact(executed, policy["redact_columns"])
        result = {
            "status": "executed",
            "parsed_query": parsed_query,
            "result": executed,
            "adaptive_risk": agent_risk_snapshot(request.agent_id),
            "trace": lifecycle("success"),
        }
    except Exception as exc:
        result = {
            "status": "execution_error",
            "error": str(exc),
            "parsed_query": parsed_query,
            "adaptive_risk": agent_risk_snapshot(request.agent_id),
            "trace": lifecycle("failed"),
        }
    _audit_entry(request, policy, result)
    result["adaptive_risk"] = agent_risk_snapshot(request.agent_id)
    return result
