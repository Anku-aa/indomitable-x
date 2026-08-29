"""Guardian, quarantine, and adaptive risk endpoints."""

import time

from fastapi import APIRouter, HTTPException

from guardian_agent import QUARANTINED_AGENTS, QUARANTINE_REASONS, all_agent_risk_snapshots, analyze_recent_activity
from models import AgentQueryRequest
from services.audit_service import _audit_entry
from routes.approvals import _quarantine_agent
from core.state import PENDING_APPROVALS, PENDING_CREATED_AT, PENDING_LOCK


router = APIRouter()


@router.post("/guardian/run")
def guardian_run():
    report = analyze_recent_activity()
    for verdict in report["verdicts"]:
        if verdict["verdict"] == "quarantine":
            _quarantine_agent(verdict["agent_id"], verdict["reasoning"])

    guardian_request = AgentQueryRequest(agent_id="guardian_agent", query="Autonomous Guardian analysis of recent audit activity")
    guardian_policy = {
        "decision": "SYSTEM",
        "risk_score": 0,
        "reasons": ["Guardian Agent completed autonomous behavioral analysis"],
        "redact_columns": [],
    }
    _audit_entry(guardian_request, guardian_policy, {"status": "SYSTEM", "event_type": "guardian_analysis", "verdicts": report["verdicts"], "summary": report["summary"]})
    return report


@router.get("/guardian/status")
def guardian_status():
    agent_status = []
    for snapshot in all_agent_risk_snapshots():
        agent_id = snapshot["agent_id"]
        agent_status.append({
            **snapshot,
            "status": "quarantined" if agent_id in QUARANTINED_AGENTS else "restricted" if snapshot["risk_level"] == "RESTRICTED" else "clear",
            "reasoning": QUARANTINE_REASONS.get(agent_id, snapshot["reason"]),
        })
    return {
        "quarantined_agents": [{"agent_id": agent_id, "reasoning": QUARANTINE_REASONS.get(agent_id, "")} for agent_id in sorted(QUARANTINED_AGENTS)],
        "agents": agent_status,
    }


@router.get("/agent-risk")
def agent_risk():
    return {"agents": all_agent_risk_snapshots()}


@router.post("/guardian/lift/{agent_id}")
def guardian_lift(agent_id: str):
    if agent_id not in QUARANTINED_AGENTS:
        raise HTTPException(status_code=404, detail="Agent is not quarantined")
    QUARANTINED_AGENTS.remove(agent_id)
    reasoning = QUARANTINE_REASONS.pop(agent_id, "")
    restored = 0
    with PENDING_LOCK:
        for pending in PENDING_APPROVALS.values():
            if pending["agent_id"] == agent_id and pending["status"] == "auto_held_quarantine":
                pending["status"] = "pending_approval"
                pending.pop("auto_hold_reason", None)
                pending.pop("auto_held_at", None)
                PENDING_CREATED_AT[pending["id"]] = time.monotonic()
                restored += 1
    return {"agent_id": agent_id, "status": "quarantine_lifted", "restored_pending_approvals": restored, "previous_reasoning": reasoning}
