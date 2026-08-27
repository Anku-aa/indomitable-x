"""FastAPI application for the AgentGate governance layer."""

from datetime import datetime, timezone
import hashlib
from fastapi.responses import Response
import json
import re
import time
from decimal import Decimal
from itertools import count
from threading import Lock
from typing import Any, Optional
import uuid

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import text

from auth import AGENT_KEYS, verify_key
from db import get_engine, get_conn, get_table_schema, init_db
from llm import extract_target_row_id, interpret
from policy_engine import AGENT_ROLES, evaluate
from guardian_agent import (
    QUARANTINED_AGENTS,
    QUARANTINE_REASONS,
    analyze_recent_activity,
)
from compliance_agent import generate_pdf, generate_report


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


init_db()
PENDING_APPROVALS = {}
PENDING_CREATED_AT = {}
PENDING_LOCK = Lock()
AUDIT_LOCK = Lock()
_approval_ids = count(1)
bearer_scheme = HTTPBearer(auto_error=False)


class AgentQueryRequest(BaseModel):
    agent_id: Optional[str] = None
    query: str
    target_row_id: Optional[int] = None


class ApprovalRequest(BaseModel):
    approve: bool
    reviewer: str
    confirm_quarantine_override: bool = False


app = FastAPI(title="AgentGate")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization Bearer token required")
    return credentials.credentials


def _agent_for_key(api_key: str) -> Optional[str]:
    """Resolve a supplied credential without trusting a client-supplied identity."""
    for agent_id, expected_key in AGENT_KEYS.items():
        if api_key == expected_key:
            return agent_id
    return None


@app.on_event("startup")
def print_agent_keys():
    print("AgentGate API keys (demo-only; keep these secret):")
    for agent_id, key in AGENT_KEYS.items():
        print(f"  {agent_id}: {key}")


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _hash_payload(payload, prev_hash):
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256((canonical + prev_hash).encode("utf-8")).hexdigest()


def _json_safe(value):
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _audit_payload(row):
    row = row._mapping
    return {
        "id": row["id"],
        "ts": row["ts"],
        "agent_id": row["agent_id"],
        "nl_query": row["nl_query"],
        "decision": row["decision"],
        "risk_score": row["risk_score"],
        "reasons": json.loads(row["reasons"]),
        "redact_columns": json.loads(row["redact_columns"]),
        "result": json.loads(row["result"]),
        "status": row["status"],
    }


def _audit_response(row):
    row = row._mapping
    return {
        "id": row["id"],
        "timestamp": datetime.fromtimestamp(row["ts"], timezone.utc).isoformat(),
        "agent_id": row["agent_id"],
        "query": row["nl_query"],
        "decision": row["decision"],
        "risk_score": row["risk_score"],
        "reasons": json.loads(row["reasons"]),
        "redact_columns": json.loads(row["redact_columns"]),
        "result": json.loads(row["result"]),
        "status": row["status"],
        "prev_hash": row["prev_hash"],
        "entry_hash": row["entry_hash"],
    }


def _extract_id(query: str, target_row_id: Optional[int]):
    if target_row_id is not None:
        return target_row_id
    return extract_target_row_id(query)


def _safe_identifier(identifier: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier or ""):
        raise ValueError(f"Invalid SQL identifier: {identifier}")
    return identifier


def _execute(parsed_query: dict[str, Any], query: str, target_row_id: Optional[int]):
    """Execute the already-policy-checked query and return JSON-safe data."""
    sql = parsed_query["sql"].rstrip().rstrip(";")
    operation = parsed_query["operation"]
    table = _safe_identifier(parsed_query["table"])
    row_id = _extract_id(query, target_row_id)
    params = {}
    schema = get_table_schema(table)
    schema_columns = [str(column["name"]) for column in schema]
    row_key = next((str(column["name"]) for column in schema if column.get("primary_key")), None)
    row_key = row_key or next((column for column in ("id", "Employee_ID") if column in schema_columns), None)

    if operation == "DELETE":
        if row_id is None:
            raise ValueError("An employee id is required for DELETE")
        if row_key is None:
            raise ValueError(f"Table '{table}' has no primary key for targeted DELETE")
        with get_engine().begin() as connection:
            cursor = connection.execute(
                text(f"DELETE FROM {table} WHERE {row_key} = :row_id"),
                {"row_id": row_id},
            )
            if cursor.rowcount == 0:
                return {"status": f"no employee row found for id {row_id}", "row_count": 0}
            return {"status": f"deleted row id {row_id}", "row_count": cursor.rowcount}

    if ":id" in sql:
        if row_id is None:
            raise ValueError("An employee id is required for this query")
        params["id"] = row_id

    if operation == "SELECT" and row_id is not None and ":id" not in sql and row_key:
        sql += f" WHERE {row_key} = :id"
        params["id"] = row_id

    if operation == "SELECT" and "department" in {column.lower() for column in parsed_query["columns"]} and " where " not in sql.lower():
        department_match = re.search(r"\b(?:in|from)\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 &-]*)\s+department\b", query, re.IGNORECASE)
        if department_match:
            sql += " WHERE Department = :department_filter"
            params["department_filter"] = department_match.group(1).strip()

    for column in parsed_query["columns"]:
        if operation != "UPDATE":
            continue
        if f":{column}" not in sql:
            continue
        if column == "salary":
            match = re.search(r"\bsalary\s*(?:to|=)\s*\$?(\d+)\b", query, re.IGNORECASE)
            params[column] = int(match.group(1)) if match else None
        else:
            match = re.search(
                rf"\b{re.escape(column)}\s*(?:to|=|as)\s+['\"]?([^,.;]+)",
                query,
                re.IGNORECASE,
            )
            params[column] = match.group(1).strip() if match else None
        if params[column] is None:
            raise ValueError(f"A value for {column} is required for this update")

    with get_engine().begin() as connection:
        cursor = connection.execute(text(sql), params)
        if operation == "SELECT":
            rows = [_json_safe(dict(row._mapping)) for row in cursor.fetchall()]
            return {"rows": rows, "row_count": len(rows)}
        return {"row_count": cursor.rowcount}


def _redact(result: dict, redact_columns: list[str]):
    if not redact_columns or "rows" not in result:
        return result
    redacted = []
    for row in result["rows"]:
        row_copy = dict(row)
        for column in redact_columns:
            if column in row_copy:
                row_copy[column] = "***REDACTED***"
        redacted.append(row_copy)
    return {**result, "rows": redacted}


def _audit_entry(request: AgentQueryRequest, policy: dict, result: dict):
    status = result.get("status", policy["decision"].lower())
    with AUDIT_LOCK, get_engine().begin() as connection:
        previous = connection.execute(
            text("SELECT entry_hash FROM audit_log ORDER BY ts DESC, id DESC LIMIT 1")
        ).fetchone()
        prev_hash = previous._mapping["entry_hash"] if previous else "GENESIS"
        payload = {
            "id": uuid.uuid4().hex,
            "ts": time.time(),
            "agent_id": request.agent_id,
            "nl_query": request.query,
            "decision": policy["decision"],
            "risk_score": policy["risk_score"],
            "reasons": policy["reasons"],
            "redact_columns": policy["redact_columns"],
            "result": result,
            "status": status,
        }
        entry_hash = _hash_payload(payload, prev_hash)
        connection.execute(
            text("""
            INSERT INTO audit_log
                (id, ts, agent_id, nl_query, decision, risk_score, reasons,
                 redact_columns, result, status, prev_hash, entry_hash)
            VALUES (:id, :ts, :agent_id, :nl_query, :decision, :risk_score,
                    :reasons, :redact_columns, :result, :status, :prev_hash,
                    :entry_hash)
            """),
            {
                "id": payload["id"],
                "ts": payload["ts"],
                "agent_id": payload["agent_id"],
                "nl_query": payload["nl_query"],
                "decision": payload["decision"],
                "risk_score": payload["risk_score"],
                "reasons": json.dumps(payload["reasons"], sort_keys=True),
                "redact_columns": json.dumps(payload["redact_columns"], sort_keys=True),
                "result": json.dumps(payload["result"], sort_keys=True),
                "status": payload["status"],
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
            },
        )
        return {**payload, "prev_hash": prev_hash, "entry_hash": entry_hash}


def _update_audit_entry(audit_id: str, policy: dict, result: dict):
    """Update one lifecycle record and re-chain hashes for later entries."""
    with AUDIT_LOCK, get_engine().begin() as connection:
        rows = connection.execute(
            text("SELECT * FROM audit_log ORDER BY ts ASC, id ASC")
        ).fetchall()
        target_index = next(
            (index for index, row in enumerate(rows) if row._mapping["id"] == audit_id),
            None,
        )
        if target_index is None:
            raise ValueError(f"Audit entry not found: {audit_id}")

        states = [dict(row._mapping) for row in rows]
        target = states[target_index]
        target["decision"] = policy["decision"]
        target["risk_score"] = policy["risk_score"]
        target["reasons"] = json.dumps(policy["reasons"], sort_keys=True)
        target["redact_columns"] = json.dumps(policy["redact_columns"], sort_keys=True)
        target["result"] = json.dumps(result, sort_keys=True)
        target["status"] = result.get("status", policy["decision"].lower())

        previous_hash = "GENESIS" if target_index == 0 else states[target_index - 1]["entry_hash"]
        for index in range(target_index, len(states)):
            state = states[index]
            payload = {
                "id": state["id"],
                "ts": state["ts"],
                "agent_id": state["agent_id"],
                "nl_query": state["nl_query"],
                "decision": state["decision"],
                "risk_score": state["risk_score"],
                "reasons": json.loads(state["reasons"]),
                "redact_columns": json.loads(state["redact_columns"]),
                "result": json.loads(state["result"]),
                "status": state["status"],
            }
            state["prev_hash"] = previous_hash
            state["entry_hash"] = _hash_payload(payload, previous_hash)
            connection.execute(
                text("""
                UPDATE audit_log
                SET decision = :decision, risk_score = :risk_score,
                    reasons = :reasons, redact_columns = :redact_columns,
                    result = :result, status = :status,
                    prev_hash = :prev_hash, entry_hash = :entry_hash
                WHERE id = :id
                """),
                state,
            )
            previous_hash = state["entry_hash"]

        return _audit_response(connection.execute(
            text("SELECT * FROM audit_log WHERE id = :id"), {"id": audit_id}
        ).fetchone())


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/agents")
def agents():
    return {"agents": list(AGENT_ROLES)}


@app.post("/agent/query")
def agent_query(request: AgentQueryRequest, api_key: str = Depends(require_api_key)):
    key_agent_id = _agent_for_key(api_key)
    if key_agent_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if request.agent_id is None:
        request.agent_id = key_agent_id
    elif not verify_key(request.agent_id, api_key):
        raise HTTPException(status_code=401, detail="Invalid API key for claimed agent")
    if request.agent_id in QUARANTINED_AGENTS:
        raise HTTPException(
            status_code=403,
            detail=f"Agent {request.agent_id} is quarantined",
        )

    parsed_query = interpret(request.query)
    policy = evaluate(request.agent_id, parsed_query)
    resolved_target_row_id = _extract_id(request.query, request.target_row_id)

    if policy["decision"] == "DENY":
        result = {"status": "denied", "parsed_query": parsed_query}
        _audit_entry(request, policy, result)
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
                    result = {
                        "status": "pending_approval",
                        "approval_id": existing_id,
                        "duplicate": True,
                    }
                    return result

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
            result = {"status": "pending_approval", "approval_id": approval_id}
        audit_record = _audit_entry(request, policy, result)
        pending["audit_id"] = audit_record["id"]
        return result

    try:
        executed = _execute(parsed_query, request.query, resolved_target_row_id)
        executed = _redact(executed, policy["redact_columns"])
        result = {"status": "executed", "parsed_query": parsed_query, "result": executed}
    except Exception as exc:
        result = {"status": "execution_error", "error": str(exc), "parsed_query": parsed_query}
    _audit_entry(request, policy, result)
    return result


@app.get("/approvals")
def approvals():
    return {
        "approvals": [
            pending
            for pending in PENDING_APPROVALS.values()
            if pending["status"] in {"pending_approval", "auto_held_quarantine"}
        ]
    }


def _quarantine_agent(agent_id: str, reasoning: str):
    """Quarantine an agent and hold its unresolved approvals immediately."""
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


@app.post("/guardian/run")
def guardian_run():
    report = analyze_recent_activity()
    for verdict in report["verdicts"]:
        if verdict["verdict"] == "quarantine":
            _quarantine_agent(verdict["agent_id"], verdict["reasoning"])

    guardian_request = AgentQueryRequest(
        agent_id="guardian_agent",
        query="Autonomous Guardian analysis of recent audit activity",
    )
    guardian_policy = {
        "decision": "SYSTEM",
        "risk_score": 0,
        "reasons": ["Guardian Agent completed autonomous behavioral analysis"],
        "redact_columns": [],
    }
    _audit_entry(guardian_request, guardian_policy, {
        "status": "SYSTEM",
        "event_type": "guardian_analysis",
        "verdicts": report["verdicts"],
        "summary": report["summary"],
    })
    return report


@app.get("/guardian/status")
def guardian_status():
    agent_status = [
        {
            "agent_id": agent_id,
            "status": "quarantined" if agent_id in QUARANTINED_AGENTS else "clear",
            "reasoning": QUARANTINE_REASONS.get(agent_id, ""),
        }
        for agent_id in AGENT_ROLES
    ]
    return {
        "quarantined_agents": [
            {"agent_id": agent_id, "reasoning": QUARANTINE_REASONS.get(agent_id, "")}
            for agent_id in sorted(QUARANTINED_AGENTS)
        ],
        "agents": agent_status,
    }


@app.post("/guardian/lift/{agent_id}")
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
    return {
        "agent_id": agent_id,
        "status": "quarantine_lifted",
        "restored_pending_approvals": restored,
        "previous_reasoning": reasoning,
    }


@app.post("/approvals/{approval_id}")
def review_approval(approval_id: int, review: ApprovalRequest):
    pending = PENDING_APPROVALS.get(approval_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if pending["status"] != "pending_approval":
        if pending["status"] == "auto_held_quarantine":
            if review.approve and not review.confirm_quarantine_override:
                raise HTTPException(
                    status_code=409,
                    detail="Explicit quarantine override confirmation is required to approve this request",
                )
        else:
            raise HTTPException(status_code=409, detail="Approval request already reviewed")

    pending["reviewer"] = review.reviewer
    pending["reviewed_at"] = _timestamp()
    PENDING_CREATED_AT.pop(approval_id, None)
    original_request = AgentQueryRequest(
        agent_id=pending["agent_id"],
        query=pending["query"],
        target_row_id=pending["target_row_id"],
    )

    if not review.approve:
        pending["status"] = "rejected"
        rejected_policy = {
            **pending["policy"],
            "reasons": pending["policy"]["reasons"] + [
                f"Approval rejected by {review.reviewer}"
            ],
        }
        rejected_result = {"status": "rejected", "reviewer": review.reviewer}
        if pending.get("audit_id"):
            _update_audit_entry(pending["audit_id"], rejected_policy, rejected_result)
        else:
            _audit_entry(original_request, rejected_policy, rejected_result)
        return pending

    try:
        executed = _execute(pending["parsed_query"], pending["query"], pending["target_row_id"])
        executed = _redact(executed, pending["policy"]["redact_columns"])
        pending["status"] = "executed"
        pending["result"] = executed
        approved_policy = {**pending["policy"], "decision": "ALLOW"}
        approved_result = {"status": "approved", "reviewer": review.reviewer, "result": executed}
        if pending.get("audit_id"):
            _update_audit_entry(pending["audit_id"], approved_policy, approved_result)
        else:
            _audit_entry(original_request, approved_policy, approved_result)
    except Exception as exc:
        pending["status"] = "execution_error"
        pending["result"] = {"error": str(exc)}
        error_result = {"status": "execution_error", "reviewer": review.reviewer, "error": str(exc)}
        if pending.get("audit_id"):
            _update_audit_entry(pending["audit_id"], pending["policy"], error_result)
        else:
            _audit_entry(original_request, pending["policy"], error_result)
    return pending


@app.get("/audit-log")
def audit_log():
    with get_conn() as connection:
        rows = connection.execute(
            text("SELECT * FROM audit_log ORDER BY ts DESC, id DESC")
        ).fetchall()
    return {"audit_log": [_audit_response(row) for row in rows]}


@app.get("/audit-log/verify")
def verify_audit_log():
    with get_conn() as connection:
        rows = connection.execute(
            text("SELECT * FROM audit_log ORDER BY ts ASC, id ASC")
        ).fetchall()

    previous_hash = "GENESIS"
    broken_at = None
    for row in rows:
        row_data = row._mapping
        try:
            payload = _audit_payload(row)
            expected_hash = _hash_payload(payload, previous_hash)
            chain_matches = row_data["prev_hash"] == previous_hash
            entry_matches = row_data["entry_hash"] == expected_hash
        except (TypeError, ValueError, json.JSONDecodeError):
            chain_matches = False
            entry_matches = False

        if broken_at is None and (not chain_matches or not entry_matches):
            broken_at = row._mapping["id"]
        previous_hash = row_data["entry_hash"]

    return {
        "valid": broken_at is None,
        "checked_entries": len(rows),
        "broken_at": broken_at,
    }


@app.get("/compliance/report")
def compliance_report(hours: int = 24):
    try:
        report = generate_report(hours)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {**report, "generated_at": _timestamp()}


@app.get("/compliance/report/pdf")
def compliance_report_pdf(hours: int = 24):
    try:
        report = generate_report(hours)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    pdf = generate_pdf(report, report["stats"])
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=agentgate-compliance-report.pdf"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=DEFAULT_HOST, port=DEFAULT_PORT)
