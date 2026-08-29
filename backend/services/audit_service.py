"""Audit serialization and tamper-evident hash-chain operations."""

from datetime import datetime, timezone
import hashlib
import json
import time
from decimal import Decimal
import uuid

from sqlalchemy import text

from db import get_conn, get_engine
from models import AgentQueryRequest
from core.state import AUDIT_LOCK


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _hash_payload(payload, prev_hash):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
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
        "id": row["id"], "ts": row["ts"], "agent_id": row["agent_id"], "nl_query": row["nl_query"],
        "decision": row["decision"], "risk_score": row["risk_score"], "reasons": json.loads(row["reasons"]),
        "redact_columns": json.loads(row["redact_columns"]), "result": json.loads(row["result"]), "status": row["status"],
    }


def _audit_response(row):
    row = row._mapping
    return {
        "id": row["id"],
        "timestamp": datetime.fromtimestamp(row["ts"], timezone.utc).isoformat(),
        "agent_id": row["agent_id"], "query": row["nl_query"], "decision": row["decision"],
        "risk_score": row["risk_score"], "reasons": json.loads(row["reasons"]),
        "redact_columns": json.loads(row["redact_columns"]), "result": json.loads(row["result"]),
        "status": row["status"], "prev_hash": row["prev_hash"], "entry_hash": row["entry_hash"],
    }


def _audit_entry(request: AgentQueryRequest, policy: dict, result: dict):
    status = result.get("status", policy["decision"].lower())
    with AUDIT_LOCK, get_engine().begin() as connection:
        previous = connection.execute(text("SELECT entry_hash FROM audit_log ORDER BY ts DESC, id DESC LIMIT 1")).fetchone()
        prev_hash = previous._mapping["entry_hash"] if previous else "GENESIS"
        payload = {
            "id": uuid.uuid4().hex, "ts": time.time(), "agent_id": request.agent_id, "nl_query": request.query,
            "decision": policy["decision"], "risk_score": policy["risk_score"], "reasons": policy["reasons"],
            "redact_columns": policy["redact_columns"], "result": result, "status": status,
        }
        entry_hash = _hash_payload(payload, prev_hash)
        connection.execute(text("""
            INSERT INTO audit_log
                (id, ts, agent_id, nl_query, decision, risk_score, reasons,
                 redact_columns, result, status, prev_hash, entry_hash)
            VALUES (:id, :ts, :agent_id, :nl_query, :decision, :risk_score,
                    :reasons, :redact_columns, :result, :status, :prev_hash,
                    :entry_hash)
            """), {
                "id": payload["id"], "ts": payload["ts"], "agent_id": payload["agent_id"],
                "nl_query": payload["nl_query"], "decision": payload["decision"],
                "risk_score": payload["risk_score"], "reasons": json.dumps(payload["reasons"], sort_keys=True),
                "redact_columns": json.dumps(payload["redact_columns"], sort_keys=True),
                "result": json.dumps(payload["result"], sort_keys=True), "status": payload["status"],
                "prev_hash": prev_hash, "entry_hash": entry_hash,
            })
        return {**payload, "prev_hash": prev_hash, "entry_hash": entry_hash}


def _update_audit_entry(audit_id: str, policy: dict, result: dict):
    """Update one lifecycle record and re-chain hashes for later entries."""
    with AUDIT_LOCK, get_engine().begin() as connection:
        rows = connection.execute(text("SELECT * FROM audit_log ORDER BY ts ASC, id ASC")).fetchall()
        target_index = next((index for index, row in enumerate(rows) if row._mapping["id"] == audit_id), None)
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
                "id": state["id"], "ts": state["ts"], "agent_id": state["agent_id"], "nl_query": state["nl_query"],
                "decision": state["decision"], "risk_score": state["risk_score"], "reasons": json.loads(state["reasons"]),
                "redact_columns": json.loads(state["redact_columns"]), "result": json.loads(state["result"]),
                "status": state["status"],
            }
            state["prev_hash"] = previous_hash
            state["entry_hash"] = _hash_payload(payload, previous_hash)
            connection.execute(text("""
                UPDATE audit_log
                SET decision = :decision, risk_score = :risk_score,
                    reasons = :reasons, redact_columns = :redact_columns,
                    result = :result, status = :status,
                    prev_hash = :prev_hash, entry_hash = :entry_hash
                WHERE id = :id
                """), state)
            previous_hash = state["entry_hash"]

        return _audit_response(connection.execute(text("SELECT * FROM audit_log WHERE id = :id"), {"id": audit_id}).fetchone())
