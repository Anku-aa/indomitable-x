"""Audit trail endpoints."""

import json

from fastapi import APIRouter
from sqlalchemy import text

from db import get_conn
from services.audit_service import _audit_payload, _audit_response, _hash_payload


router = APIRouter()


@router.get("/audit-log")
def audit_log():
    with get_conn() as connection:
        rows = connection.execute(text("SELECT * FROM audit_log ORDER BY ts DESC, id DESC")).fetchall()
    return {"audit_log": [_audit_response(row) for row in rows]}


@router.get("/audit-log/verify")
def verify_audit_log():
    with get_conn() as connection:
        rows = connection.execute(text("SELECT * FROM audit_log ORDER BY ts ASC, id ASC")).fetchall()

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

    return {"valid": broken_at is None, "checked_entries": len(rows), "broken_at": broken_at}
