"""Query execution, redaction, and governance trace helpers."""

import re
from typing import Any, Optional

from sqlalchemy import text

from db import get_engine, get_table_schema
from llm import extract_target_row_id
from services.audit_service import _json_safe


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
            cursor = connection.execute(text(f"DELETE FROM {table} WHERE {row_key} = :row_id"), {"row_id": row_id})
            if cursor.rowcount == 0:
                return {"status": f"no employee row found for id {row_id}", "row_count": 0}
            return {"status": f"deleted row id {row_id}", "row_count": cursor.rowcount}

    if ":id" in sql:
        if row_id is None:
            raise ValueError("An employee id is required for this query")
        params["id"] = row_id

    if (
        operation in {"SELECT", "UPDATE"} and row_id is not None and ":id" not in sql
        and row_key and " where " not in sql.lower()
    ):
        sql += f" WHERE {row_key} = :id"
        params["id"] = row_id

    if (
        operation == "SELECT" and "department" in {column.lower() for column in parsed_query["columns"]}
        and " where " not in sql.lower()
    ):
        department_match = re.search(
            r"\b(?:in|from)\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 &-]*?)(?:\s+department)?"
            r"(?:\s+(?:and|their|with|where)|[?.!,]|$)", query, re.IGNORECASE,
        )
        if department_match:
            sql += " WHERE Department = :department_filter"
            params["department_filter"] = department_match.group(1).strip()

    for column in parsed_query["columns"]:
        if operation != "UPDATE" or f":{column}" not in sql:
            continue
        if column == "salary":
            match = re.search(r"\bsalary\s*(?:to|=)\s*\$?(\d+)\b", query, re.IGNORECASE)
            params[column] = int(match.group(1)) if match else None
        elif column in {"Monthly_Income", "Performance_Rating", "Job_Satisfaction", "Age", "Years_At_Company"}:
            column_phrase = re.escape(column).replace("_", r"(?:[_\s]+)")
            match = re.search(rf"\b{column_phrase}\s*(?:to|=|as)\s+\$?['\"]?(\d+(?:\.\d+)?)", query, re.IGNORECASE)
            match = match or re.search(r"\bto\s+\$?['\"]?(\d+(?:\.\d+)?)", query, re.IGNORECASE)
            params[column] = float(match.group(1)) if match and "." in match.group(1) else int(match.group(1)) if match else None
        else:
            column_phrase = re.escape(column).replace("_", r"(?:[_\s]+)")
            match = re.search(rf"\b{column_phrase}\s*(?:to|=|as)\s+['\"]?([^,.;]+)", query, re.IGNORECASE)
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


def _trace(parsed_query: dict, policy: dict, database_status: str | None = None, audit_status: str = "success"):
    """Describe the real request lifecycle for the observability UI."""
    steps = [
        {"step": "query_received", "label": "Query Received", "status": "success"},
        {"step": "authentication", "label": "Authentication", "status": "success", "agent_id": None},
        {"step": "llm_interpreter", "label": "LLM Interpreter", "status": "success", "parsed_query": parsed_query},
        {
            "step": "policy_engine", "label": "Policy / Risk",
            "status": "denied" if policy["decision"] == "DENY" else "success",
            "decision": policy["decision"], "risk_score": policy["risk_score"],
            "adaptive_risk_score": policy.get("adaptive_risk_score", 0),
            "adaptive_risk_level": policy.get("adaptive_risk_level", "NORMAL"),
            "reasons": policy["reasons"],
        },
        {"step": "decision", "label": "Decision", "status": policy["decision"].lower(), "decision": policy["decision"]},
    ]
    if database_status:
        steps.append({"step": "database", "label": "Database", "status": database_status})
    steps.append({"step": "audit_log", "label": "Audit Log", "status": audit_status})
    return steps


def _approval_trace(pending: dict, decision: str, database_status: str):
    trace = _trace(pending["parsed_query"], pending["policy"], database_status)
    trace[3]["status"] = "success"
    trace[4]["status"] = decision.lower()
    trace[4]["decision"] = decision
    return trace
