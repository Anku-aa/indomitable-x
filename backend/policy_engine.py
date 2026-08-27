"""Config-driven authorization and risk evaluation for AgentGate."""

import os
from pathlib import Path

import yaml


POLICIES_FILE = Path(os.getenv("POLICIES_FILE", Path(__file__).with_name("policies.yaml")))


def load_policies_from_config() -> dict:
    """Load and normalize agent/table policies from YAML."""
    if not POLICIES_FILE.exists():
        raise FileNotFoundError(f"Policy configuration not found: {POLICIES_FILE}")
    raw = yaml.safe_load(POLICIES_FILE.read_text()) or {}
    normalized = {}
    for agent_id, definition in (raw.get("agents") or {}).items():
        tables = {}
        for table_name, table_policy in (definition.get("tables") or {}).items():
            table_policy = table_policy or {}
            tables[table_name] = {
                "allowed_columns": set(table_policy.get("allowed_columns") or []),
                "sensitive_columns": set(table_policy.get("sensitive_columns") or []),
                "allowed_operations": {op.upper() for op in (table_policy.get("allowed_ops") or [])},
                "update_columns": set(table_policy.get("update_columns") or []),
                "aggregate_only_columns": set(table_policy.get("aggregate_only_columns") or []),
                "row_level_denied_columns": set(table_policy.get("row_level_denied_columns") or []),
            }
        normalized[agent_id] = {
            "label": definition.get("label", agent_id),
            "tables": tables,
            "allowed_tables": set(tables),
            "allowed_operations": set().union(*(p["allowed_operations"] for p in tables.values())) if tables else set(),
            "allowed_columns": set().union(*(p["allowed_columns"] for p in tables.values())) if tables else set(),
            "update_columns": set().union(*(p["update_columns"] for p in tables.values())) if tables else set(),
            "aggregate_only_columns": set().union(*(p["aggregate_only_columns"] for p in tables.values())) if tables else set(),
        }
    return normalized


AGENT_ROLES = load_policies_from_config()


def governed_tables() -> list[str]:
    return sorted({table for role in AGENT_ROLES.values() for table in role["tables"]})


def table_policy(agent_id: str, table: str) -> dict | None:
    role = AGENT_ROLES.get(agent_id)
    return role["tables"].get(table) if role else None


def sensitive_columns() -> set[str]:
    return set().union(*(p["sensitive_columns"] for role in AGENT_ROLES.values() for p in role["tables"].values())) if AGENT_ROLES else set()


def _result(decision, risk_score, reasons, redact_columns):
    return {"decision": decision, "risk_score": risk_score, "reasons": reasons, "redact_columns": redact_columns}


def evaluate(agent_id, parsed_query):
    role = AGENT_ROLES.get(agent_id)
    if role is None or agent_id == "rogue_agent":
        return _result("DENY", 10, ["Unknown or untrusted agent"], [])

    operation = parsed_query.get("operation", "").upper()
    table = parsed_query.get("table")
    columns = parsed_query.get("columns", [])
    is_aggregate = parsed_query.get("is_aggregate", False)
    policy = role["tables"].get(table)
    if policy is None:
        return _result("DENY", 10, [f"Table '{table}' is not allowed for {agent_id}"], [])

    if operation == "DELETE":
        return _result("REQUIRE_APPROVAL", 8, ["DELETE is a destructive operation and requires human approval"], [])
    if operation not in policy["allowed_operations"]:
        return _result("DENY", 10, [f"Operation '{operation}' is not allowed for {agent_id}"], [])

    row_level_denied = set(columns) & policy["row_level_denied_columns"]
    if operation == "SELECT" and not is_aggregate and row_level_denied:
        return _result(
            "DENY",
            10,
            ["Row-level access is permanently denied for sensitive column(s): " + ", ".join(sorted(row_level_denied))],
            [],
        )

    aggregate_only_row_access = set(columns) & policy["aggregate_only_columns"]
    if operation == "SELECT" and not is_aggregate and aggregate_only_row_access:
        return _result(
            "DENY",
            10,
            ["Row-level access is denied; column(s) are available only through aggregate queries: " + ", ".join(sorted(aggregate_only_row_access))],
            [],
        )

    reasons = []
    redact_columns = []
    risk_score = 0
    for column in columns:
        if column not in policy["allowed_columns"]:
            redact_columns.append(column)
            risk_score += 1
            reasons.append(f"Column '{column}' is outside the agent allowlist")
        if column in policy["sensitive_columns"] and column not in policy["allowed_columns"]:
            reasons.append(f"Sensitive column '{column}' will be redacted for {agent_id}")
    if operation == "UPDATE":
        unauthorized_updates = set(columns) - policy["update_columns"]
        if unauthorized_updates:
            reasons.append("UPDATE includes columns outside update permissions: " + ", ".join(sorted(unauthorized_updates)))
            return _result("DENY", 10, reasons, redact_columns)
        risk_score = 3
        reasons.append("UPDATE on an allowed column requires approval")

    if operation != "UPDATE":
        risk_score = min(risk_score, 2)
    decision = "DENY" if risk_score >= 6 else "REQUIRE_APPROVAL" if risk_score >= 3 else "ALLOW"
    if not reasons:
        reasons.append("Query matches the agent policy")
    return _result(decision, risk_score, reasons, redact_columns)
