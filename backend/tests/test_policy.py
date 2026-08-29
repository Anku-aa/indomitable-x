"""Smoke-test representative Agenate policy decisions."""

from pprint import pprint

from db import init_db
from policy_engine import evaluate


SCENARIOS = [
    (
        "Safe HR read",
        "recruiter_agent",
        {"operation": "SELECT", "table": "hr_records", "columns": ["Department", "Job_Role"], "is_aggregate": False},
    ),
    (
        "Analytics aggregate salary",
        "hr_analytics_agent",
        {"operation": "SELECT", "table": "hr_records", "columns": ["Department", "Monthly_Income"], "is_aggregate": True},
    ),
    (
        "Analytics row-level salary",
        "hr_analytics_agent",
        {"operation": "SELECT", "table": "hr_records", "columns": ["Employee_ID", "Monthly_Income"], "is_aggregate": False},
    ),
    (
        "Senior HR updates income",
        "senior_hr_agent",
        {"operation": "UPDATE", "table": "hr_records", "columns": ["Monthly_Income"], "is_aggregate": False},
    ),
    (
        "Rogue reads employee data",
        "rogue_agent",
        {"operation": "SELECT", "table": "hr_records", "columns": ["Monthly_Income"], "is_aggregate": False},
    ),
    (
        "Agent tries to delete a row",
        "recruiter_agent",
        {"operation": "DELETE", "table": "hr_records", "columns": ["Employee_ID"], "is_aggregate": False},
    ),
]


if __name__ == "__main__":
    init_db()
    for name, agent_id, query in SCENARIOS:
        result = evaluate(agent_id, query)
        print(f"{name}: {result['decision']} (risk={result['risk_score']})")
        print(f"  reasons: {result['reasons']}")
        print(f"  redact_columns: {result['redact_columns']}")
