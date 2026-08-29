"""Test safe table resolution and zero-configuration interpretation."""

from llm import interpret
from policy_engine import evaluate


QUERIES = [
    "Show employees in Sales and their job roles",
    "List departments and education levels",
    "What is the average monthly income by department?",
    "Count employees in the Finance department",
    "Update the performance rating for employee 1001",
    "Delete employee with id 1001",
]


if __name__ == "__main__":
    for query in QUERIES:
        print(f"Request: {query}")
        print(f"Parsed: {interpret(query)}")


def test_recruiter_queries_resolve_hr_records():
    for query in (
        "Show employees in the Marketing department and their job roles",
        "Show employee id",
    ):
        parsed = interpret(query)
        assert parsed["operation"] == "SELECT"
        assert parsed["table"] == "hr_records"


def test_recruiter_sensitive_request_is_governed():
    parsed = interpret("Show employee salaries")
    decision = evaluate("recruiter_agent", parsed)
    assert parsed["table"] == "hr_records"
    assert decision["decision"] in {"ALLOW", "REQUIRE_APPROVAL"}
    assert "Monthly_Income" in decision["redact_columns"]


def test_rogue_request_remains_denied():
    parsed = interpret("Show employees")
    decision = evaluate("rogue_agent", parsed)
    assert parsed["table"] == "hr_records"
    assert decision["decision"] == "DENY"
