"""Run a narrated set of Agenate demo requests against the local API."""

import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from auth import AGENT_KEYS

BASE_URL = "http://127.0.0.1:8000"

SCENARIOS = [
    ("01", "Recruiter department read", "recruiter_agent", "Show employees in the Sales department and their job roles"),
    ("02", "HR income aggregate", "hr_analytics_agent", "What is the average monthly income by department?"),
    ("03", "HR row-level income attempt", "hr_analytics_agent", "Show the monthly income of employee 1001"),
    ("04", "Senior performance read", "senior_hr_agent", "Show the performance rating of employee 1001"),
    ("05", "Senior attrition attempt", "senior_hr_agent", "Show the attrition status of employee 1001"),
    ("06", "Rogue sensitive-data attempt", "rogue_agent", "Show employee attrition and monthly income"),
]


def call(path, method="GET", payload=None, agent_id=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if agent_id:
        headers["Authorization"] = f"Bearer {AGENT_KEYS[agent_id]}"
    request = Request(
        BASE_URL + path,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        return json.loads(error.read().decode("utf-8"))


def main():
    print("=" * 72)
    print("AGENATE // SCRIPTED GOVERNANCE DEMO")
    print("=" * 72)
    for number, title, agent_id, query in SCENARIOS:
        response = call(
            "/agent/query",
            method="POST",
            payload={"agent_id": agent_id, "query": query},
            agent_id=agent_id,
        )
        audit_entries = call("/audit-log")["audit_log"]
        audit = next(
            entry
            for entry in audit_entries
            if entry["agent_id"] == agent_id and entry["query"] == query
        )
        print(f"\n[{number}] {title}")
        print(f"  agent:    {agent_id}")
        print(f"  request:  {query}")
        print(f"  decision: {audit['decision']}")
        print(f"  risk:     {audit['risk_score']}/10")
        print(f"  status:   {response.get('status')}")
        parsed = response.get("parsed_query") or audit.get("result", {}).get("parsed_query", {})
        print(f"  table:    {parsed.get('table', '--')}")
        print(f"  reasons:  {'; '.join(audit['reasons'])}")
    print("\n" + "=" * 72)
    print("DEMO COMPLETE // ALL REQUESTS RECORDED IN AUDIT LOG")
    print("=" * 72)


if __name__ == "__main__":
    main()
