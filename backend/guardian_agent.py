"""Autonomous behavioral monitoring for AgentGate."""

import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from dotenv import load_dotenv

from sqlalchemy import text

from db import get_conn
from policy_engine import sensitive_columns


GUARDIAN_AGENT_ID = "guardian_agent"
QUARANTINED_AGENTS: set[str] = set()
QUARANTINE_REASONS: dict[str, str] = {}
RECENT_ACTIVITY_LIMIT = 20
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

_GROQ_MODEL = "llama-3.3-70b-versatile"
_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def _recent_entries(limit: int) -> list[dict[str, Any]]:
    with get_conn() as connection:
        rows = connection.execute(
            text("""
                SELECT ts, agent_id, nl_query, decision, risk_score,
                       redact_columns, result
                FROM audit_log
                WHERE agent_id != :guardian_agent
                ORDER BY ts DESC, id DESC
                LIMIT :limit
            """),
            {"guardian_agent": GUARDIAN_AGENT_ID, "limit": limit},
        ).fetchall()

    return [dict(row._mapping) for row in reversed(rows)]


def _json_value(value, default):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _activity_summary(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        grouped[entry["agent_id"]].append(entry)

    summary = []
    for agent_id, agent_entries in grouped.items():
        denied = sum(1 for entry in agent_entries if entry["decision"] == "DENY")
        high_risk = sum(1 for entry in agent_entries if (entry["risk_score"] or 0) >= 6)
        gaps = [
            round(agent_entries[index]["ts"] - agent_entries[index - 1]["ts"], 3)
            for index in range(1, len(agent_entries))
        ]
        rapid_fire = sum(1 for gap in gaps if gap <= 1)
        sensitive_targets: dict[str, int] = defaultdict(int)
        for entry in agent_entries:
            redact_columns = _json_value(entry["redact_columns"], [])
            result = _json_value(entry["result"], {})
            parsed = result.get("parsed_query", {}) if isinstance(result, dict) else {}
            requested = set(parsed.get("columns", []))
            for column in (requested | set(redact_columns)) & sensitive_columns():
                sensitive_targets[column] += 1

        summary.append({
            "agent_id": agent_id,
            "requests_analyzed": len(agent_entries),
            "denied_requests": denied,
            "high_risk_requests": high_risk,
            "time_gaps_seconds": gaps,
            "rapid_fire_requests": rapid_fire,
            "sensitive_columns_targeted": dict(sensitive_targets),
        })
    return summary


def _call_groq(summary: list[dict[str, Any]], api_key: str) -> list[dict[str, str]]:
    prompt = f"""You are the AgentGate Guardian Agent. Review this recent agent activity summary.
Identify repeated denied sensitive-data attempts, rapid-fire/scripted behavior,
and escalating risk. Return ONLY a JSON array with one object per agent:
{{"agent_id":"...","verdict":"normal|flag|quarantine","reasoning":"..."}}

Activity summary:
{json.dumps(summary, sort_keys=True)}
"""
    body = json.dumps({
        "model": _GROQ_MODEL,
        "temperature": 0,
        "max_tokens": 900,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    request = Request(
        _GROQ_URL,
        data=body,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"].strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content).strip()
    verdicts = json.loads(content)
    if not isinstance(verdicts, list):
        raise ValueError("Guardian LLM response was not a JSON array")
    for verdict in verdicts:
        if (
            not isinstance(verdict, dict)
            or set(verdict) != {"agent_id", "verdict", "reasoning"}
            or verdict["verdict"] not in {"normal", "flag", "quarantine"}
        ):
            raise ValueError("Guardian LLM response had an invalid verdict")
    return verdicts


def _rule_based_verdicts(summary: list[dict[str, Any]]) -> list[dict[str, str]]:
    verdicts = []
    for agent in summary:
        denied = agent["denied_requests"]
        high_risk = agent["high_risk_requests"]
        rapid_fire = agent["rapid_fire_requests"]
        targeted = ", ".join(agent["sensitive_columns_targeted"]) or "none"
        if denied >= 3:
            verdict = "quarantine"
            reasoning = (
                f"{denied} denied requests in the recent window, repeatedly targeting "
                f"sensitive columns ({targeted})."
            )
        elif denied >= 2 or high_risk >= 1:
            verdict = "flag"
            reasoning = (
                f"Observed {denied} denied and {high_risk} high-risk requests; "
                f"sensitive targets: {targeted}."
            )
        else:
            verdict = "normal"
            reasoning = f"Activity is within normal bounds ({rapid_fire} rapid-fire requests)."
        verdicts.append({"agent_id": agent["agent_id"], "verdict": verdict, "reasoning": reasoning})
    return verdicts


def analyze_recent_activity(limit: int = RECENT_ACTIVITY_LIMIT) -> dict[str, Any]:
    """Analyze recent audit behavior using Groq or zero-config rules."""
    entries = _recent_entries(limit)
    summary = _activity_summary(entries)
    api_key = os.getenv("GROQ_API_KEY")
    if api_key:
        try:
            verdicts = _call_groq(summary, api_key)
        except Exception:
            verdicts = _rule_based_verdicts(summary)
    else:
        verdicts = _rule_based_verdicts(summary)
    return {"verdicts": verdicts, "summary": summary, "entries_analyzed": len(entries)}
