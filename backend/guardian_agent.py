"""Autonomous behavioral monitoring for AgentGate."""

import json
import os
import re
import time
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
ADAPTIVE_RISK_RESTRICT_THRESHOLD = int(os.getenv("ADAPTIVE_RISK_RESTRICT_THRESHOLD", "8"))
ADAPTIVE_RISK_WINDOW_SECONDS = int(os.getenv("ADAPTIVE_RISK_WINDOW_SECONDS", "60"))

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


def _risk_level(score: int, quarantined: bool = False) -> str:
    if quarantined:
        return "QUARANTINED"
    if score >= ADAPTIVE_RISK_RESTRICT_THRESHOLD:
        return "RESTRICTED"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "ELEVATED"
    return "NORMAL"


def _risk_factor(entry: dict[str, Any]) -> tuple[int, list[str], bool]:
    """Return adaptive points, factor labels, and whether sensitive data was targeted."""
    decision = entry.get("decision")
    policy_risk = entry.get("risk_score") or 0
    redact_columns = _json_value(entry.get("redact_columns"), [])
    result = _json_value(entry.get("result"), {})
    parsed = result.get("parsed_query", {}) if isinstance(result, dict) else {}
    requested = set(parsed.get("columns", []))
    targeted = sorted((requested | set(redact_columns)) & sensitive_columns())
    sensitive = bool(targeted)
    points = 0
    factors = []
    if decision == "DENY":
        points += 1
        factors.append("denied request")
    if sensitive:
        points += 2
        factors.append("sensitive-data attempt: " + ", ".join(targeted))
    if policy_risk >= 6 or parsed.get("operation") in {"DELETE", "UPDATE"} or sensitive:
        points += 1
        factors.append("high-risk operation")
    return points, factors, sensitive


def agent_risk_snapshot(agent_id: str, limit: int = RECENT_ACTIVITY_LIMIT) -> dict[str, Any]:
    """Build an agent's runtime risk state from real audit entries."""
    with get_conn() as connection:
        rows = connection.execute(
            text("""
                SELECT ts, agent_id, nl_query, decision, risk_score,
                       redact_columns, reasons, result, status
                FROM audit_log
                WHERE agent_id = :agent_id
                ORDER BY ts ASC, id ASC
            """),
            {"agent_id": agent_id},
        ).fetchall()

    # Keep the score responsive to current behavior. Older audit evidence remains
    # immutable and visible, but it should not permanently poison privileges.
    cutoff = time.time() - ADAPTIVE_RISK_WINDOW_SECONDS
    entries = [dict(row._mapping) for row in rows if (row._mapping["ts"] or 0) >= cutoff][-limit:]
    denied_requests = sum(1 for entry in entries if entry["decision"] == "DENY")
    sensitive_attempts = 0
    high_risk_requests = 0
    score = 1 if entries else 0
    factors: list[str] = []
    violations: list[dict[str, Any]] = []
    for entry in entries:
        points, entry_factors, sensitive = _risk_factor(entry)
        score += points
        sensitive_attempts += int(sensitive)
        high_risk_requests += int((entry.get("risk_score") or 0) >= 6)
        if entry_factors:
            factors.extend(entry_factors)
            violations.append({
                "timestamp": entry["ts"],
                "query": entry["nl_query"],
                "decision": entry["decision"],
                "reasons": _json_value(entry.get("reasons"), []),
                "factors": entry_factors,
            })

    # Repeated denials are an escalation signal, independent of YAML policy.
    if denied_requests >= 3:
        score += 2
        factors.append("repeated denied requests")
    score = min(10, score)
    recent_factors = list(dict.fromkeys(factors))[-6:]
    status = _risk_level(score, agent_id in QUARANTINED_AGENTS)
    reason = recent_factors[-1] if recent_factors else "No behavioral risk indicators observed"
    if status == "RESTRICTED":
        reason = "; ".join(recent_factors[-3:]) or "Adaptive risk threshold exceeded"
    return {
        "agent_id": agent_id,
        "risk_score": score,
        "risk_level": status,
        "status": status,
        "denied_requests": denied_requests,
        "sensitive_attempts": sensitive_attempts,
        "high_risk_requests": high_risk_requests,
        "recent_violations": list(reversed(violations[-5:])),
        "risk_factors": recent_factors,
        "reason": reason,
        "privilege_state": "QUARANTINED" if agent_id in QUARANTINED_AGENTS else "RESTRICTED" if status == "RESTRICTED" else "POLICY PRIVILEGES",
        "restrict_threshold": ADAPTIVE_RISK_RESTRICT_THRESHOLD,
        "window_size": len(entries),
        "window_seconds": ADAPTIVE_RISK_WINDOW_SECONDS,
    }


def all_agent_risk_snapshots() -> list[dict[str, Any]]:
    from policy_engine import AGENT_ROLES
    return [agent_risk_snapshot(agent_id) for agent_id in AGENT_ROLES]


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
