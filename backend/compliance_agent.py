"""Human-readable compliance reporting from the AgentGate audit trail."""

from collections import Counter
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from dotenv import load_dotenv

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from sqlalchemy import text

from db import get_conn


load_dotenv(Path(__file__).resolve().parents[1] / ".env")

_GROQ_MODEL = "llama-3.3-70b-versatile"
_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MAX_AUDIT_TRAIL_EVENTS = 100


def _load_entries(period_hours: int) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc).timestamp() - (period_hours * 3600)
    with get_conn() as connection:
        rows = connection.execute(
            text("SELECT * FROM audit_log WHERE ts >= :cutoff ORDER BY ts ASC, id ASC"),
            {"cutoff": cutoff},
        ).fetchall()
    return [dict(row._mapping) for row in rows]


def _json_value(value, default):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _category(entry: dict[str, Any]) -> str:
    status = entry["status"] or ""
    result = _json_value(entry["result"], {})
    if status.upper() == "SYSTEM" or entry["decision"] == "SYSTEM":
        return "system"
    if status == "pending_approval":
        return "pending"
    if status == "rejected":
        return "rejected"
    if status == "guardian_analysis":
        return "system"
    if status == "executed" and isinstance(result, dict) and result.get("reviewer"):
        return "approved"
    if status == "executed":
        return "executed"
    if status == "denied" or entry["decision"] == "DENY":
        return "denied"
    return "other"


def _quarantine_actions(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions = []
    for entry in entries:
        if entry["agent_id"] != "guardian_agent":
            continue
        result = _json_value(entry["result"], {})
        for verdict in result.get("verdicts", []) if isinstance(result, dict) else []:
            if verdict.get("verdict") == "quarantine":
                actions.append({
                    "timestamp": entry["ts"],
                    "agent_id": verdict.get("agent_id"),
                    "reasoning": verdict.get("reasoning", ""),
                })
    return actions


def _build_stats(entries: list[dict[str, Any]], period_hours: int) -> dict[str, Any]:
    breakdown = {key: 0 for key in ("executed", "denied", "pending", "approved", "rejected", "system", "other")}
    by_agent: Counter[str] = Counter()
    for entry in entries:
        by_agent[entry["agent_id"]] += 1
        category = _category(entry)
        if category in breakdown:
            breakdown[category] += 1

    highest_risk = sorted(
        entries,
        key=lambda entry: (entry["risk_score"] or 0, entry["ts"]),
        reverse=True,
    )[:5]
    risk_events = [
        {
            "timestamp": entry["ts"],
            "agent_id": entry["agent_id"],
            "query": entry["nl_query"],
            "decision": entry["decision"],
            "risk_score": entry["risk_score"],
            "status": entry["status"],
        }
        for entry in highest_risk
    ]
    return {
        "period_hours": period_hours,
        "total_requests": len(entries),
        "decision_breakdown": breakdown,
        "by_agent": dict(by_agent),
        "highest_risk_events": risk_events,
        "guardian_quarantine_actions": _quarantine_actions(entries),
    }


def _row_count(entry: dict[str, Any]) -> int:
    """Read row_count without retaining or exposing the returned row data."""
    value = _json_value(entry.get("result"), {})
    while isinstance(value, dict):
        if isinstance(value.get("row_count"), (int, float)):
            return int(value["row_count"])
        value = value.get("result")
    return 0


def _audit_trail(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = entries[-MAX_AUDIT_TRAIL_EVENTS:]
    trail = []
    for entry in selected:
        query = str(entry.get("nl_query") or "")
        trail.append({
            "timestamp": datetime.fromtimestamp(entry["ts"], timezone.utc).isoformat(),
            "agent_id": entry["agent_id"],
            "query": query[:60] + ("..." if len(query) > 60 else ""),
            "decision": _category(entry),
            "risk_score": int(entry.get("risk_score") or 0),
            "row_count": _row_count(entry),
        })
    return trail


def _call_groq(stats: dict[str, Any], api_key: str) -> str:
    prompt = f"""You are writing a compliance report for a non-technical compliance officer.
Use the AgentGate audit statistics below. Write a clear, professional summary
in plain English in 3 to 5 short paragraphs. Explain what happened, what
stands out, and what needs human attention. Do not mention prompts, JSON, or
implementation details. Do not invent facts beyond the statistics.

Audit statistics:
{json.dumps(stats, indent=2, sort_keys=True)}
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
    summary = payload["choices"][0]["message"]["content"].strip()
    if not summary:
        raise ValueError("Compliance LLM returned an empty summary")
    return summary


def _template_summary(stats: dict[str, Any]) -> str:
    breakdown = stats["decision_breakdown"]
    by_agent = ", ".join(
        f"{agent}: {count} request{'s' if count != 1 else ''}"
        for agent, count in stats["by_agent"].items()
    ) or "No agent activity was recorded."
    high_risk = stats["highest_risk_events"]
    highest = max((event["risk_score"] or 0 for event in high_risk), default=0)
    quarantine_count = len(stats["guardian_quarantine_actions"])
    attention = []
    if breakdown["denied"]:
        attention.append(f"{breakdown['denied']} request(s) were denied")
    if breakdown["pending"]:
        attention.append(f"{breakdown['pending']} request(s) remain pending human approval")
    if breakdown["rejected"]:
        attention.append(f"{breakdown['rejected']} approval(s) were rejected")
    if quarantine_count:
        attention.append(f"the Guardian recorded {quarantine_count} quarantine action(s)")
    attention_text = "; ".join(attention) if attention else "No immediate exceptions were recorded."
    return (
        f"During the last {stats['period_hours']} hours, AgentGate recorded "
        f"{stats['total_requests']} audit event(s). The activity breakdown was "
        f"{breakdown['executed']} executed, {breakdown['denied']} denied, "
        f"{breakdown['pending']} pending approval, {breakdown['approved']} approved, "
        f"{breakdown['rejected']} rejected, and {breakdown['other']} other system event(s).\n\n"
        f"Activity by agent was: {by_agent}. The highest recorded risk score was "
        f"{highest} out of 10.\n\n"
        f"The main items requiring human attention are: {attention_text}. "
        f"Review the highest-risk events and any pending approvals before closing "
        f"the reporting period."
    )


def generate_report(period_hours: int = 24) -> dict[str, Any]:
    """Generate compliance stats and a narrative summary."""
    if period_hours < 1:
        raise ValueError("period_hours must be at least 1")
    entries = _load_entries(period_hours)
    stats = _build_stats(entries, period_hours)
    audit_trail = _audit_trail(entries)
    api_key = os.getenv("GROQ_API_KEY")
    if api_key:
        try:
            summary = _call_groq(stats, api_key)
        except Exception:
            summary = _template_summary(stats)
    else:
        summary = _template_summary(stats)
    return {
        "summary": summary,
        "stats": stats,
        "audit_trail": audit_trail,
        "audit_trail_total": len(entries),
        "audit_trail_note": (
            f"Showing most recent {MAX_AUDIT_TRAIL_EVENTS} of {len(entries)} total events."
            if len(entries) > MAX_AUDIT_TRAIL_EVENTS
            else f"Showing all {len(entries)} events."
        ),
    }


def generate_pdf(report: dict[str, Any], stats: dict[str, Any]) -> bytes:
    """Render a clean one-page compliance report PDF."""
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
        title="AgentGate Compliance Report",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, textColor=colors.HexColor("#163b39"), spaceAfter=4)
    meta_style = ParagraphStyle("ReportMeta", parent=styles["Normal"], fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#637372"), spaceAfter=14)
    body_style = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=colors.HexColor("#263634"), spaceAfter=8)
    small_style = ParagraphStyle("ReportSmall", parent=styles["Normal"], fontName="Helvetica", fontSize=8, leading=10, textColor=colors.HexColor("#263634"))

    story = [
        Paragraph("AgentGate Compliance Report", title_style),
        Paragraph(f"Review period: last {stats['period_hours']} hours | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", meta_style),
    ]
    for paragraph in report["summary"].split("\n\n"):
        story.append(Paragraph(paragraph.replace("&", "&amp;"), body_style))

    breakdown = stats["decision_breakdown"]
    table_data = [
        ["Metric", "Value", "Metric", "Value"],
        ["Total events", str(stats["total_requests"]), "Highest risk", str(max((event["risk_score"] or 0 for event in stats["highest_risk_events"]), default=0)) + "/10"],
        ["Executed", str(breakdown["executed"]), "Denied", str(breakdown["denied"])],
        ["Pending", str(breakdown["pending"]), "Approved", str(breakdown["approved"])],
        ["Rejected", str(breakdown["rejected"]), "Other/system", str(breakdown["other"])],
        ["Guardian quarantines", str(len(stats["guardian_quarantine_actions"])), "", ""],
    ]
    table = Table(table_data, colWidths=[1.35 * inch, 0.75 * inch, 1.55 * inch, 0.75 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163b39")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b9c8c4")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef4f1")]),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([Spacer(1, 5), table, Spacer(1, 10)])
    agents = ", ".join(f"{agent}: {count}" for agent, count in stats["by_agent"].items()) or "None"
    story.append(Paragraph(f"Activity by agent: {agents}", small_style))
    audit_trail = report.get("audit_trail", [])
    if audit_trail:
        trail_data = [["Timestamp", "Agent", "Query", "Decision", "Risk", "Rows"]]
        for event in audit_trail:
            trail_data.append([
                event["timestamp"].replace("+00:00", "Z")[:19].replace("T", " "),
                event["agent_id"],
                event["query"],
                event["decision"],
                str(event["risk_score"]),
                str(event["row_count"]),
            ])
        trail_table = Table(
            trail_data,
            colWidths=[1.05 * inch, 0.85 * inch, 2.85 * inch, 0.7 * inch, 0.35 * inch, 0.45 * inch],
            repeatRows=1,
        )
        trail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#315957")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 6.3),
            ("LEADING", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b9c8c4")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f6f4")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.extend([Spacer(1, 8), Paragraph("Compact audit trail", small_style), Spacer(1, 3), trail_table])
        if report.get("audit_trail_note"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(report["audit_trail_note"], small_style))
    document.build(story)
    return output.getvalue()
