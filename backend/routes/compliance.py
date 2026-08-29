"""Compliance report endpoints."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from compliance_agent import generate_pdf, generate_report
from services.audit_service import _timestamp


router = APIRouter()


@router.get("/compliance/report")
def compliance_report(hours: int = 24):
    try:
        report = generate_report(hours)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {**report, "generated_at": _timestamp()}


@router.get("/compliance/report/pdf")
def compliance_report_pdf(hours: int = 24):
    try:
        report = generate_report(hours)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    pdf = generate_pdf(report, report["stats"])
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=agentgate-compliance-report.pdf"})
