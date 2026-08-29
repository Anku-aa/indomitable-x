"""Health and agent discovery endpoints."""

from fastapi import APIRouter

from policy_engine import AGENT_ROLES


router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/agents")
def agents():
    return {"agents": list(AGENT_ROLES)}
