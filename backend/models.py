"""Request models shared by the HTTP and MCP entry points."""

from typing import Optional

from pydantic import BaseModel


class AgentQueryRequest(BaseModel):
    agent_id: Optional[str] = None
    query: str
    target_row_id: Optional[int] = None


class ApprovalRequest(BaseModel):
    approve: bool
    reviewer: str
    confirm_quarantine_override: bool = False
