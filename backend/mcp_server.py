"""MCP stdio server for governed AgentGate database access.

The tool handlers call the existing FastAPI endpoint functions directly so
MCP and REST requests share interpretation, policy, execution, redaction,
approval, and audit behavior.
"""

from typing import Any

from mcp.server.mcpserver import MCPServer

from auth import AGENT_KEYS, verify_key
from main import (
    AgentQueryRequest,
    ApprovalRequest,
    agent_query,
    approvals,
    review_approval,
)


server = MCPServer(
    "agentgate",
    description="AgentGate governed employee database access",
)


def _require_valid_key(api_key: str) -> None:
    if not isinstance(api_key, str) or not any(
        verify_key(agent_id, api_key) for agent_id in AGENT_KEYS
    ):
        raise ValueError("Invalid or missing AgentGate API key")


@server.tool(
    description=(
        "Submit a natural-language employee database request. The request is "
        "authenticated, interpreted, policy-checked, executed, redacted, "
        "queued for approval, or denied just like the REST API."
    ),
    structured_output=True,
)
def query_database(agent_id: str, query: str, api_key: str) -> dict[str, Any]:
    """Run one authenticated, governed database request."""
    if not verify_key(agent_id, api_key):
        raise ValueError("Invalid API key for claimed agent")
    return agent_query(AgentQueryRequest(agent_id=agent_id, query=query), api_key)


@server.tool(
    description="List pending AgentGate approval requests using a valid agent key.",
    structured_output=True,
)
def list_pending_approvals(api_key: str) -> dict[str, Any]:
    """Return the current in-memory approval queue."""
    _require_valid_key(api_key)
    return approvals()


@server.tool(
    description=(
        "Approve or reject a pending AgentGate request. A valid AgentGate "
        "agent key is required; reviewer identifies the human reviewer."
    ),
    structured_output=True,
)
def resolve_approval(
    approval_id: str,
    approve: bool,
    reviewer: str,
    api_key: str,
) -> dict[str, Any]:
    """Resolve an approval through the same REST approval handler."""
    _require_valid_key(api_key)
    try:
        numeric_id = int(approval_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("approval_id must be an integer") from exc
    return review_approval(numeric_id, ApprovalRequest(approve=approve, reviewer=reviewer))


if __name__ == "__main__":
    server.run("stdio")
