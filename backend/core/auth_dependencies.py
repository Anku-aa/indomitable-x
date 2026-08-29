"""FastAPI authentication dependencies for AgentGate."""

from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth import AGENT_KEYS


bearer_scheme = HTTPBearer(auto_error=False)


def require_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization Bearer token required")
    return credentials.credentials


def _agent_for_key(api_key: str) -> Optional[str]:
    """Resolve a supplied credential without trusting a client-supplied identity."""
    for agent_id, expected_key in AGENT_KEYS.items():
        if api_key == expected_key:
            return agent_id
    return None


def print_agent_keys():
    print("AgentGate API keys (demo-only; keep these secret):")
    for agent_id, key in AGENT_KEYS.items():
        print(f"  {agent_id}: {key}")
