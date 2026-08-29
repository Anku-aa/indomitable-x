"""Simple static API-key authentication for registered Agenate agents."""

import hmac
import json
import secrets
from pathlib import Path

from policy_engine import AGENT_ROLES


AGENT_IDS = tuple(AGENT_ROLES)
KEY_FILE = Path(__file__).with_name(".agent_keys.json")


def _load_or_generate_keys():
    try:
        stored = json.loads(KEY_FILE.read_text())
        if all(isinstance(stored.get(agent_id), str) for agent_id in AGENT_IDS):
            return {agent_id: stored[agent_id] for agent_id in AGENT_IDS}
    except (OSError, json.JSONDecodeError):
        pass

    keys = {agent_id: secrets.token_hex(16) for agent_id in AGENT_IDS}
    KEY_FILE.write_text(json.dumps(keys, indent=2) + "\n")
    try:
        KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return keys


AGENT_KEYS = _load_or_generate_keys()


def verify_key(agent_id: str, provided_key: str) -> bool:
    """Return whether the provided key belongs to the claimed agent."""
    expected_key = AGENT_KEYS.get(agent_id)
    if expected_key is None or not isinstance(provided_key, str):
        return False
    return hmac.compare_digest(expected_key, provided_key)
