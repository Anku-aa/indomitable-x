"""Shared in-memory state used by routes and services."""

from itertools import count
from threading import Lock


PENDING_APPROVALS = {}
PENDING_CREATED_AT = {}
PENDING_LOCK = Lock()
AUDIT_LOCK = Lock()
_approval_ids = count(1)
