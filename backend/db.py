"""SQLAlchemy database helpers and backend-agnostic schema discovery."""

import os
import re

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, Text, create_engine, insert, select, text


DEFAULT_DATABASE_URL = "sqlite:///./hr_demo.db"
DATABASE_URL = os.getenv("DB_URL", DEFAULT_DATABASE_URL)

metadata = MetaData()
audit_log = Table(
    "audit_log", metadata,
    Column("id", String, primary_key=True), Column("ts", Float, nullable=False),
    Column("agent_id", String, nullable=False), Column("nl_query", Text, nullable=False),
    Column("decision", String, nullable=False), Column("risk_score", Integer, nullable=False),
    Column("reasons", Text, nullable=False), Column("redact_columns", Text, nullable=False),
    Column("result", Text, nullable=False), Column("status", String, nullable=False),
    Column("prev_hash", String, nullable=False), Column("entry_hash", String, nullable=False),
)

_demo_metadata = MetaData()
_demo_employees = Table(
    "employees", _demo_metadata,
    Column("id", Integer, primary_key=True), Column("name", String, nullable=False),
    Column("department", String, nullable=False), Column("role", String, nullable=False),
    Column("salary", Integer, nullable=False), Column("ssn", String, nullable=False),
    Column("email", String, nullable=False),
)
_demo_rows = [
    {"id": 1, "name": "Aisha Patel", "department": "Engineering", "role": "Software Engineer", "salary": 125000, "ssn": "111-22-3333", "email": "aisha.patel@example.com"},
    {"id": 2, "name": "Marcus Chen", "department": "Engineering", "role": "Engineering Manager", "salary": 158000, "ssn": "222-33-4444", "email": "marcus.chen@example.com"},
    {"id": 3, "name": "Sofia Rodriguez", "department": "HR", "role": "People Operations Partner", "salary": 92000, "ssn": "333-44-5555", "email": "sofia.rodriguez@example.com"},
    {"id": 4, "name": "Daniel Kim", "department": "Finance", "role": "Financial Analyst", "salary": 105000, "ssn": "444-55-6666", "email": "daniel.kim@example.com"},
    {"id": 5, "name": "Priya Shah", "department": "Sales", "role": "Account Executive", "salary": 98000, "ssn": "555-66-7777", "email": "priya.shah@example.com"},
]

engine_kwargs = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, **engine_kwargs)


def get_engine():
    return engine


def get_conn():
    """Return a SQLAlchemy connection for an explicit read/write context."""
    return engine.connect()


def _valid_identifier(identifier: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier or ""):
        raise ValueError(f"Invalid SQL identifier: {identifier}")
    return identifier


def get_table_schema(table_name: str) -> list[dict[str, object]]:
    """Discover columns for a connected table on SQLite or PostgreSQL."""
    table_name = _valid_identifier(table_name)
    with get_conn() as connection:
        if DATABASE_URL.startswith("sqlite"):
            rows = connection.execute(text(f'PRAGMA table_info("{table_name}")')).fetchall()
            return [
                {"name": row._mapping["name"], "type": row._mapping["type"],
                 "nullable": not bool(row._mapping["notnull"]), "primary_key": bool(row._mapping["pk"])}
                for row in rows
            ]
        rows = connection.execute(text("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = :table_name
            ORDER BY ordinal_position
        """), {"table_name": table_name}).fetchall()
        return [
            {"name": row._mapping["column_name"], "type": row._mapping["data_type"],
             "nullable": row._mapping["is_nullable"] == "YES", "primary_key": False}
            for row in rows
        ]


def init_db() -> None:
    """Create the audit table and seed only the zero-config demo database."""
    metadata.create_all(engine)
    if DATABASE_URL != DEFAULT_DATABASE_URL:
        return
    _demo_metadata.create_all(engine)
    with engine.begin() as connection:
        existing_ids = {row[0] for row in connection.execute(select(_demo_employees.c.id)).fetchall()}
        missing = [row for row in _demo_rows if row["id"] not in existing_ids]
        if missing:
            connection.execute(insert(_demo_employees), missing)


if __name__ == "__main__":
    init_db()
