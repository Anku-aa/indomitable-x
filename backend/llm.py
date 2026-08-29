"""Natural-language interpretation using dynamic governed schemas."""

import json
import os
import re
from pathlib import Path
from urllib.request import Request, urlopen

from dotenv import load_dotenv

from db import get_table_schema
from policy_engine import AGENT_ROLES, governed_tables, sensitive_columns


load_dotenv(Path(__file__).resolve().parents[1] / ".env")
_GROQ_MODEL = "llama-3.3-70b-versatile"
_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def extract_target_row_id(nl_query):
    """Extract a generic row id from phrases such as 'customer with id 5'."""
    match = re.search(r"\b(?:employee|customer|user)\s+(?:with\s+)?(?:id\s*(?:is|=|of|#)?\s*)?(\d+)\b", nl_query, re.IGNORECASE)
    if not match:
        match = re.search(r"\b(?:record|row)?\s*(?:with\s+)?id\s*(?:is|=|of|#)?\s*(\d+)\b", nl_query, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _schema_map() -> dict[str, list[dict[str, object]]]:
    schemas = {}
    for table in governed_tables():
        discovered = get_table_schema(table)
        if discovered:
            schemas[table] = discovered
            continue

        # Keep interpretation deterministic during first boot, before a
        # governed table has been created or a remote schema is reachable.
        policy_columns = set()
        for role in AGENT_ROLES.values():
            table_policy = role["tables"].get(table)
            if table_policy:
                policy_columns.update(table_policy["allowed_columns"])
                policy_columns.update(table_policy["sensitive_columns"])
                policy_columns.update(table_policy["row_level_denied_columns"])
                policy_columns.update(table_policy["aggregate_only_columns"])
        schemas[table] = [{"name": column, "type": "UNKNOWN"} for column in sorted(policy_columns)]
    return schemas


def _table_for_query(text: str, schemas: dict[str, list[dict[str, object]]]) -> str:
    lowered = text.lower()
    available = {table: schema for table, schema in schemas.items() if table in governed_tables()}
    if not available:
        return ""
    for table in available:
        if re.search(rf"\b{re.escape(table.lower())}\b", lowered) or re.search(rf"\b{re.escape(table.lower().rstrip('s'))}s?\b", lowered):
            return table
    scored = []
    for table, schema in available.items():
        score = sum(1 for column in schema if re.search(rf"\b{re.escape(str(column['name']).lower())}s?\b", lowered))
        scored.append((score, table))
    return max(scored)[1] if scored and max(scored)[0] > 0 else next(iter(available), "")


def _columns_in(text: str, schema: list[dict[str, object]]) -> list[str]:
    lowered = text.lower()
    mentioned = []
    for column in schema:
        name = str(column["name"])
        variants = {name.lower(), name.lower().replace("_", " ")}
        if any(re.search(rf"\b{re.escape(variant)}s?\b", lowered) for variant in variants):
            mentioned.append(name)
    # People commonly say "ID" instead of the dataset's Employee_ID name.
    if "Employee_ID" in {str(column["name"]) for column in schema} and re.search(r"\b(?:employee\s+)?id\b", lowered):
        if "Employee_ID" not in mentioned:
            mentioned.insert(0, "Employee_ID")
    return mentioned


def _quoted(value: str) -> str:
    """Quote a small natural-language literal for the generated read query."""
    return "'" + value.replace("'", "''") + "'"


def _education_filter(text: str, schema: list[dict[str, object]]) -> str | None:
    names = {str(column["name"]) for column in schema}
    if "Education_Level" not in names:
        return None
    matches = (
        (r"\bphd\b", "PhD"),
        (r"\bdoctorate\b", "PhD"),
        (r"\bmaster(?:'s)?\s+degree\b", "Master's Degree"),
        (r"\bbachelor(?:'s)?\s+degree\b", "Bachelor's Degree"),
        (r"\bhigh\s+school\b", "High School"),
    )
    lowered = text.lower()
    for pattern, value in matches:
        if re.search(pattern, lowered):
            return f"Education_Level = {_quoted(value)}"
    return None


def _overtime_filter(text: str, schema: list[dict[str, object]]) -> str | None:
    names = {str(column["name"]) for column in schema}
    if "Overtime" not in names or not re.search(r"\bovertime\b", text, re.IGNORECASE):
        return None
    value = "No" if re.search(r"\b(?:not|without|don't|do not)\s+(?:work\s+)?overtime\b", text, re.IGNORECASE) else "Yes"
    return f"Overtime = {_quoted(value)}"


def _department_filter_value(text: str, schema: list[dict[str, object]]) -> str | None:
    names = {str(column["name"]) for column in schema}
    if "Department" not in names:
        return None
    match = re.search(
        r"\b(?:in|from)\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 &-]*?)(?:\s+department)?"
        r"(?:\s+(?:and|their|with|where)|[?.!,]|$)",
        text,
        re.IGNORECASE,
    )
    return match.group(1).strip() if match else None


def _insert_field_value(text: str, column: str, schema: list[dict[str, object]]) -> str | None:
    """Read an explicitly labelled INSERT field without guessing its value."""
    if column == "Employee_ID":
        target_id = extract_target_row_id(text)
        return str(target_id) if target_id is not None else None
    aliases = {column.lower(), column.lower().replace("_", " ")}
    if column == "Job_Role":
        aliases.add("role")
    alias_pattern = "|".join(re.escape(alias) for alias in sorted(aliases, key=len, reverse=True))
    known_aliases = []
    for item in schema:
        known_aliases.extend([str(item["name"]).lower(), str(item["name"]).lower().replace("_", " ")])
    stop_pattern = "|".join(
        re.escape(alias) for alias in sorted(set(known_aliases), key=len, reverse=True) if alias not in aliases
    )
    stop = rf"(?=\s*(?:,|\band\s+(?:{stop_pattern})\b|$))" if stop_pattern else r"(?=\s*(?:,|$))"
    match = re.search(
        rf"\b(?:{alias_pattern})\b\s*(?:is|=|:|to)?\s*([^,;]+?){stop}",
        text,
        re.IGNORECASE,
    )
    return match.group(1).strip().strip("'\"") if match else None


def _parsed(operation, table, columns, is_aggregate, sql):
    return {"operation": operation, "table": table, "columns": columns, "is_aggregate": is_aggregate, "sql": sql}


def _rule_based_parse(nl_query):
    text = nl_query.strip()
    lowered = text.lower()
    schemas = _schema_map()
    table = _table_for_query(text, schemas)
    schema = schemas.get(table, [])
    all_columns = [str(column["name"]) for column in schema]
    columns = _columns_in(text, schema)
    if not table:
        return _parsed("SELECT", "", [], False, "SELECT 1;")

    if re.search(r"\b(add|create|insert)\b", lowered) and re.search(r"\b(?:employee|record)\b", lowered):
        insert_columns = [
            column for column in all_columns
            if _insert_field_value(text, column, schema) is not None
        ]
        placeholders = ", ".join(f":{column}" for column in insert_columns)
        column_list = ", ".join(insert_columns)
        sql = f"INSERT INTO {table} ({column_list}) VALUES ({placeholders});" if insert_columns else f"INSERT INTO {table} DEFAULT VALUES;"
        return _parsed("INSERT", table, insert_columns, False, sql)

    if re.search(r"\b(average|avg|count|sum|minimum|maximum|min|max)\b", lowered):
        if re.search(r"\b(average|avg)\b", lowered):
            group_column = next((column for column in columns if re.search(rf"\bby\s+{re.escape(column.lower().replace('_', ' '))}s?\b", lowered)), None)
            aggregate_column = "salary" if "salary" in columns else next((c for c in columns if c != group_column and c != "id"), "id")
            if group_column and group_column != aggregate_column:
                return _parsed("SELECT", table, columns, True, f"SELECT {group_column}, AVG({aggregate_column}) AS average_{aggregate_column} FROM {table} GROUP BY {group_column};")
            return _parsed("SELECT", table, columns, True, f"SELECT AVG({aggregate_column}) AS average_{aggregate_column} FROM {table};")
        if re.search(r"\bcount\b", lowered):
            return _parsed("SELECT", table, columns, True, f"SELECT COUNT(*) AS {table}_count FROM {table};")
        aggregate_column = next((c for c in columns if c != "id"), "id")
        function, label = ("SUM", "total") if "sum" in lowered else (("MIN", "minimum") if re.search(r"\b(minimum|min)\b", lowered) else ("MAX", "maximum"))
        return _parsed("SELECT", table, columns, True, f"SELECT {function}({aggregate_column}) AS {label}_{aggregate_column} FROM {table};")

    if re.search(r"\b(update|change|set|modify|edit)\b", lowered):
        has_id_filter = "id" in columns
        update_columns = [column for column in columns if column != "id"] or [next((c for c in all_columns if c != "id"), "id")]
        assignments = ", ".join(f"{column} = :{column}" for column in update_columns)
        where_clause = " WHERE id = :id" if has_id_filter else ""
        return _parsed("UPDATE", table, update_columns, False, f"UPDATE {table} SET {assignments}{where_clause};")
    if re.search(r"\b(delete|remove)\b", lowered):
        target_id = extract_target_row_id(text)
        row_key = next((column for column in ("id", "Employee_ID") if column in all_columns), None)
        department = _department_filter_value(text, schema)
        if target_id is not None and row_key:
            columns = [row_key]
            sql = f"DELETE FROM {table} WHERE {row_key} = :id;"
        elif department:
            columns = ["Department"]
            sql = f"DELETE FROM {table} WHERE Department = :department_filter;"
        else:
            sql = f"DELETE FROM {table};"
        return _parsed("DELETE", table, columns, False, sql)

    columns = columns or all_columns
    filters = [value for value in (_education_filter(text, schema), _overtime_filter(text, schema)) if value]
    sql = f"SELECT {', '.join(columns)} FROM {table}"
    if filters:
        sql += " WHERE " + " AND ".join(filters)
    return _parsed("SELECT", table, columns, False, sql + ";")


def _apply_common_filters(parsed: dict, nl_query: str) -> dict:
    """Add deterministic filters when an LLM omits an obvious dataset condition."""
    if parsed.get("operation") != "SELECT" or parsed.get("is_aggregate"):
        return parsed
    schema = _schema_map().get(parsed.get("table"), [])
    filters = [value for value in (_education_filter(nl_query, schema), _overtime_filter(nl_query, schema)) if value]
    sql = parsed.get("sql", "").rstrip().rstrip(";")
    if filters and " where " not in sql.lower():
        parsed = {**parsed, "sql": sql + " WHERE " + " AND ".join(filters) + ";"}
    return parsed


def _schema_description():
    descriptions = []
    for table, schema in _schema_map().items():
        sensitive = set()
        for role in AGENT_ROLES.values():
            policy = role["tables"].get(table)
            if policy:
                sensitive.update(policy["sensitive_columns"])
        fields = ", ".join(f"{column['name']} {column['type']}" + (" (SENSITIVE)" if column["name"] in sensitive else "") for column in schema)
        descriptions.append(f"- {table}: {fields}")
    return "\n".join(descriptions) or "- No governed tables were discovered"


def _validate_llm_result(result):
    required = {"operation", "table", "columns", "is_aggregate", "sql"}
    if set(result) != required:
        raise ValueError("Groq response did not match the required shape")
    if result["operation"] not in {"SELECT", "UPDATE", "DELETE", "INSERT"}:
        raise ValueError("Groq returned an invalid operation")
    if result["table"] not in governed_tables() or not isinstance(result["columns"], list):
        raise ValueError("Groq returned an invalid governed table or columns value")
    valid_columns = {str(column["name"]) for column in _schema_map().get(result["table"], [])}
    if any(column not in valid_columns for column in result["columns"]):
        raise ValueError("Groq returned a column not present in the connected schema")
    if not isinstance(result["is_aggregate"], bool) or not isinstance(result["sql"], str):
        raise ValueError("Groq returned invalid field types")
    return result


def _call_groq(nl_query, api_key):
    prompt = f"""Convert the user's request into one database query for Agenate.

Governed database schema:
{_schema_description()}

Return ONLY valid JSON with exactly this shape:
{{"operation":"SELECT|UPDATE|DELETE|INSERT","table":"table_name","columns":["column"],"is_aggregate":false,"sql":"SQL string"}}

Use only governed tables and columns shown above. Set is_aggregate true for
AVG, COUNT, SUM, MIN, or MAX queries. Do not add explanations.

User request: {nl_query}
"""
    body = json.dumps({"model": _GROQ_MODEL, "temperature": 0, "max_tokens": 500, "messages": [{"role": "user", "content": prompt}]}).encode("utf-8")
    request = Request(_GROQ_URL, data=body, headers={"content-type": "application/json", "authorization": f"Bearer {api_key}"}, method="POST")
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"].strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content).strip()
    return _validate_llm_result(json.loads(content))


def interpret(nl_query: str) -> dict:
    """Interpret a request with Groq, falling back to the dynamic local parser."""
    api_key = os.getenv("GROQ_API_KEY")
    if api_key:
        try:
            return _apply_common_filters(_call_groq(nl_query, api_key), nl_query)
        except Exception:
            pass
    return _apply_common_filters(_rule_based_parse(nl_query), nl_query)
