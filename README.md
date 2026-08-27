# AgentGate

AgentGate is a governance layer between AI agents and a database. It turns a natural-language request into a structured query, evaluates that query against the requesting agent's permissions, and only then allows database execution. Sensitive employee data is protected by column-level policy, risk scoring, redaction, audit logging, and optional human approval.

## Problem

AI agents are useful database operators, but a natural-language request can hide dangerous intent: an HR agent may accidentally request salary data, an analytics agent may expose individual salaries instead of an aggregate, or an untrusted agent may attempt to read SSNs or delete records. AgentGate makes the authorization boundary explicit and inspectable before an agent reaches SQLite.

## Architecture

```text
Agent / natural-language request
              |
              v
       llm.interpret()
       Groq or local parser
              |
              v
     policy_engine.evaluate()
     identity + table + column + risk checks
              |
       +------+------------------+
       |                         |
    ALLOW              REQUIRE_APPROVAL / DENY
       |                         |
       v                         v
   SQLite DB       approval queue or blocked request
       |
       +-----------> audit log
```

- `llm.py` converts natural language into `{operation, table, columns, is_aggregate, sql}`. It uses Groq when `GROQ_API_KEY` is present and a zero-configuration keyword parser otherwise.
- `policy_engine.py` registers five focused roles for the real `hr_records` dataset: `recruiter_agent`, `hr_analytics_agent`, `senior_hr_agent`, `support_agent`, and `rogue_agent`.
- `main.py` coordinates interpretation, policy decisions, SQLite execution, redaction, the in-memory approval queue, and the audit log.
- `db.py` defaults to the loaded `hr_records` database. The original five-row `employees` seed path remains available only when a different database URL is selected.
- `db.py` discovers governed table columns dynamically using SQLite `PRAGMA table_info` or PostgreSQL `information_schema`.
- `policies.yaml` defines which agents can access which tables, columns, operations, and sensitive fields.
- `frontend/index.html` is a build-free governance console that polls audit and approval state from the API.
- `compliance_agent.py` turns the audit trail into a plain-English report and a one-page PDF for compliance review.

## Tech Stack

- Python 3
- FastAPI and Uvicorn
- MCP Python SDK for direct Claude Desktop / Claude Code tool access
- ReportLab for downloadable compliance PDFs
- Pydantic request models
- SQLAlchemy Core with SQLite or PostgreSQL
- Groq's OpenAI-compatible API via Python's standard-library HTTP client, with a local parser fallback
- Single-file HTML, CSS, and JavaScript frontend

## Setup

From the project directory:

```bash
cd "/Users/aniketsingh/Documents/local/Indomitable X"
python3 -m pip install -r backend/requirements.txt
cd backend
uvicorn main:app --port 8000
```

The API is available at `http://127.0.0.1:8000`. To use Groq interpretation, set the key in a local gitignored `.env` file or export it before starting the server:

```bash
export GROQ_API_KEY="your-api-key"
```

Groq provides fast inference for this demo; a free API key can be created at [console.groq.com](https://console.groq.com/). Without `GROQ_API_KEY`, AgentGate makes no LLM call and uses the local parser and rule-based Guardian/compliance summaries.

### MCP Server

AgentGate also exposes the same governed flow as an MCP stdio server. The MCP
tools require an AgentGate API key, so copy the key printed by the server (or
read the demo-only `backend/.agent_keys.json` file) when configuring a client.

Run the MCP server from the backend directory:

```bash
cd "/Users/aniketsingh/Documents/local/Indomitable X/backend"
python3 mcp_server.py
```

For Claude Desktop, add an `agentgate` entry to
`claude_desktop_config.json` (the location depends on macOS version):

```json
{
  "mcpServers": {
    "agentgate": {
      "command": "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3",
      "args": ["/Users/aniketsingh/Documents/local/Indomitable X/backend/mcp_server.py"],
      "env": {
        "DB_URL": "sqlite:////Users/aniketsingh/Documents/local/Indomitable X/backend/hr_demo.db"
      }
    }
  }
}
```

The `query_database` tool accepts `agent_id`, the natural-language `query`,
and `api_key`. `list_pending_approvals` and `resolve_approval` also require a
valid `api_key`. For PostgreSQL, set the same `DB_URL` in the MCP entry, for
example `postgresql://user:password@host/dbname`.

### Database Backends

The consolidated demo uses `sqlite:///./hr_demo.db` by default. Create/populate it once with the included CSV loader:

```bash
cd "/Users/aniketsingh/Documents/local/Indomitable X/backend"
python3 load_hr_dataset.py
```

To switch to PostgreSQL, set `DB_URL` before starting Uvicorn:

```bash
export DB_URL="postgresql://user:password@host/dbname"
cd "/Users/aniketsingh/Documents/local/Indomitable X/backend"
uvicorn main:app --port 8000
```

The `hr_records` and `audit_log` schemas, policy flow, hash-chain verification, and API queries work against either backend. For a live demo deployment, a free PostgreSQL instance from [Supabase](https://supabase.com/) or [Render](https://render.com/) works well; copy its connection string into `DB_URL`.

### Test AgentGate Against Your Own Data

AgentGate is schema-agnostic. To govern a real SQLite or PostgreSQL table:

1. Point `DB_URL` at the database. For SQLite use an absolute URL such as `sqlite:////Users/me/data.db`; for PostgreSQL use `postgresql://user:password@host/database`.
2. Edit `backend/policies.yaml`. Add each agent and governed table, listing the columns it may see, sensitive columns that must be redacted, allowed operations, and update columns. The table and column names can be completely different from the demo.
3. Restart Uvicorn. On startup AgentGate introspects the configured tables and builds the natural-language prompt from the live schema. No Python code changes or employee seed data are needed for a custom database.

The consolidated policies are in `backend/policies.yaml` and all target `hr_records`: recruiters see organizational fields, HR analytics sees sensitive metrics only through aggregates, senior HR can read selected individual metrics but never row-level attrition, support has limited read-only access, and the rogue role has no permissions.

Example policy:

```yaml
agents:
  recruiter_agent:
    label: "Recruiter Agent"
    tables:
      hr_records:
        allowed_columns: [Employee_ID, Department, Job_Role, Education_Level, Years_At_Company]
        sensitive_columns: [Monthly_Income, Performance_Rating, Attrition]
        allowed_ops: [SELECT]
```

If `GROQ_API_KEY` is not set, the local parser still selects the governed table and live columns. With a key, Groq receives the dynamically discovered schema rather than a hardcoded employees description.

For a two-terminal demo, keep the server running in Terminal 1 and launch the scripted client from Terminal 2:

Terminal 1:

```bash
cd "/Users/aniketsingh/Documents/local/Indomitable X/backend"
uvicorn main:app --port 8000
```

Confirm the server is ready:

```bash
curl http://127.0.0.1:8000/health
```

Expected output:

```json
{"status":"ok"}
```

Terminal 2:

```bash
cd "/Users/aniketsingh/Documents/local/Indomitable X"
python3 backend/demo_agents.py
```

The server uses `backend/hr_demo.db` after the loader has run. Open the frontend directly by double-clicking `frontend/index.html`, or open this file path in a browser:

```text
/Users/aniketsingh/Documents/local/Indomitable X/frontend/index.html
```

## Try It

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Recruiter department read:

```bash
curl -X POST http://127.0.0.1:8000/agent/query \
  -H 'Authorization: Bearer <recruiter-agent-key>' \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"recruiter_agent","query":"Show employees in Sales and their job roles"}'
```

HR analytics aggregate:

```bash
curl -X POST http://127.0.0.1:8000/agent/query \
  -H 'Authorization: Bearer <hr-analytics-agent-key>' \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"hr_analytics_agent","query":"What is the average monthly income by department?"}'
```

Protected row-level income request:

```bash
curl -X POST http://127.0.0.1:8000/agent/query \
  -H 'Authorization: Bearer <hr-analytics-agent-key>' \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"hr_analytics_agent","query":"Show monthly income of employee 1001"}'
```

Inspect governance state:

```bash
curl http://127.0.0.1:8000/audit-log
curl http://127.0.0.1:8000/approvals
```

Generate a compliance report for the last 24 hours and download its PDF:

```bash
curl 'http://127.0.0.1:8000/compliance/report?hours=24'
curl -o agentgate-compliance-report.pdf 'http://127.0.0.1:8000/compliance/report/pdf?hours=24'
```

Run the narrated demo against the running server:

```bash
cd "/Users/aniketsingh/Documents/local/Indomitable X"
python3 backend/demo_agents.py
```

## Hackathon Criteria

### Technical Complexity — 35%

AgentGate combines natural-language interpretation, structured query handling, role-based authorization, sensitive-column controls, aggregate-only restrictions, risk scoring, SQL execution, redaction, auditability, and a human approval path in one request lifecycle.

### Innovation — 25%

The project treats the model as an untrusted query planner rather than an implicitly trusted database user. Every request passes through an inspectable policy boundary, with a local fallback that keeps the governance layer operational without an API key.

### Functionality — 25%

The working API supports agent discovery, query execution, denial, audit history, pending approvals, reviewer decisions, SQLite data, and six scripted demo scenarios. The frontend makes the entire decision stream visible in real time.

### UI/UX — 15%

The dashboard is a direct-open security console rather than a generic admin screen: agent identities, risk bars, color-coded outcomes, live telemetry, and approval actions are arranged around the core governance workflow.

## Project Files

```text
agentgate/
├── backend/
│   ├── db.py                  Database engine, schema discovery, and optional seed data
│   ├── policy_engine.py       Agent roles and risk evaluation
│   ├── llm.py                 Natural-language query interpretation
│   ├── main.py                FastAPI application
│   ├── guardian_agent.py      Autonomous behavioral monitoring
│   ├── compliance_agent.py    Human-readable reports and PDF export
│   ├── policies.yaml           Configurable agent/table policies
│   ├── demo_agents.py         Narrated hr_records API demo runner
│   ├── test_policy.py         Policy smoke tests
│   ├── test_llm.py            Parser smoke tests
│   └── requirements.txt       Pinned Python dependencies
├── frontend/
│   └── index.html              Build-free governance dashboard
├── README.md
└── .gitignore
```
