"""FastAPI application assembly for the Agenate governance layer."""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.auth_dependencies import print_agent_keys
from db import init_db
from models import AgentQueryRequest, ApprovalRequest
from routes.approvals import approvals, review_approval, router as approvals_router
from routes.audit import router as audit_router
from routes.compliance import router as compliance_router
from routes.guardian import router as guardian_router
from routes.query import agent_query, router as query_router
from routes.system import router as system_router


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


init_db()

app = FastAPI(title="Agenate")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system_router)
app.include_router(query_router)
app.include_router(audit_router)
app.include_router(approvals_router)
app.include_router(guardian_router)
app.include_router(compliance_router)


@app.on_event("startup")
def startup():
    print_agent_keys()


if __name__ == "__main__":
    uvicorn.run("main:app", host=DEFAULT_HOST, port=DEFAULT_PORT)
