from __future__ import annotations

import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from apps.auth_tokens import TokenStore  # noqa: E402
from copilot.chat_store import ChatStore  # noqa: E402
from copilot.utils import data_path, load_env_file, read_json  # noqa: E402
from copilot.workflow import IncidentWorkflow  # noqa: E402

load_env_file()
app = FastAPI(title="AI Incident Copilot API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOGGER = logging.getLogger("copilot.api")


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", os.urandom(8).hex())
    request.state.request_id = request_id
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    latency_ms = (time.perf_counter() - start) * 1000
    LOGGER.info(
        "request_id=%s %s %s -> %s (%.2f ms)",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        latency_ms,
    )
    return response


WORKFLOW = IncidentWorkflow()
CHAT_STORE = ChatStore()
AUTH_TOKEN_TTL_SEC = int(os.getenv("AUTH_TOKEN_TTL_SEC", "28800"))
TOKENS = TokenStore(ttl_seconds=AUTH_TOKEN_TTL_SEC)


class RunCopilotRequest(BaseModel):
    incident_id: str = Field(..., min_length=1)
    retrieval_mode: str = Field(default="vector", pattern="^(vector|manifest_vector)$")
    approval_status: str = Field(default="pending", pattern="^(approved|rejected|pending)$")
    approved_by: str = "ui_user"
    feedback: str = ""
    force_new_ticket: bool = False


class StartCopilotRequest(BaseModel):
    incident_id: str = Field(..., min_length=1)
    retrieval_mode: str = Field(default="vector", pattern="^(vector|manifest_vector)$")


class ResumeCopilotRequest(BaseModel):
    run_id: str = Field(..., min_length=4)
    approval_status: str = Field(..., pattern="^(approved|rejected|pending)$")
    approved_by: str = "human_reviewer"
    feedback: str = ""


class ChatRequest(BaseModel):
    chat_id: str | None = None
    message: str = Field(..., min_length=1)
    approved_by: str = "chat_user"
    retrieval_mode: str = Field(default="vector", pattern="^(vector|manifest_vector)$")


class AuthRequest(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)


def _auth_user(request: Request) -> Dict[str, Any]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    user = TOKENS.resolve(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


def _issue_auth_token(user_id: int, username: str) -> Dict[str, Any]:
    return TOKENS.issue(user_id=user_id, username=username)


def _parse_logs() -> list[dict]:
    rows = []
    for line in data_path("logs.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 5)
        if len(parts) != 6:
            continue
        ts, svc, level, request_id, error_code, message = parts
        rows.append(
            {
                "timestamp": ts,
                "service": svc,
                "level": level,
                "request_id": request_id,
                "error_code": error_code,
                "message": message,
            }
        )
    return rows


def _find_incident(incident_id: str) -> Dict[str, Any] | None:
    incidents = read_json(data_path("sample_incidents.json"))
    return next((x for x in incidents if x.get("id") == incident_id), None)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "service": "ai-incident-copilot", "version": "1.0.0"}


@app.get("/api/incidents")
def incidents(incident_id: str | None = None, use_eval: bool = Query(default=False, alias="eval")) -> Dict[str, Any]:
    all_incidents = read_json(data_path("sample_incidents.json"))
    _ = use_eval
    if incident_id:
        incident = next((x for x in all_incidents if x.get("id") == incident_id), None)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {"incident": incident}
    return {"incidents": all_incidents}


@app.get("/api/logs")
def logs(service: str = "") -> Dict[str, Any]:
    rows = _parse_logs()
    if service:
        rows = [row for row in rows if row.get("service") == service]
    return {"logs": rows}


@app.get("/api/metrics")
def metrics(service: str = "") -> Dict[str, Any]:
    rows = read_json(data_path("metrics.json"))
    if service:
        rows = [row for row in rows if row.get("service") == service]
    return {"metrics": rows}


@app.get("/api/runbooks")
def runbooks(service: str = "") -> Dict[str, Any]:
    rows = read_json(data_path("runbooks.json"))
    if service:
        rows = [row for row in rows if row.get("service") == service] or rows
    return {"runbooks": rows}


@app.get("/api/historical-incidents")
def historical(service: str = "") -> Dict[str, Any]:
    rows = read_json(data_path("historical_incidents.json"))
    if service:
        rows = [row for row in rows if row.get("service") == service] or rows
    return {"historical": rows}


@app.get("/api/manifest")
def manifest() -> Dict[str, Any]:
    return {"manifest": read_json(data_path("manifest.json"))}


@app.post("/api/auth/register")
def auth_register(req: AuthRequest) -> Dict[str, Any]:
    try:
        user = CHAT_STORE.register_user(username=req.username.strip(), password=req.password)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Registration failed: {exc}") from exc
    return _issue_auth_token(user.user_id, user.username)


@app.post("/api/auth/login")
def auth_login(req: AuthRequest) -> Dict[str, Any]:
    user = CHAT_STORE.authenticate(username=req.username.strip(), password=req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return _issue_auth_token(user.user_id, user.username)


@app.get("/api/chat/sessions")
def chat_sessions(request: Request) -> Dict[str, Any]:
    user = _auth_user(request)
    return {"sessions": CHAT_STORE.list_chats(user_id=int(user["user_id"]))}


@app.get("/api/chat/sessions/{chat_id}")
def chat_session_detail(chat_id: str, request: Request) -> Dict[str, Any]:
    user = _auth_user(request)
    chat = CHAT_STORE.get_chat(user_id=int(user["user_id"]), chat_id=chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    return {"chat": chat, "messages": CHAT_STORE.get_messages(chat_id)}


@app.post("/api/run-copilot")
def run_copilot(req: RunCopilotRequest) -> Dict[str, Any]:
    incident = _find_incident(req.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {req.incident_id} not found")
    if "idempotency_key" not in incident:
        incident["idempotency_key"] = f"{incident['id']}-create"
    if req.force_new_ticket:
        incident["idempotency_key"] = f"{incident['idempotency_key']}-{int(time.time() * 1000)}"

    try:
        state = WORKFLOW.run(
            incident=incident,
            config={"retrieval_mode": req.retrieval_mode},
            approval_handler=lambda _: {
                "status": req.approval_status,
                "approved_by": req.approved_by,
                "note": req.feedback,
            },
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Workflow failed: {exc}") from exc

    return {
        "outcome": state.outcome,
        "diagnosis": state.diagnosis,
        "remediation": state.remediation,
        "approval": state.approval,
        "servicenow": state.servicenow,
    }


@app.post("/api/run-copilot/start")
def run_copilot_start(req: StartCopilotRequest) -> Dict[str, Any]:
    incident = _find_incident(req.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {req.incident_id} not found")
    if "idempotency_key" not in incident:
        incident["idempotency_key"] = f"{incident['id']}-create"
    try:
        result = WORKFLOW.start_and_wait(
            incident=incident,
            config={"retrieval_mode": req.retrieval_mode},
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Workflow start failed: {exc}") from exc
    return result


@app.post("/api/run-copilot/resume")
def run_copilot_resume(req: ResumeCopilotRequest) -> Dict[str, Any]:
    try:
        state = WORKFLOW.resume(
            run_id_val=req.run_id,
            approval_decision={"status": req.approval_status, "approved_by": req.approved_by, "note": req.feedback},
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Workflow resume failed: {exc}") from exc

    return {
        "outcome": state.outcome,
        "diagnosis": state.diagnosis,
        "remediation": state.remediation,
        "approval": state.approval,
        "servicenow": state.servicenow,
    }


def _extract_incident_id(text: str) -> str | None:
    m = re.search(r"INC-SAMPLE-\d{3}|INC\d{4,}", text.upper())
    return m.group(0) if m else None


def _extract_approval(text: str) -> str | None:
    low = text.strip().lower()
    if any(word in low for word in ["approve", "approved", "yes", "go ahead", "good remedy", "looks good", "proceed"]):
        return "approved"
    if any(word in low for word in ["reject", "rejected", "no", "deny"]):
        return "rejected"
    if "pending" in low or "wait" in low:
        return "pending"
    return None


def _chat_help_text() -> str:
    return (
        "I can help with incident triage. Share an incident id like INC-SAMPLE-001 or paste alert details "
        "(service, symptoms, severity, impact). I will investigate, draft remediation, and then ask for approval."
    )


def _infer_service_from_text(text: str) -> str:
    low = text.lower()
    mapping = {
        "checkout": "checkout-api",
        "payment": "payment-api",
        "auth": "auth-service",
        "inventory": "inventory-service",
        "search": "search-api",
        "gateway": "gateway",
        "cache": "cache-layer",
        "notification": "notification-worker",
        "db": "db-proxy",
    }
    for key, service in mapping.items():
        if key in low:
            return service
    return "unknown-service"


def _build_incident_from_description(session_id: str, text: str) -> Dict[str, Any]:
    title = text.strip().split(".")[0][:90] or "Production incident"
    service = _infer_service_from_text(text)
    sev = "2" if any(x in text.lower() for x in ["sev1", "sev2", "critical", "outage", "high"]) else "3"
    return {
        "id": f"CHAT-{session_id[-6:]}",
        "title": title,
        "description": text,
        "service": service,
        "severity": sev,
        "start_time": "2026-09-26T10:00:00Z",
        "end_time": "2026-09-26T10:30:00Z",
        "idempotency_key": f"chat-{session_id}-create",
    }


@app.post("/api/chat")
def chat(req: ChatRequest, request: Request) -> Dict[str, Any]:
    user = _auth_user(request)
    user_id = int(user["user_id"])

    chat_id = req.chat_id
    if chat_id:
        chat = CHAT_STORE.get_chat(user_id=user_id, chat_id=chat_id)
        if not chat:
            raise HTTPException(status_code=404, detail="Chat not found")
        state = chat.get("state", {})
    else:
        title = req.message.strip().split("\n")[0][:80] or "New incident chat"
        chat_id = CHAT_STORE.create_chat(user_id=user_id, title=title)
        state = {"waiting_approval": False, "waiting_clarification": False}

    CHAT_STORE.add_message(chat_id, "user", req.message)

    intent = WORKFLOW.agent_chat_intent(
        req.message,
        {
            "waiting_approval": bool(state.get("waiting_approval")),
            "waiting_clarification": bool(state.get("waiting_clarification")),
            "has_run_id": bool(state.get("run_id")),
            "last_incident_id": state.get("last_incident_id", ""),
        },
    )

    if state.get("waiting_clarification"):
        incident = state.get("incident_payload") or _build_incident_from_description(chat_id, req.message)
        incident["description"] = (incident.get("description", "") + "\nClarification: " + req.message).strip()
        incident["idempotency_key"] = f"{incident.get('idempotency_key','chat')}-{int(time.time()*1000)}"
        started = WORKFLOW.start_and_wait(incident=incident, config={"retrieval_mode": req.retrieval_mode})
        state.update({"run_id": started["run_id"], "waiting_clarification": False, "waiting_approval": True, "incident_payload": incident})
        CHAT_STORE.set_state(chat_id, state)
        remediation = started.get("approval_request", {}).get("remediation", {})
        assistant = WORKFLOW.agent_chat_response(
            "Summarize revised incident plan and request approval.",
            {"incident": incident, "remediation": remediation, "fallback": "Revised plan ready. Reply approved or rejected."},
        )
        CHAT_STORE.add_message(chat_id, "assistant", assistant)
        return {"chat_id": chat_id, "assistant": assistant, "state": {"waiting_approval": True}, "preview": remediation}

    if state.get("waiting_approval") and state.get("run_id"):
        decision = intent.get("approval_status")
        if decision == "none":
            decision = _extract_approval(req.message)
        if not decision:
            assistant = WORKFLOW.agent_chat_response(
                "Ask user to provide approval decision (approved/rejected/pending).",
                {"fallback": "I am waiting for approval. Reply approved, rejected, or pending."},
            )
            CHAT_STORE.add_message(chat_id, "assistant", assistant)
            return {"chat_id": chat_id, "assistant": assistant, "state": {"waiting_approval": True}}

        if decision == "rejected":
            state.update({"waiting_approval": False, "waiting_clarification": True})
            CHAT_STORE.set_state(chat_id, state)
            assistant = WORKFLOW.agent_chat_response(
                "User rejected plan. Ask concise clarification questions to revise remediation.",
                {"fallback": "Please share what should change. I will revise the plan."},
            )
            CHAT_STORE.add_message(chat_id, "assistant", assistant)
            return {"chat_id": chat_id, "assistant": assistant, "state": {"waiting_clarification": True}}

        result = WORKFLOW.resume(
            run_id_val=state["run_id"],
            approval_decision={"status": decision, "approved_by": req.approved_by, "note": req.message},
        )
        state.update({"waiting_approval": False, "waiting_clarification": False, "run_id": None})
        CHAT_STORE.set_state(chat_id, state)
        assistant = WORKFLOW.agent_chat_response(
            "Summarize final action result after approval, including ServiceNow status.",
            {
                "decision": decision,
                "diagnosis": result.diagnosis,
                "servicenow": result.servicenow,
                "fallback": f"Approval {decision}. ServiceNow status: {result.servicenow.get('status','skipped')}",
            },
        )
        CHAT_STORE.add_message(chat_id, "assistant", assistant)
        return {
            "chat_id": chat_id,
            "assistant": assistant,
            "state": {"waiting_approval": False},
            "result": {
                "outcome": result.outcome,
                "diagnosis": result.diagnosis,
                "approval": result.approval,
                "servicenow": result.servicenow,
            },
        }

    intent_type = intent.get("intent", "incident_report")
    incident_id = intent.get("incident_id") or _extract_incident_id(req.message)

    if intent_type == "smalltalk" and not incident_id:
        assistant = intent.get("response") or WORKFLOW.agent_chat_response(
            "Reply naturally to user message as an SRE incident copilot and mention you can triage incidents.",
            {"user_message": req.message, "fallback": _chat_help_text()},
        )
        CHAT_STORE.add_message(chat_id, "assistant", assistant)
        return {"chat_id": chat_id, "assistant": assistant, "state": {"waiting_approval": False}}

    if incident_id:
        incident = None
        sn_read = WORKFLOW.toolset.read_servicenow_incident(incident_id)
        if sn_read.get("ok"):
            payload = sn_read.get("data", {}).get("result") if isinstance(sn_read.get("data"), dict) else sn_read.get("data", {})
            if not isinstance(payload, dict):
                payload = {}
            desc = payload.get("description") or payload.get("short_description") or f"ServiceNow incident {incident_id}"
            incident = {
                "id": incident_id,
                "title": payload.get("short_description", f"ServiceNow incident {incident_id}"),
                "description": desc,
                "service": _infer_service_from_text(desc),
                "severity": str(payload.get("urgency") or payload.get("severity") or "2"),
                "start_time": "2026-09-26T10:00:00Z",
                "end_time": "2026-09-26T10:30:00Z",
                "idempotency_key": f"{incident_id}-chat",
                "servicenow_incident_id": payload.get("sys_id") or payload.get("number") or incident_id,
            }
        else:
            incident = _find_incident(incident_id)
        if not incident:
            assistant = WORKFLOW.agent_chat_response(
                "Incident id not found. Ask user for raw incident details to proceed.",
                {"incident_id": incident_id, "fallback": f"I could not fetch {incident_id}. Please share incident details."},
            )
            CHAT_STORE.add_message(chat_id, "assistant", assistant)
            return {"chat_id": chat_id, "assistant": assistant, "state": {"waiting_approval": False}}
    else:
        incident = _build_incident_from_description(chat_id, req.message)
        incident_id = incident["id"]

    if "idempotency_key" not in incident:
        incident["idempotency_key"] = f"{incident['id']}-create"

    started = WORKFLOW.start_and_wait(incident=incident, config={"retrieval_mode": req.retrieval_mode})
    remediation = started.get("approval_request", {}).get("remediation", {})
    state.update(
        {
            "run_id": started["run_id"],
            "waiting_approval": True,
            "waiting_clarification": False,
            "last_incident_id": incident_id,
            "incident_payload": incident,
        }
    )
    CHAT_STORE.set_state(chat_id, state)
    CHAT_STORE.set_title(chat_id, incident.get("title", "Incident triage"))

    assistant = WORKFLOW.agent_chat_response(
        "Triage complete. Explain likely root cause and ask for approval to create/update ServiceNow incident.",
        {
            "incident_id": incident_id,
            "remediation": remediation,
            "fallback": (
                f"Triage complete for {incident_id}. Root cause: {remediation.get('likely_root_cause','unknown')} "
                f"(confidence {remediation.get('confidence',0)}). Reply approved or rejected."
            ),
        },
    )
    CHAT_STORE.add_message(chat_id, "assistant", assistant)
    return {"chat_id": chat_id, "assistant": assistant, "state": {"waiting_approval": True, "run_id": started["run_id"]}, "preview": remediation}


web_dir = ROOT / "frontend" / "dist"
if web_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(web_dir / "assets")), name="assets")


@app.get("/")
def index() -> FileResponse:
    if not web_dir.exists():
        raise HTTPException(status_code=503, detail="Frontend not built. Run: npm install && npm run build in frontend/")
    return FileResponse(web_dir / "index.html")
