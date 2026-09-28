from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from .schemas import (
    CreateServiceNowIncidentInput,
    FetchLogsInput,
    FetchMetricsInput,
    SearchRunbooksInput,
)
from .state import WorkflowState
from .telemetry import Tracer
from .tools import Toolset, timed_tool_call
from .utils import project_root, read_json, run_id, write_json

try:
    from langchain_openai import AzureChatOpenAI
except Exception:  # noqa: BLE001
    AzureChatOpenAI = None

IncidentState = WorkflowState


class DiagnosisOutput(BaseModel):
    likely_root_cause: str = Field(min_length=3)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Dict[str, str]]
    needs_clarification: bool = False
    clarifying_question: str = ""


class RemediationOutput(BaseModel):
    incident_summary: str
    likely_root_cause: str
    confidence: float
    evidence: list[Dict[str, str]]
    recommended_actions: list[Dict[str, Any]]


class InvestigationPlanOutput(BaseModel):
    should_use_logs: bool = True
    should_use_metrics: bool = True
    should_use_runbooks: bool = True
    should_use_historical: bool = True
    deterministic_known_issue: bool = False
    likely_root_cause: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""


class ChatIntentOutput(BaseModel):
    intent: Literal["smalltalk", "incident_report", "approval", "clarification"]
    incident_id: str = ""
    approval_status: Literal["approved", "rejected", "pending", "none"] = "none"
    response: str = ""


@dataclass
class WorkflowResult:
    raw: Dict[str, Any]

    @property
    def outcome(self) -> Dict[str, Any]:
        return self.raw.get("outcome", {})

    @property
    def diagnosis(self) -> Dict[str, Any]:
        return self.raw.get("diagnosis", {})

    @property
    def remediation(self) -> Dict[str, Any]:
        return self.raw.get("remediation", {})

    @property
    def approval(self) -> Dict[str, Any]:
        return self.raw.get("approval", {})

    @property
    def servicenow(self) -> Dict[str, Any]:
        return self.raw.get("servicenow", {})


KNOWN_ISSUES = {
    "db_timeout": {
        "keywords": ["db_timeout", "connection pool", "pool exhausted"],
        "root_cause": "database_connection_pool_exhaustion",
        "confidence": 0.9,
    },
    "tls_expiry": {
        "keywords": ["tls", "certificate", "x509", "expired"],
        "root_cause": "expired_tls_certificate",
        "confidence": 0.92,
    },
}


class IncidentWorkflow:
    def __init__(self, model_name: str | None = None) -> None:
        self.toolset = Toolset()
        self.model_name = model_name or os.getenv("DEFAULT_MODEL_NAME", "azure-openai")
        self._tracers: Dict[str, Tracer] = {}
        self._checkpointer = MemorySaver()
        self.graph = self._build_graph().compile(checkpointer=self._checkpointer)

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(IncidentState)
        graph.add_node("classify_incident", self._wrap_node("classify_incident", self.classify_incident))
        graph.add_node("deterministic_known_issue_check", self._wrap_node("deterministic_known_issue_check", self.deterministic_known_issue_check))
        graph.add_node("fetch_logs", self._wrap_node("fetch_logs", self.fetch_logs))
        graph.add_node("fetch_metrics", self._wrap_node("fetch_metrics", self.fetch_metrics))
        graph.add_node("retrieve_runbooks", self._wrap_node("retrieve_runbooks", self.retrieve_runbooks))
        graph.add_node("retrieve_historical_incidents", self._wrap_node("retrieve_historical_incidents", self.retrieve_historical_incidents))
        graph.add_node("diagnose", self._wrap_node("diagnose", self.diagnose))
        graph.add_node("draft_remediation", self._wrap_node("draft_remediation", self.draft_remediation))
        graph.add_node("request_human_approval", self._wrap_node("request_human_approval", self.request_human_approval))
        graph.add_node("create_or_update_servicenow", self._wrap_node("create_or_update_servicenow", self.create_or_update_servicenow))
        graph.add_node("finalize_report", self._wrap_node("finalize_report", self.finalize_report))

        graph.add_edge(START, "classify_incident")
        graph.add_edge("classify_incident", "deterministic_known_issue_check")
        graph.add_edge("deterministic_known_issue_check", "fetch_logs")
        graph.add_edge("fetch_logs", "fetch_metrics")
        graph.add_edge("fetch_metrics", "retrieve_runbooks")
        graph.add_edge("retrieve_runbooks", "retrieve_historical_incidents")
        graph.add_edge("retrieve_historical_incidents", "diagnose")
        graph.add_edge("diagnose", "draft_remediation")
        graph.add_edge("draft_remediation", "request_human_approval")
        graph.add_conditional_edges(
            "request_human_approval",
            self._approval_route,
            {"write": "create_or_update_servicenow", "final": "finalize_report"},
        )
        graph.add_edge("create_or_update_servicenow", "finalize_report")
        graph.add_edge("finalize_report", END)
        return graph

    def _wrap_node(self, node_name: str, fn):
        def _inner(state: IncidentState):
            tracer = self._tracer(state)
            start = time.perf_counter()
            try:
                out = fn(state)
                tracer.node_done(node_name, (time.perf_counter() - start) * 1000, "ok")
                return out
            except Exception:
                tracer.node_done(node_name, (time.perf_counter() - start) * 1000, "error")
                raise

        return _inner

    def _thread_cfg(self, run_id_val: str) -> Dict[str, Any]:
        return {"configurable": {"thread_id": run_id_val}}

    def _tracer(self, state: IncidentState) -> Tracer:
        rid = state["run_id"]
        if rid not in self._tracers:
            self._tracers[rid] = Tracer(run_id=rid, model_name=state.get("model_name", self.model_name))
        return self._tracers[rid]

    def _llm(self):
        if AzureChatOpenAI is None:
            return None
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
        api_key = os.getenv("AZURE_OPENAI_API_KEY", "")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
        api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
        if not endpoint or not api_key or not deployment:
            return None
        return AzureChatOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            azure_deployment=deployment,
            api_version=api_version,
            temperature=0,
        )

    def agent_chat_intent(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        llm = self._llm()
        if llm is None:
            return {
                "intent": "incident_report",
                "incident_id": "",
                "approval_status": "none",
                "response": "Please share incident details or an incident id so I can investigate.",
            }
        prompt = {
            "context": context,
            "message": message,
            "instruction": (
                "Classify user message intent for an SRE incident copilot chat. "
                "intent must be one of: smalltalk, incident_report, approval, clarification. "
                "Extract incident_id if present. approval_status should be approved/rejected/pending/none. "
                "Provide a short conversational response draft."
            ),
        }
        structured = llm.with_structured_output(ChatIntentOutput)
        out = structured.invoke(json.dumps(prompt)).model_dump()
        return out

    def agent_chat_response(self, instruction: str, payload: Dict[str, Any]) -> str:
        llm = self._llm()
        if llm is None:
            return payload.get("fallback", "I can help with incident triage.")
        prompt = {
            "instruction": instruction,
            "payload": payload,
            "style": "concise, SRE assistant, actionable",
        }
        msg = llm.invoke(json.dumps(prompt))
        content = getattr(msg, "content", "")
        if isinstance(content, list):
            content = " ".join(str(x) for x in content)
        return str(content).strip()

    def run(self, incident: Dict[str, Any], config: Dict[str, Any], approval_handler) -> WorkflowResult:
        rid = run_id()
        approval_input = approval_handler({"incident": incident})
        init_state: IncidentState = {
            "run_id": rid,
            "model_name": self.model_name,
            "config": config,
            "incident": incident,
            "approval_input": approval_input,
            "approval": {"required": True, "status": "pending"},
            "errors": [],
        }
        out = self.graph.invoke(init_state, config=self._thread_cfg(rid))
        return WorkflowResult(raw=out)

    def start_and_wait(self, incident: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        rid = run_id()
        state: IncidentState = {
            "run_id": rid,
            "model_name": self.model_name,
            "config": config,
            "incident": incident,
            "classification": self.classify_incident({"run_id": rid, "incident": incident}).get("classification", {}),
            "approval": {"required": True, "status": "pending"},
            "errors": [],
        }
        state.update(self.deterministic_known_issue_check(state))
        state.update(self.fetch_logs(state))
        state.update(self.fetch_metrics(state))
        state.update(self.retrieve_runbooks(state))
        state.update(self.retrieve_historical_incidents(state))
        state.update(self.diagnose(state))
        state.update(self.draft_remediation(state))
        self._save_checkpoint(rid, state)
        return {
            "run_id": rid,
            "status": "waiting_for_approval",
            "approval_request": {
                "message": "Approve ServiceNow create/update for this remediation plan?",
                "remediation": state.get("remediation", {}),
                "options": ["approved", "rejected", "pending"],
            },
        }

    def resume(self, run_id_val: str, approval_decision: Dict[str, Any]) -> WorkflowResult:
        state = self._load_checkpoint(run_id_val)
        if not state:
            raise RuntimeError(f"Run {run_id_val} not found for resume")
        state["approval_input"] = approval_decision
        state.update(self.request_human_approval(state))
        if self._approval_route(state) == "write":
            state.update(self.create_or_update_servicenow(state))
        state.update(self.finalize_report(state))
        self._delete_checkpoint(run_id_val)
        return WorkflowResult(raw=state)

    def _checkpoint_path(self, run_id_val: str):
        return project_root() / ".state" / "checkpoints" / f"{run_id_val}.json"

    def _save_checkpoint(self, run_id_val: str, state: IncidentState) -> None:
        write_json(self._checkpoint_path(run_id_val), state)

    def _load_checkpoint(self, run_id_val: str) -> IncidentState:
        path = self._checkpoint_path(run_id_val)
        if not path.exists():
            return {}
        return read_json(path)

    def _delete_checkpoint(self, run_id_val: str) -> None:
        path = self._checkpoint_path(run_id_val)
        if path.exists():
            path.unlink()

    def classify_incident(self, state: IncidentState) -> IncidentState:
        incident = state["incident"]
        return {
            "classification": {
                "service": incident.get("service", "unknown-service"),
                "severity": str(incident.get("severity", "3")),
                "title": incident.get("title", "Untitled incident"),
            }
        }

    def deterministic_known_issue_check(self, state: IncidentState) -> IncidentState:
        tracer = self._tracer(state)
        llm = self._llm()
        if llm is None:
            text = f"{state['incident'].get('title','')} {state['incident'].get('description','')}".lower()
            for issue in KNOWN_ISSUES.values():
                if any(keyword in text for keyword in issue["keywords"]):
                    return {
                        "deterministic_match": issue,
                        "tool_plan": {
                            "should_use_logs": True,
                            "should_use_metrics": True,
                            "should_use_runbooks": True,
                            "should_use_historical": True,
                        },
                        "diagnosis": {
                            "likely_root_cause": issue["root_cause"],
                            "confidence": issue["confidence"],
                            "path": "deterministic",
                            "evidence": [{"source": "known_issue_rule", "detail": ", ".join(issue["keywords"])}],
                            "needs_clarification": False,
                        },
                    }
            return {
                "deterministic_match": None,
                "tool_plan": {
                    "should_use_logs": True,
                    "should_use_metrics": True,
                    "should_use_runbooks": True,
                    "should_use_historical": True,
                },
            }

        prompt = {
            "incident": state["incident"],
            "classification": state.get("classification", {}),
            "instruction": (
                "You are an incident investigation planner. Decide which tools are needed now "
                "(logs, metrics, runbooks, historical), and whether this is already a deterministic known issue. "
                "If deterministic_known_issue is true, provide likely_root_cause and confidence."
            ),
        }
        structured = llm.with_structured_output(InvestigationPlanOutput)
        plan = structured.invoke(json.dumps(prompt)).model_dump()
        tracer.estimate_model_usage(len(json.dumps(prompt)), len(json.dumps(plan)))

        update: IncidentState = {
            "tool_plan": {
                "should_use_logs": bool(plan.get("should_use_logs", True)),
                "should_use_metrics": bool(plan.get("should_use_metrics", True)),
                "should_use_runbooks": bool(plan.get("should_use_runbooks", True)),
                "should_use_historical": bool(plan.get("should_use_historical", True)),
                "reasoning": plan.get("reasoning", ""),
            }
        }
        if plan.get("deterministic_known_issue") and plan.get("likely_root_cause"):
            update["deterministic_match"] = {
                "root_cause": plan.get("likely_root_cause"),
                "confidence": plan.get("confidence", 0.75),
                "source": "llm_planner",
            }
            update["diagnosis"] = {
                "likely_root_cause": plan.get("likely_root_cause"),
                "confidence": plan.get("confidence", 0.75),
                "path": "deterministic",
                "evidence": [{"source": "llm_planner", "detail": plan.get("reasoning", "known issue match")}],
                "needs_clarification": False,
            }
        else:
            update["deterministic_match"] = None
        return update

    def _should_use(self, state: IncidentState, key: str) -> bool:
        plan = state.get("tool_plan", {})
        return bool(plan.get(key, True))

    def fetch_logs(self, state: IncidentState) -> IncidentState:
        if not self._should_use(state, "should_use_logs"):
            return {"logs": []}
        tracer = self._tracer(state)
        args = FetchLogsInput(
            service=state["classification"]["service"],
            start_time=state["incident"].get("start_time", "1970-01-01T00:00:00Z"),
            end_time=state["incident"].get("end_time", "1970-01-01T00:30:00Z"),
        ).model_dump()
        result, latency = timed_tool_call(self.toolset.fetch_logs, **args)
        tracer.tool_done("fetch_logs", latency, "ok" if result["ok"] else "error", tool_input=args, tool_output=result)
        data = result.get("data") or {}
        return {"logs": data.get("logs", []), "errors": ([] if result["ok"] else [{"tool": "fetch_logs", "error": result.get("error", {})}])}

    def fetch_metrics(self, state: IncidentState) -> IncidentState:
        if not self._should_use(state, "should_use_metrics"):
            return {"metrics": []}
        tracer = self._tracer(state)
        args = FetchMetricsInput(
            service=state["classification"]["service"],
            start_time=state["incident"].get("start_time", "1970-01-01T00:00:00Z"),
            end_time=state["incident"].get("end_time", "1970-01-01T00:30:00Z"),
        ).model_dump()
        result, latency = timed_tool_call(self.toolset.fetch_metrics, **args)
        tracer.tool_done("fetch_metrics", latency, "ok" if result["ok"] else "error", tool_input=args, tool_output=result)
        data = result.get("data") or {}
        return {"metrics": data.get("metrics", []), "errors": ([] if result["ok"] else [{"tool": "fetch_metrics", "error": result.get("error", {})}])}

    def retrieve_runbooks(self, state: IncidentState) -> IncidentState:
        if not self._should_use(state, "should_use_runbooks"):
            return {"runbook_matches": [], "historical_matches": []}
        tracer = self._tracer(state)
        query = f"{state['incident'].get('title','')} {state['incident'].get('description','')}"
        args = SearchRunbooksInput(
            query=query,
            service=state["classification"]["service"],
            severity=state["classification"]["severity"],
            mode=state.get("config", {}).get("retrieval_mode", os.getenv("RETRIEVAL_MODE", "vector")),
        ).model_dump()
        result, latency = timed_tool_call(self.toolset.search_runbooks, **args)
        tracer.tool_done("search_runbooks", latency, "ok" if result["ok"] else "error", tool_input=args, tool_output=result)
        data = result.get("data") or {}
        return {
            "runbook_matches": data.get("runbooks", []),
            "historical_matches": data.get("historical", []),
            "errors": ([] if result["ok"] else [{"tool": "search_runbooks", "error": result.get("error", {})}]),
        }

    def retrieve_historical_incidents(self, state: IncidentState) -> IncidentState:
        if not self._should_use(state, "should_use_historical"):
            return {"historical_matches": state.get("historical_matches", [])}
        return {"historical_matches": state.get("historical_matches", [])}

    def diagnose(self, state: IncidentState) -> IncidentState:
        tracer = self._tracer(state)
        if state.get("diagnosis"):
            return {"diagnosis": state["diagnosis"]}

        llm = self._llm()
        if llm is None:
            diagnosis = {
                "likely_root_cause": "insufficient_context",
                "confidence": 0.3,
                "path": "heuristic_fallback",
                "needs_clarification": True,
                "clarifying_question": "Please share deployment diff, dependency failures, and region impact.",
                "evidence": [{"source": "system", "detail": "Azure OpenAI not configured"}],
            }
            return {"diagnosis": diagnosis}

        prompt = {
            "incident": state["incident"],
            "logs": state.get("logs", [])[:20],
            "metrics": state.get("metrics", [])[:5],
            "runbooks": state.get("runbook_matches", [])[:3],
            "historical": state.get("historical_matches", [])[:3],
            "instruction": "Diagnose likely root cause with confidence and explain evidence.",
        }
        structured = llm.with_structured_output(DiagnosisOutput)
        out = structured.invoke(json.dumps(prompt))
        tracer.estimate_model_usage(len(json.dumps(prompt)), len(json.dumps(out.model_dump())))
        return {"diagnosis": {**out.model_dump(), "path": "llm_reasoning"}}

    def draft_remediation(self, state: IncidentState) -> IncidentState:
        diagnosis = state.get("diagnosis", {})
        llm = self._llm()
        if llm is None:
            remediation = {
                "incident_summary": state["incident"].get("description", ""),
                "likely_root_cause": diagnosis.get("likely_root_cause", "unknown"),
                "confidence": diagnosis.get("confidence", 0.0),
                "evidence": diagnosis.get("evidence", []),
                "recommended_actions": [{"action": "Gather more evidence and apply runbook checks", "risk": "medium", "requires_approval": True}],
            }
        else:
            prompt = {
                "incident": state["incident"],
                "diagnosis": diagnosis,
                "instruction": "Draft a structured remediation plan JSON with recommended actions and risk.",
            }
            structured = llm.with_structured_output(RemediationOutput)
            remediation = structured.invoke(json.dumps(prompt)).model_dump()

        remediation["approval"] = state.get("approval", {"required": True, "status": "pending"})
        remediation["servicenow_update"] = {
            "short_description": state["incident"].get("title", "AI Incident"),
            "severity": str(state["incident"].get("severity", "3")),
            "work_notes": "AI triage summary attached",
            "idempotency_key": state["incident"].get("idempotency_key", f"{state['incident'].get('id','incident')}-create"),
        }
        return {"remediation": remediation}

    def request_human_approval(self, state: IncidentState) -> IncidentState:
        approval_input = state.get("approval_input")
        if approval_input is None:
            approval_input = {"status": "pending", "approved_by": "human_reviewer", "note": "awaiting decision"}

        approval = {
            "required": True,
            "status": approval_input.get("status", "pending"),
            "approved_by": approval_input.get("approved_by", "human_reviewer"),
            "note": approval_input.get("note", ""),
        }
        tracer = self._tracer(state)
        tracer.approval(status=approval["status"], approved_by=approval["approved_by"], note=approval["note"])
        return {"approval": approval}

    def _approval_route(self, state: IncidentState) -> str:
        if state.get("approval", {}).get("status") == "approved":
            return "write"
        return "final"

    def create_or_update_servicenow(self, state: IncidentState) -> IncidentState:
        tracer = self._tracer(state)
        if state.get("approval", {}).get("status") != "approved":
            return {"servicenow": {"status": "skipped", "reason": "approval_not_granted"}}

        sn_payload = state["remediation"]["servicenow_update"]
        work_notes = json.dumps(state["remediation"])

        existing_id = state["incident"].get("servicenow_incident_id")
        if existing_id:
            result, latency = timed_tool_call(
                self.toolset.update_servicenow_incident,
                incident_id=existing_id,
                state="2",
                work_notes=work_notes,
                idempotency_key=f"{sn_payload['idempotency_key']}-update",
            )
            tracer.tool_done(
                "update_servicenow_incident",
                latency,
                "ok" if result["ok"] else "error",
                tool_input={"incident_id": existing_id, "state": "2", "idempotency_key": f"{sn_payload['idempotency_key']}-update"},
                tool_output=result,
            )
        else:
            args = CreateServiceNowIncidentInput(
                title=sn_payload["short_description"],
                description=state["incident"].get("description", ""),
                severity=sn_payload["severity"],
                work_notes=work_notes,
                idempotency_key=sn_payload["idempotency_key"],
            ).model_dump()
            result, latency = timed_tool_call(
                self.toolset.create_servicenow_incident,
                **args,
                simulate_timeout_once=bool(state["incident"].get("simulate_servicenow_timeout", False)),
            )
            tracer.tool_done("create_servicenow_incident", latency, "ok" if result["ok"] else "error", tool_input=args, tool_output=result)

            if not result["ok"] and result.get("error", {}).get("code") == "TIMEOUT":
                retry_result, retry_latency = timed_tool_call(self.toolset.create_servicenow_incident, **args, simulate_timeout_once=False)
                tracer.tool_done("create_servicenow_incident_retry", retry_latency, "ok" if retry_result["ok"] else "error", tool_input=args, tool_output=retry_result)
                result = retry_result

        if result["ok"]:
            return {
                "servicenow": {
                    "status": "success",
                    "incident_id": result["data"].get("incident_id"),
                    "duplicate_prevented": bool(result["data"].get("duplicate_prevented", False)),
                }
            }
        return {"servicenow": {"status": "error", "error": result["error"]}}

    def finalize_report(self, state: IncidentState) -> IncidentState:
        tracer = self._tracer(state)
        outcome = {
            "run_id": state["run_id"],
            "diagnosis": state.get("diagnosis", {}),
            "approval": state.get("approval", {}),
            "servicenow": state.get("servicenow", {}),
            "errors": state.get("errors", []),
            "final_remediation": state.get("remediation", {}),
        }
        outcome["trace_summary_path"] = str(tracer.finalize(outcome))
        return {"outcome": outcome}
