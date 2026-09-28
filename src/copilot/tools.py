from __future__ import annotations

import time
from typing import Any, Dict

from .live_clients import LiveSources
from .retrieval import Retriever
from .servicenow import ServiceNowClient


def _result(ok: bool, data: Dict[str, Any] | None = None, code: str = "", message: str = "", retryable: bool = False) -> Dict[str, Any]:
    return {
        "ok": ok,
        "data": data,
        "error": None if ok else {"code": code, "message": message, "retryable": retryable},
    }


class Toolset:
    def __init__(self) -> None:
        self.sources = LiveSources()
        self.retriever = Retriever()
        self.sn = ServiceNowClient()

    def validate_live_config(self) -> Dict[str, Any]:
        missing = self.sources.required_env()
        if missing:
            return _result(False, code="CONFIG_ERROR", message=f"Missing required environment variables: {', '.join(sorted(set(missing)))}", retryable=False)
        return _result(True, {"validated": True})

    def fetch_logs(self, service: str, start_time: str, end_time: str) -> Dict[str, Any]:
        return self.sources.fetch_logs(service=service, start_time=start_time, end_time=end_time)

    def fetch_metrics(self, service: str, start_time: str, end_time: str) -> Dict[str, Any]:
        return self.sources.fetch_metrics(service=service, start_time=start_time, end_time=end_time)

    def search_runbooks(self, query: str, service: str, severity: str, mode: str) -> Dict[str, Any]:
        runbooks = self.retriever.search_runbooks(query=query, service=service, severity=severity, mode=mode)
        historical = self.retriever.search_historical(query=query, service=service, severity=severity, mode=mode)
        return _result(True, {"runbooks": runbooks, "historical": historical})

    def create_servicenow_incident(
        self,
        title: str,
        description: str,
        severity: str,
        work_notes: str,
        idempotency_key: str,
        simulate_timeout_once: bool = False,
    ) -> Dict[str, Any]:
        return self.sn.create_incident(
            title=title,
            description=description,
            severity=severity,
            work_notes=work_notes,
            idempotency_key=idempotency_key,
            simulate_timeout_once=simulate_timeout_once,
        )

    def update_servicenow_incident(self, incident_id: str, state: str, work_notes: str, idempotency_key: str) -> Dict[str, Any]:
        return self.sn.update_incident(incident_id=incident_id, state=state, work_notes=work_notes, idempotency_key=idempotency_key)

    def read_servicenow_incident(self, incident_id: str) -> Dict[str, Any]:
        return self.sn.read_incident(incident_id)


def timed_tool_call(fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return result, elapsed_ms
