from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List


def _result(ok: bool, data: Dict[str, Any] | None = None, code: str = "", message: str = "", retryable: bool = False) -> Dict[str, Any]:
    return {
        "ok": ok,
        "data": data,
        "error": None if ok else {"code": code, "message": message, "retryable": retryable},
    }


class LiveAPIClient:
    def __init__(self) -> None:
        self.auth_type = os.getenv("API_AUTH_TYPE", "none").strip().lower()
        self.bearer_token = os.getenv("API_BEARER_TOKEN", "")
        self.basic_username = os.getenv("API_BASIC_USERNAME", "")
        self.basic_password = os.getenv("API_BASIC_PASSWORD", "")

    def _auth_header(self) -> Dict[str, str]:
        if self.auth_type == "bearer":
            if not self.bearer_token:
                raise RuntimeError("API_BEARER_TOKEN is required when API_AUTH_TYPE=bearer")
            return {"Authorization": f"Bearer {self.bearer_token}"}
        if self.auth_type == "basic":
            if not self.basic_username or not self.basic_password:
                raise RuntimeError("API_BASIC_USERNAME and API_BASIC_PASSWORD are required when API_AUTH_TYPE=basic")
            raw = f"{self.basic_username}:{self.basic_password}".encode("utf-8")
            return {"Authorization": f"Basic {base64.b64encode(raw).decode('utf-8')}"}
        return {}

    def get_json(self, base_url: str, query: Dict[str, Any]) -> Dict[str, Any]:
        if not base_url:
            return _result(False, code="CONFIG_ERROR", message="Missing API URL", retryable=False)
        try:
            qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
            url = f"{base_url}?{qs}" if qs else base_url
            req = urllib.request.Request(url=url, method="GET")
            req.add_header("Accept", "application/json")
            for key, val in self._auth_header().items():
                req.add_header(key, val)
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return _result(True, {"payload": payload})
        except Exception as exc:  # noqa: BLE001
            return _result(False, code="HTTP_REQUEST_FAILED", message=str(exc), retryable=True)


class LiveSources:
    def __init__(self) -> None:
        self.client = LiveAPIClient()
        self.incidents_url = os.getenv("INCIDENTS_API_URL", "")
        self.logs_url = os.getenv("LOGS_API_URL", "")
        self.metrics_url = os.getenv("METRICS_API_URL", "")
        self.runbooks_url = os.getenv("RUNBOOKS_API_URL", "")
        self.historical_url = os.getenv("HISTORICAL_INCIDENTS_API_URL", "")
        self.manifest_url = os.getenv("MANIFEST_API_URL", "")

    def required_env(self) -> List[str]:
        required = [
            "INCIDENTS_API_URL",
            "LOGS_API_URL",
            "METRICS_API_URL",
            "RUNBOOKS_API_URL",
            "HISTORICAL_INCIDENTS_API_URL",
            "MANIFEST_API_URL",
        ]
        missing = [name for name in required if not os.getenv(name)]
        auth_type = os.getenv("API_AUTH_TYPE", "none").strip().lower()
        if auth_type == "bearer" and not os.getenv("API_BEARER_TOKEN"):
            missing.append("API_BEARER_TOKEN")
        if auth_type == "basic":
            if not os.getenv("API_BASIC_USERNAME"):
                missing.append("API_BASIC_USERNAME")
            if not os.getenv("API_BASIC_PASSWORD"):
                missing.append("API_BASIC_PASSWORD")
        return missing

    @staticmethod
    def _extract_list(payload: Any, key: str) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            if key in payload and isinstance(payload[key], list):
                return payload[key]
            if "result" in payload and isinstance(payload["result"], list):
                return payload["result"]
            if "items" in payload and isinstance(payload["items"], list):
                return payload["items"]
        return []

    @staticmethod
    def _extract_object(payload: Any, key: str) -> Dict[str, Any]:
        if isinstance(payload, dict):
            if key in payload and isinstance(payload[key], dict):
                return payload[key]
            if "result" in payload and isinstance(payload["result"], dict):
                return payload["result"]
            return payload
        return {}

    def fetch_incident(self, incident_id: str) -> Dict[str, Any]:
        raw = self.client.get_json(self.incidents_url, {"incident_id": incident_id})
        if not raw["ok"]:
            return raw
        payload = raw["data"]["payload"]
        if isinstance(payload, list):
            if not payload:
                return _result(False, code="NOT_FOUND", message=f"Incident {incident_id} not found", retryable=False)
            return _result(True, {"incident": payload[0]})
        incident = self._extract_object(payload, "incident")
        if not incident:
            return _result(False, code="NOT_FOUND", message=f"Incident {incident_id} not found", retryable=False)
        return _result(True, {"incident": incident})

    def fetch_logs(self, service: str, start_time: str, end_time: str) -> Dict[str, Any]:
        raw = self.client.get_json(self.logs_url, {"service": service, "start_time": start_time, "end_time": end_time})
        if not raw["ok"]:
            return raw
        logs = self._extract_list(raw["data"]["payload"], "logs")
        return _result(True, {"logs": logs})

    def fetch_metrics(self, service: str, start_time: str, end_time: str) -> Dict[str, Any]:
        raw = self.client.get_json(self.metrics_url, {"service": service, "start_time": start_time, "end_time": end_time})
        if not raw["ok"]:
            return raw
        metrics = self._extract_list(raw["data"]["payload"], "metrics")
        return _result(True, {"metrics": metrics})

    def fetch_runbooks(self, service: str, severity: str, query: str) -> Dict[str, Any]:
        raw = self.client.get_json(self.runbooks_url, {"service": service, "severity": severity, "query": query})
        if not raw["ok"]:
            return raw
        runbooks = self._extract_list(raw["data"]["payload"], "runbooks")
        return _result(True, {"runbooks": runbooks})

    def fetch_historical(self, service: str, severity: str, query: str) -> Dict[str, Any]:
        raw = self.client.get_json(self.historical_url, {"service": service, "severity": severity, "query": query})
        if not raw["ok"]:
            return raw
        historical = self._extract_list(raw["data"]["payload"], "historical")
        return _result(True, {"historical": historical})

    def fetch_manifest(self) -> Dict[str, Any]:
        raw = self.client.get_json(self.manifest_url, {})
        if not raw["ok"]:
            return raw
        manifest = self._extract_object(raw["data"]["payload"], "manifest")
        return _result(True, {"manifest": manifest})
