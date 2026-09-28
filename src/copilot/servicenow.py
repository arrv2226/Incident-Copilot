from __future__ import annotations

import json
import os
import urllib.parse
from pathlib import Path
from typing import Any, Dict

import requests

from .utils import project_root, write_json


def _state_path(name: str) -> Path:
    p = project_root() / ".state" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


class ServiceNowClient:
    def __init__(self) -> None:
        self.instance = os.getenv("SERVICENOW_INSTANCE", "")
        self.username = os.getenv("SERVICENOW_USERNAME", "")
        self.password = os.getenv("SERVICENOW_PASSWORD", "")
        self.auth_mode = os.getenv("SERVICENOW_AUTH_MODE", "basic").strip().lower()

        self.oauth_client_id = os.getenv("SERVICENOW_OAUTH_CLIENT_ID", "")
        self.oauth_client_secret = os.getenv("SERVICENOW_OAUTH_CLIENT_SECRET", "")
        self.oauth_username = os.getenv("SERVICENOW_OAUTH_USERNAME", "") or self.username
        self.oauth_password = os.getenv("SERVICENOW_OAUTH_PASSWORD", "") or self.password
        self.oauth_scope = os.getenv("SERVICENOW_OAUTH_SCOPE", "")
        self.oauth_token_url = os.getenv("SERVICENOW_OAUTH_TOKEN_URL", "")
        self.bearer_token_static = os.getenv("SERVICENOW_BEARER_TOKEN", "")
        self._bearer_token_cached = ""
        self._bearer_token_expires_at = 0.0

        self.idem_path = _state_path("idempotency_store.json")
        self._validate_config()

    def _validate_config(self) -> None:
        missing = []
        if not self.instance:
            missing.append("SERVICENOW_INSTANCE")

        if self.auth_mode in {"basic", "url"}:
            if not self.username:
                missing.append("SERVICENOW_USERNAME")
            if not self.password:
                missing.append("SERVICENOW_PASSWORD")

        if self.auth_mode == "oauth":
            if not self.bearer_token_static:
                if not self.oauth_client_id:
                    missing.append("SERVICENOW_OAUTH_CLIENT_ID")
                if not self.oauth_client_secret:
                    missing.append("SERVICENOW_OAUTH_CLIENT_SECRET")
                if not self.oauth_username:
                    missing.append("SERVICENOW_OAUTH_USERNAME or SERVICENOW_USERNAME")
                if not self.oauth_password:
                    missing.append("SERVICENOW_OAUTH_PASSWORD or SERVICENOW_PASSWORD")

        if missing:
            raise RuntimeError(f"Missing required ServiceNow configuration: {', '.join(missing)}")

    def _idem_get(self, key: str) -> Dict[str, Any] | None:
        store = _load_json(self.idem_path, {})
        return store.get(key)

    def _idem_put(self, key: str, value: Dict[str, Any]) -> None:
        store = _load_json(self.idem_path, {})
        store[key] = value
        write_json(self.idem_path, store)

    def _result(self, ok: bool, data: Dict[str, Any] | None = None, code: str = "", message: str = "", retryable: bool = False) -> Dict[str, Any]:
        return {
            "ok": ok,
            "data": data,
            "error": None if ok else {"code": code, "message": message, "retryable": retryable},
        }

    def create_incident(self, title: str, description: str, severity: str, work_notes: str, idempotency_key: str, simulate_timeout_once: bool = False) -> Dict[str, Any]:
        seen = self._idem_get(idempotency_key)
        if seen:
            return self._result(True, {**seen, "duplicate_prevented": True})
        return self._create_incident_real(title, description, severity, work_notes, idempotency_key, simulate_timeout_once=simulate_timeout_once)

    def update_incident(self, incident_id: str, state: str, work_notes: str, idempotency_key: str) -> Dict[str, Any]:
        seen = self._idem_get(idempotency_key)
        if seen:
            return self._result(True, {**seen, "duplicate_prevented": True})
        return self._update_incident_real(incident_id, state, work_notes, idempotency_key)

    def read_incident(self, incident_id: str) -> Dict[str, Any]:
        return self._read_incident_real(incident_id)

    def _oauth_access_token(self) -> str:
        import time

        if self.bearer_token_static:
            return self.bearer_token_static
        if self._bearer_token_cached and time.time() < self._bearer_token_expires_at - 30:
            return self._bearer_token_cached

        token_url = self.oauth_token_url or f"https://{self.instance}/oauth_token.do"
        data = {
            "grant_type": "password",
            "client_id": self.oauth_client_id,
            "client_secret": self.oauth_client_secret,
            "username": self.oauth_username,
            "password": self.oauth_password,
        }
        if self.oauth_scope:
            data["scope"] = self.oauth_scope

        resp = requests.post(token_url, data=data, timeout=20)
        if resp.status_code >= 400:
            raise RuntimeError(f"OAuth token request failed: HTTP {resp.status_code} {resp.text[:180]}")
        payload = resp.json()
        token = payload.get("access_token", "")
        if not token:
            raise RuntimeError(f"OAuth token missing in response: {payload}")

        expires_in = int(payload.get("expires_in", 1800))
        self._bearer_token_cached = token
        self._bearer_token_expires_at = time.time() + max(60, expires_in)
        return token

    def _request(self, method: str, endpoint: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        auth = None

        if self.auth_mode == "url":
            user = urllib.parse.quote(self.username, safe="")
            pwd = urllib.parse.quote(self.password, safe="")
            url = f"https://{user}:{pwd}@{self.instance}{endpoint}"
        elif self.auth_mode == "oauth":
            url = f"https://{self.instance}{endpoint}"
            token = self._oauth_access_token()
            headers["Authorization"] = f"Bearer {token}"
        else:
            url = f"https://{self.instance}{endpoint}"
            auth = (self.username, self.password)

        try:
            resp = requests.request(method=method, url=url, json=payload, headers=headers, auth=auth, timeout=20)
            if resp.status_code >= 400:
                return self._result(False, code=f"HTTP_{resp.status_code}", message=resp.reason, retryable=resp.status_code >= 500)
            data = resp.json()
            return self._result(True, data)
        except Exception as e:  # noqa: BLE001
            return self._result(False, code="REQUEST_FAILED", message=str(e), retryable=True)

    def _create_incident_real(
        self,
        title: str,
        description: str,
        severity: str,
        work_notes: str,
        idempotency_key: str,
        simulate_timeout_once: bool = False,
    ) -> Dict[str, Any]:
        payload = {
            "short_description": title,
            "description": description,
            "urgency": severity,
            "work_notes": work_notes,
        }
        resp = self._request("POST", "/api/now/table/incident", payload)
        if not resp["ok"]:
            return resp
        result = resp["data"].get("result", {})
        out = {"incident_id": result.get("number") or result.get("sys_id"), "operation": "create"}
        self._idem_put(idempotency_key, out)
        if simulate_timeout_once:
            return self._result(False, code="TIMEOUT", message="Simulated timeout after create; retry with same idempotency key", retryable=True)
        return self._result(True, out)

    def _update_incident_real(self, incident_id: str, state: str, work_notes: str, idempotency_key: str) -> Dict[str, Any]:
        payload = {"state": state, "work_notes": work_notes}
        resp = self._request("PATCH", f"/api/now/table/incident/{incident_id}", payload)
        if not resp["ok"]:
            return resp
        out = {"incident_id": incident_id, "operation": "update"}
        self._idem_put(idempotency_key, out)
        return self._result(True, out)

    def _read_incident_real(self, incident_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/now/table/incident/{incident_id}")
