from __future__ import annotations

import secrets

from fastapi.testclient import TestClient

from apps.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["service"] == "ai-incident-copilot"


def test_auth_and_chat_sessions_flow() -> None:
    username = f"test_user_{secrets.token_hex(4)}"
    password = "demo_password_123"

    register = client.post("/api/auth/register", json={"username": username, "password": password})
    assert register.status_code == 200
    token = register.json()["token"]

    unauthorized = client.get("/api/chat/sessions")
    assert unauthorized.status_code == 401

    sessions = client.get("/api/chat/sessions", headers={"Authorization": f"Bearer {token}"})
    assert sessions.status_code == 200
    payload = sessions.json()
    assert "sessions" in payload
    assert isinstance(payload["sessions"], list)
