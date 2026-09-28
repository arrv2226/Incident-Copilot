from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class TokenStore:
    ttl_seconds: int

    def __post_init__(self) -> None:
        self._tokens: Dict[str, Dict[str, Any]] = {}

    def issue(self, user_id: int, username: str) -> Dict[str, Any]:
        token = uuid.uuid4().hex
        self._tokens[token] = {
            "user_id": user_id,
            "username": username,
            "expires_at": time.time() + self.ttl_seconds,
        }
        return {"token": token, "user": {"id": user_id, "username": username}}

    def resolve(self, token: str) -> Dict[str, Any] | None:
        payload = self._tokens.get(token)
        if not payload:
            return None
        expires_at = float(payload.get("expires_at", 0))
        if expires_at and time.time() > expires_at:
            self._tokens.pop(token, None)
            return None
        return payload
