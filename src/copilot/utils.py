from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Dict


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def data_path(name: str) -> Path:
    return project_root() / "data" / name


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def run_id() -> str:
    return f"run-{uuid.uuid4().hex[:10]}"


def load_env_file() -> None:
    env_path = project_root() / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def redact_sensitive(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    sensitive = {"password", "token", "authorization", "servicenow_password"}
    for k, v in payload.items():
        if k.lower() in sensitive:
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out
