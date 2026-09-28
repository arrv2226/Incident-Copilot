from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

from .utils import project_root, redact_sensitive


class Tracer:
    def __init__(self, run_id: str, model_name: str) -> None:
        self.run_id = run_id
        self.model_name = model_name
        self.trace_dir = project_root() / "traces"
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.trace_dir / f"{run_id}.jsonl"
        self.summary: Dict[str, Any] = {
            "run_id": run_id,
            "model_name": model_name,
            "nodes": [],
            "tools": [],
            "approvals": [],
            "total_latency_ms": 0,
            "estimated_tokens": 0,
            "estimated_cost_usd": 0.0,
        }

    def event(self, kind: str, payload: Dict[str, Any]) -> None:
        record = {
            "ts": time.time(),
            "run_id": self.run_id,
            "kind": kind,
            "payload": redact_sensitive(payload),
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def node_done(self, node: str, latency_ms: float, status: str) -> None:
        self.summary["nodes"].append({"node": node, "latency_ms": round(latency_ms, 2), "status": status})
        self.summary["total_latency_ms"] += latency_ms
        self.event("node", {"node": node, "latency_ms": latency_ms, "status": status})

    def tool_done(
        self,
        name: str,
        latency_ms: float,
        status: str,
        tool_input: Dict[str, Any] | None = None,
        tool_output: Dict[str, Any] | None = None,
    ) -> None:
        record = {
            "tool": name,
            "latency_ms": round(latency_ms, 2),
            "status": status,
            "input": tool_input or {},
            "output": tool_output or {},
        }
        self.summary["tools"].append(record)
        self.event("tool", {"tool": name, "latency_ms": latency_ms, "status": status, "input": tool_input or {}, "output": tool_output or {}})

    def approval(self, status: str, approved_by: str, note: str = "") -> None:
        payload = {"status": status, "approved_by": approved_by, "note": note}
        self.summary["approvals"].append(payload)
        self.event("approval", payload)

    def estimate_model_usage(self, input_text_len: int, output_text_len: int) -> None:
        tokens = int((input_text_len + output_text_len) / 4)
        cost = tokens * 0.000002
        self.summary["estimated_tokens"] += tokens
        self.summary["estimated_cost_usd"] += round(cost, 6)

    def finalize(self, outcome: Dict[str, Any]) -> Path:
        self.summary["total_latency_ms"] = round(self.summary["total_latency_ms"], 2)
        self.summary["estimated_cost_usd"] = round(self.summary["estimated_cost_usd"], 6)
        self.summary["outcome"] = outcome
        out = self.trace_dir / f"{self.run_id}.summary.json"
        with out.open("w", encoding="utf-8") as f:
            json.dump(self.summary, f, indent=2)
        return out
