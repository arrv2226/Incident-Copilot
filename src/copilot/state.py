from __future__ import annotations

from typing import Any, Dict, TypedDict


class WorkflowState(TypedDict, total=False):
    run_id: str
    model_name: str
    config: Dict[str, Any]
    incident: Dict[str, Any]
    classification: Dict[str, Any]
    deterministic_match: Dict[str, Any] | None
    logs: list[Dict[str, Any]]
    metrics: list[Dict[str, Any]]
    runbook_matches: list[Dict[str, Any]]
    historical_matches: list[Dict[str, Any]]
    diagnosis: Dict[str, Any]
    remediation: Dict[str, Any]
    approval: Dict[str, Any]
    approval_input: Dict[str, Any]
    tool_plan: Dict[str, Any]
    servicenow: Dict[str, Any]
    errors: list[Dict[str, Any]]
    outcome: Dict[str, Any]
