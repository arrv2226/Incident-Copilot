from __future__ import annotations

from typing import Dict

from pydantic import BaseModel, Field


class SearchRunbooksInput(BaseModel):
    query: str = Field(min_length=3)
    service: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    mode: str = Field(default="vector", pattern="^(vector|manifest_vector)$")


class FetchLogsInput(BaseModel):
    service: str = Field(min_length=1)
    start_time: str = Field(min_length=1)
    end_time: str = Field(min_length=1)


class FetchMetricsInput(BaseModel):
    service: str = Field(min_length=1)
    start_time: str = Field(min_length=1)
    end_time: str = Field(min_length=1)


class CreateServiceNowIncidentInput(BaseModel):
    title: str = Field(min_length=3)
    description: str = Field(min_length=5)
    severity: str = Field(min_length=1)
    work_notes: str = Field(min_length=5)
    idempotency_key: str = Field(min_length=5)


class UpdateServiceNowIncidentInput(BaseModel):
    incident_id: str = Field(min_length=2)
    state: str = Field(min_length=1)
    work_notes: str = Field(min_length=5)
    idempotency_key: str = Field(min_length=5)


TOOL_REGISTRY: Dict[str, Dict] = {
    "search_runbooks": {
        "write": False,
        "input_schema": {
            "type": "object",
            "required": ["query", "service", "severity", "mode"],
            "properties": {
                "query": {"type": "string"},
                "service": {"type": "string"},
                "severity": {"type": "string"},
                "mode": {"type": "string", "enum": ["vector", "manifest_vector"]},
            },
        },
    },
    "fetch_logs": {
        "write": False,
        "input_schema": {
            "type": "object",
            "required": ["service", "start_time", "end_time"],
            "properties": {
                "service": {"type": "string"},
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
            },
        },
    },
    "fetch_metrics": {
        "write": False,
        "input_schema": {
            "type": "object",
            "required": ["service", "start_time", "end_time"],
            "properties": {
                "service": {"type": "string"},
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
            },
        },
    },
    "create_servicenow_incident": {
        "write": True,
        "input_schema": {
            "type": "object",
            "required": ["title", "description", "severity", "work_notes", "idempotency_key"],
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "severity": {"type": "string"},
                "work_notes": {"type": "string"},
                "idempotency_key": {"type": "string"},
            },
        },
    },
    "update_servicenow_incident": {
        "write": True,
        "input_schema": {
            "type": "object",
            "required": ["incident_id", "state", "work_notes", "idempotency_key"],
            "properties": {
                "incident_id": {"type": "string"},
                "state": {"type": "string"},
                "work_notes": {"type": "string"},
                "idempotency_key": {"type": "string"},
            },
        },
    },
}
