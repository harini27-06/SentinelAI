from datetime import datetime
from math import isfinite
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    id: str | None = Field(default=None, min_length=1, max_length=150)
    event_id: str | None = Field(default=None, min_length=1, max_length=150)
    timestamp: datetime | None = None
    endpoint_id: str = Field(min_length=1, max_length=100)
    agent_type: str = Field(min_length=1, max_length=64)
    event_type: str = Field(default="telemetry", max_length=100)
    source: str = Field(default="api", max_length=64)
    scenario: str | None = Field(default=None, max_length=100)
    severity: str = Field(default="info", max_length=16)
    label: int | None = Field(default=None, ge=0, le=1)
    attack_cat: str | None = Field(default=None, max_length=100)
    synthetic: bool = False
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value):
        forbidden_keys = {"password", "passwd", "secret", "token", "authorization", "api_key", "credential"}
        count = 0

        def validate(item, depth=0):
            nonlocal count
            count += 1
            if count > 10000 or depth > 12:
                raise ValueError("payload is too large or deeply nested")
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str) or key.lower() in forbidden_keys:
                        raise ValueError("payload contains an unsupported or sensitive field")
                    validate(child, depth + 1)
            elif isinstance(item, list):
                if len(item) > 1000:
                    raise ValueError("payload arrays cannot contain more than 1000 items")
                for child in item:
                    validate(child, depth + 1)
            elif isinstance(item, float) and not isfinite(item):
                raise ValueError("payload numbers must be finite")
            elif item is not None and not isinstance(item, (str, int, float, bool)):
                raise ValueError("payload must contain JSON-compatible values")

        validate(value)
        return value

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, value):
        value = value.lower()
        if value not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("severity must be info, low, medium, high, or critical")
        return value

    def normalized_payload(self):
        data = self.model_dump(exclude={"id", "event_id", "timestamp", "endpoint_id", "agent_type",
                                        "event_type", "source", "scenario", "severity", "label",
                                        "attack_cat", "synthetic", "payload"})
        return {**data, **self.payload}


class FeedbackCreate(BaseModel):
    verdict: Literal["true_positive", "false_positive", "benign", "malicious"]
    notes: str | None = Field(default=None, max_length=2000)


class AgentRegistration(BaseModel):
    agent_id: str | None = Field(default=None, min_length=1, max_length=100)
    agent_type: str = Field(min_length=1, max_length=64)
    endpoint_id: str | None = Field(default=None, min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)


class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "investigating", "resolved", "false_positive", "confirmed"]


class FeedbackRequest(FeedbackCreate):
    alert_id: int = Field(gt=0)


class SettingsUpdate(BaseModel):
    failed_login_threshold: int | None = Field(default=None, ge=1, le=1000)
    login_frequency_threshold: int | None = Field(default=None, ge=1, le=10000)
    unauthorized_request_threshold: int | None = Field(default=None, ge=1, le=10000)
    correlation_window_minutes: int | None = Field(default=None, ge=1, le=120)
    api_requests_per_minute: int | None = Field(default=None, ge=1, le=10000)
    file_modifications: int | None = Field(default=None, ge=1, le=10000)
    network_unique_ports: int | None = Field(default=None, ge=1, le=65535)
    dos_rate_threshold: int | None = Field(default=None, ge=1, le=1000000000)
    system_resource_threshold: int | None = Field(default=None, ge=1, le=100)
    default_simulation_event_count: int | None = Field(default=None, ge=1, le=100)


class SimulationRequest(BaseModel):
    scenario: Literal[
        "normal_login", "brute_force_login", "normal_network", "dos_spike", "api_burst",
        "file_burst", "system_activity", "novel_combination",
    ]
    endpoint_id: str | None = Field(default=None, min_length=1, max_length=100)
    agent_type: Literal[
        "login_agent", "network_agent", "file_agent", "api_agent", "system_agent", "correlation_agent",
    ]
    event_count: int = Field(default=12, ge=1, le=100)
    parameters: dict[str, int | float | str | bool] = Field(default_factory=dict)

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, value):
        bounds = {
            "failure_count": (1, 1000),
            "unauthorized_requests": (1, 1000),
            "request_rate": (1, 10000),
            "modification_count": (1, 1000),
            "dos_rate": (1, 1000000000),
            "cpu_percent": (1, 100),
            "memory_percent": (1, 100),
        }
        unknown = set(value) - set(bounds)
        if unknown:
            raise ValueError(f"Unsupported simulation parameters: {', '.join(sorted(unknown))}")
        for key, raw in value.items():
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ValueError(f"{key} must be a number")
            lower, upper = bounds[key]
            if not lower <= raw <= upper:
                raise ValueError(f"{key} must be between {lower} and {upper}")
        return value


class SimulationCreate(BaseModel):
    scenario: Literal["login_attack", "network_scan", "file_tampering", "api_abuse", "system_anomaly",
                      "correlated_activity"]
    endpoint_id: str = Field(default="SIMULATED-ENDPOINT", max_length=100)
    count: int = Field(default=1, ge=1, le=100)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    timestamp: datetime
    endpoint_id: str
    agent_type: str
    event_type: str
    source: str
    scenario: str | None
    severity: str
    label: int | None
    attack_cat: str | None
    payload: dict[str, Any]
    synthetic: bool
