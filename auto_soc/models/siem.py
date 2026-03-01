import uuid
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


class SIEMEvent(BaseModel):
    """A single log event ingested by the SIEM."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source_system: Literal[
        "firewall", "edr", "proxy",
        "dns", "auth", "email_gateway", "red_team"
    ]
    severity: Literal["critical", "high", "medium", "low", "info"]
    raw_log: str
    parsed_fields: dict[str, Any] = {}
    matched_ioc_ids: list[str] = []
    matched_ttp_ids: list[str] = []


class CorrelationRule(BaseModel):
    """A detection rule run against the event store."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    mitre_ids: list[str] = []
    match_logic: Literal["ioc_match", "ttp_pattern", "threshold", "compound"]
    match_config: dict[str, Any] = {}
    severity: Literal["critical", "high", "medium", "low"]
    enabled: bool = True


class SIEMAlert(BaseModel):
    """An alert fired by a correlation rule."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    triggered_at: datetime
    rule: CorrelationRule
    matched_events: list[str] = []
    matched_iocs: list[str] = []
    matched_ttps: list[str] = []
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["new", "acknowledged", "investigating", "closed"] = "new"
    summary: str = ""
