import uuid
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field
from auto_soc.models.siem import SIEMEvent


class MitigationAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: Literal[
        "block_ip", "block_domain", "isolate_host",
        "disable_account", "revoke_token",
        "quarantine_file", "patch_vulnerability", "no_action"
    ]
    target: str                      # e.g. "203.0.113.42" or "WKSTN-042"
    executed: bool = False
    executed_at: datetime | None = None
    notes: str = ""


class AnalystReasoning(BaseModel):
    hypothesis: str
    evidence_for: list[str]
    evidence_against: list[str]
    confidence: float = Field(ge=0.0, le=1.0)  # 0.0 – 1.0
    verdict: Literal["true_positive", "false_positive", "benign_true_positive", "inconclusive"]
    recommended_actions: list[MitigationAction] = []


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now())
    updated_at: datetime = Field(default_factory=lambda: datetime.now())
    status: Literal["open", "investigating", "contained", "remediated", "closed"] = "open"
    priority: Literal["P1", "P2", "P3", "P4"] = "P3"
    title: str
    source_alert_id: str             # SIEMAlert.alert_id
    affected_assets: list[str] = []
    analyst_reasoning: AnalystReasoning | None = None
    mitigation_actions: list[MitigationAction] = []
    timeline: list[str] = []
    summary: str = ""
    closed_at: datetime | None = None
