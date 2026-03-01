from datetime import datetime
from typing import Literal
from pydantic import BaseModel


class IOC(BaseModel):
    id: str
    type: Literal["ipv4", "ipv6", "domain", "url", "sha256", "md5", "email", "cve"]
    value: str
    source: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    tags: list[str] = []
    first_seen: datetime
    last_seen: datetime
    confidence: float
    context: str = ""


class TTP(BaseModel):
    id: str
    mitre_id: str
    name: str
    tactic: str
    description: str
    associated_iocs: list[str] = []
    severity: Literal["critical", "high", "medium", "low"]
    confidence: float


class ThreatIntelReport(BaseModel):
    report_id: str
    generated_at: datetime
    source_feed: str
    raw_item_count: int
    relevant_item_count: int
    iocs: list[IOC]
    ttps: list[TTP]
    summary: str


class RelevanceConfig(BaseModel):
    max_age_days: int = 30
    min_confidence: float = 0.4
    min_severity: Literal["critical", "high", "medium", "low"] = "medium"
    sector_tags: list[str] = ["financial", "banking"]
    excluded_sources: list[str] = []
