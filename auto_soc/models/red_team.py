import uuid
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field
from auto_soc.models.siem import SIEMEvent


class AttackPhase(BaseModel):
    phase_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    order: int
    mitre_id: str                    # e.g. "T1566.001"
    description: str
    target_endpoint: str             # Hostname from SystemEmulator
    generated_events: list[dict] = []   # raw dicts; full SIEMEvents are in the SIEM
    delay_seconds: int = 60


class AttackScenario(BaseModel):
    scenario_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target_ttps: list[str] = []      # TTP.mitre_id values
    target_iocs: list[str] = []      # IOC.id values to embed
    phases: list[AttackPhase] = []
    created_at: datetime = Field(default_factory=datetime.now)


class RedTeamConfig(BaseModel):
    difficulty: Literal["easy", "medium", "hard"] = "medium"
    max_phases: int = 5
    noise_ratio: float = 5.0         # benign events per attack event
