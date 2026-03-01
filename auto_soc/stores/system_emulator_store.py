from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel
from auto_soc.models.system_emulator import WindowsEndpoint, SystemEmulatorConfig
from auto_soc.models.siem import SIEMEvent

class SystemEmulatorStore(BaseModel):
    """Data store holding the live state of all emulated endpoints."""
    endpoints: dict[str, WindowsEndpoint] = {}
    generated_events: list[SIEMEvent] = []
    current_time: datetime = datetime.now(timezone.utc)
    cycle_count: int = 0

    def get_endpoint(self, hostname: str) -> Optional[WindowsEndpoint]:
        return self.endpoints.get(hostname)

    def add_event(self, event: SIEMEvent):
        self.generated_events.append(event)
