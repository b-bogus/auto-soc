import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Global application settings, loaded from environment or .env file."""
    
    # API Keys
    google_api_key: Optional[str] = None
    
    # Simulation Config
    default_endpoint_count: int = 5
    default_events_per_cycle: int = 50
    default_cycle_duration_minutes: int = 15
    
    # Project Paths
    base_dir: str = str(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    output_dir: str = os.path.join(base_dir, "output")
    
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
