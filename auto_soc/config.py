import os
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")


class Settings(BaseSettings):
    """Global application settings, loaded from environment or .env file."""

    # Ollama (local LLM)
    ollama_host: str = "http://192.168.0.81:11434/v1"
    ollama_model: str = "qwen2.5:32b"

    # Simulation Config
    default_endpoint_count: int = 5
    default_events_per_cycle: int = 50
    default_cycle_duration_minutes: int = 15

    # Project Paths
    base_dir: str = str(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    output_dir: str = os.path.join(base_dir, "output")

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

# PydanticAI's OllamaProvider reads OLLAMA_BASE_URL from os.environ.
# Set it here so all agent modules pick it up at import time.
os.environ["OLLAMA_BASE_URL"] = settings.ollama_host
