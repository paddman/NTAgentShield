from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def default_rules_path() -> Path:
    repository_rules = Path(__file__).resolve().parents[2] / "rules" / "behavioral"
    if repository_rules.exists():
        return repository_rules
    return Path(__file__).resolve().parent / "rules" / "behavioral"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NTSHIELD_",
        env_file=".env",
        extra="ignore",
    )

    database_path: Path = Path("./data/ntshield.db")
    rules_path: Path = Field(default_factory=default_rules_path)
    incident_window_seconds: int = 1800
    anomaly_finding_threshold: float = 85.0
    baseline_warmup_events: int = 30
    max_raw_field_chars: int = 2048

    qwen_base_url: str = "http://127.0.0.1:8000/v1"
    qwen_api_key: str = "EMPTY"
    qwen_model: str = "Qwen/Qwen3.5-9B"
    qwen_enabled: bool = True
    qwen_timeout_seconds: float = 120.0
    qwen_max_output_tokens: int = 4096
    qwen_temperature: float = 0.2

    enrollment_enabled: bool = False
    enrollment_signing_secret: str = ""
    enrollment_ca_cert_path: Path = Path("./data/pki/enrollment-ca.crt")
    enrollment_ca_key_path: Path = Path("./data/pki/enrollment-ca.key")
    enrollment_client_cert_ttl_hours: int = 720

    dashboard_title: str = "NTAgentShield Behavioral Zero-Day Hunting"
    allowed_origins: list[str] = Field(default_factory=lambda: ["*"])
