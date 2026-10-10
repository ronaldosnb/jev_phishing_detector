"""Configuracao lida de variaveis de ambiente (.env)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    jev_api_key: str
    jev_base_url: str
    jev_model: str
    phishing_threshold: float
    poll_interval_seconds: int
    data_dir: Path
    quarantine_label: str
    google_client_secrets: Path
    ms_client_id: str
    ms_tenant: str

    @property
    def db_path(self) -> Path:
        return self.data_dir / "detector.sqlite3"

    @property
    def google_token_path(self) -> Path:
        return self.data_dir / "google_token.json"

    @property
    def ms_token_cache_path(self) -> Path:
        return self.data_dir / "ms_token_cache.json"


def load_settings() -> Settings:
    load_dotenv()
    env = os.environ.get
    data_dir = Path(env("DATA_DIR", "./data")).expanduser()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return Settings(
        jev_api_key=env("JEV_API_KEY", ""),
        jev_base_url=env("JEV_BASE_URL", "https://api.typesafe.ai/v1").rstrip("/"),
        jev_model=env("JEV_MODEL", "jev-latest"),
        phishing_threshold=float(env("PHISHING_THRESHOLD", "0.7")),
        poll_interval_seconds=int(env("POLL_INTERVAL_SECONDS", "60")),
        data_dir=data_dir,
        quarantine_label=env("QUARANTINE_LABEL", "Suspeita de Phishing"),
        google_client_secrets=Path(env("GOOGLE_CLIENT_SECRETS", "./credentials.json")).expanduser(),
        ms_client_id=env("MS_CLIENT_ID", ""),
        ms_tenant=env("MS_TENANT", "common"),
    )
