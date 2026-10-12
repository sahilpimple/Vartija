"""Runtime settings, read from environment variables.

Every value has a safe demo default so ``python scripts/demo.py`` works with no setup.
Change secrets before anything leaves a laptop.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("VARTIJA_DATABASE_URL", "sqlite:///./vartija.db"))
    # Shared secret between ARCC-X and this service for HMAC-signed events.
    event_secret: str = field(default_factory=lambda: os.getenv("VARTIJA_EVENT_SECRET", "dev-only-change-me"))
    # Reject signed events whose timestamp is further than this from now (replay protection).
    max_clock_skew_seconds: int = field(default_factory=lambda: int(os.getenv("VARTIJA_MAX_SKEW", "300")))
    config_dir: Path = field(default_factory=lambda: Path(os.getenv("VARTIJA_CONFIG_DIR", ROOT / "config")))
    corpus_dir: Path = field(default_factory=lambda: Path(os.getenv("VARTIJA_CORPUS_DIR", ROOT / "corpus")))
    seed_dir: Path = field(default_factory=lambda: Path(os.getenv("VARTIJA_SEED_DIR", ROOT / "seed")))
    # Which sector overlay is active: telecom, energy, maritime, industrial ... (see config/sectors)
    sector: str = field(default_factory=lambda: os.getenv("VARTIJA_SECTOR", "telecom"))
    # LLM backend: "rules" (no model, deterministic), "ollama", or "openai" (any OpenAI-compatible API).
    llm_backend: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM", "rules"))
    llm_model: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM_MODEL", "llama3.1"))
    llm_base_url: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM_BASE_URL", "http://localhost:11434"))
    llm_api_key: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM_API_KEY", ""))
    llm_timeout_seconds: float = field(default_factory=lambda: float(os.getenv("VARTIJA_LLM_TIMEOUT", "60")))


def get_settings() -> Settings:
    return Settings()
