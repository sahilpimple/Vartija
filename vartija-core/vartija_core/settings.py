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
    # Files uploaded from the dashboard (challenge rules, data packs). Kept out of git on purpose.
    upload_dir: Path = field(default_factory=lambda: Path(os.getenv("VARTIJA_UPLOAD_DIR", ROOT / "data")))
    max_upload_mb: int = field(default_factory=lambda: int(os.getenv("VARTIJA_MAX_UPLOAD_MB", "50")))
    # Which sector overlay is active: telecom, energy, maritime, industrial ... (see config/sectors)
    sector: str = field(default_factory=lambda: os.getenv("VARTIJA_SECTOR", "telecom"))
    # LLM backend: "rules" (no model, deterministic), "ollama", or "openai" (any OpenAI-compatible API).
    llm_backend: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM", "rules"))
    llm_model: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM_MODEL", "llama3.1"))
    llm_base_url: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM_BASE_URL", "http://localhost:11434"))
    llm_api_key: str = field(default_factory=lambda: os.getenv("VARTIJA_LLM_API_KEY", ""))
    llm_timeout_seconds: float = field(default_factory=lambda: float(os.getenv("VARTIJA_LLM_TIMEOUT", "60")))
    # Embeddings for VARTIJA_RETRIEVER=hybrid: "none", "ollama" or "openai". Failure falls back to no embeddings.
    embed_backend: str = field(default_factory=lambda: os.getenv("VARTIJA_EMBED", "none"))
    embed_model: str = field(default_factory=lambda: os.getenv("VARTIJA_EMBED_MODEL", "nomic-embed-text"))
    # Auth: "headers" (demo X-User/X-Roles) or "jwt" (HS256 bearer token, e.g. CyberGRC-AI's).
    auth_mode: str = field(default_factory=lambda: os.getenv("VARTIJA_AUTH", "headers"))
    jwt_secret: str = field(default_factory=lambda: os.getenv("VARTIJA_JWT_SECRET", ""))
    jwt_user_claim: str = field(default_factory=lambda: os.getenv("VARTIJA_JWT_USER_CLAIM", "sub"))
    jwt_roles_claim: str = field(default_factory=lambda: os.getenv("VARTIJA_JWT_ROLES_CLAIM", "roles"))
    # Demo helpers (/demo/seed). "auto" = on only while the event secret is the dev default.
    demo_mode: str = field(default_factory=lambda: os.getenv("VARTIJA_DEMO", "auto"))

    @property
    def demo_enabled(self) -> bool:
        if self.demo_mode in {"1", "true", "on"}:
            return True
        if self.demo_mode in {"0", "false", "off"}:
            return False
        return self.event_secret == "dev-only-change-me"


def get_settings() -> Settings:
    return Settings()
