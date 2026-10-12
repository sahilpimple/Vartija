"""Governance context provider: the seam between Vartija and CyberGRC-AI.

Vartija asks one question: "what do we know about this asset?" The default provider
reads ``seed/grc.yaml`` so the demo runs standalone. To use CyberGRC-AI, implement
``GrcContextProvider`` with your SQLAlchemy models (or an HTTP call to its API) and
pass it to ``create_app(grc_provider=...)``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import yaml


class GrcContextProvider(Protocol):
    def context_for(self, asset_id: str | None) -> dict:
        """Return {"asset": {...}, "owner": {...}, "risks": [...], "controls": [...], "findings": [...]}."""
        ...


class YamlGrcProvider:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._data = yaml.safe_load(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    def context_for(self, asset_id: str | None) -> dict:
        assets = self._data.get("assets", {})
        asset = assets.get(asset_id or "", {})
        if not asset:
            return {"asset": {"id": asset_id, "known": False}, "owner": None, "risks": [], "controls": [],
                    "findings": []}
        risks = [r for r in self._data.get("risks", []) if asset_id in r.get("assets", [])]
        control_ids = {c for r in risks for c in r.get("controls", [])}
        controls = [c for c in self._data.get("controls", []) if c["id"] in control_ids]
        findings = [f for f in self._data.get("findings", []) if f.get("asset") == asset_id]
        return {"asset": {"id": asset_id, "known": True, **{k: v for k, v in asset.items() if k != "owner"}},
                "owner": asset.get("owner"), "risks": risks, "controls": controls, "findings": findings}


# --- Example adapter for CyberGRC-AI (fill in with your real model names) -------------
#
# class CyberGrcDbProvider:
#     def __init__(self, session_factory):
#         self.session_factory = session_factory
#
#     def context_for(self, asset_id):
#         with self.session_factory() as s:
#             asset = s.get(Asset, asset_id)
#             risks = s.scalars(select(Risk).where(Risk.asset_id == asset_id)).all()
#             ...
#             return {"asset": {...}, "owner": {...}, "risks": [...], "controls": [...], "findings": [...]}
