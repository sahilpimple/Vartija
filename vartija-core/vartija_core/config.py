"""Loads the swappable YAML configuration: regimes, sectors, policy, conflicts.

Re-skinning for a new challenge = editing these files, not the Python code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Deadline:
    stage: str
    label: str
    anchor: str
    hours: float


@dataclass(frozen=True)
class Regime:
    id: str
    name: str
    authority: str
    applies_when_flag: str
    deadlines: tuple[Deadline, ...]
    report_templates: dict[str, list[dict[str, Any]]]
    corpus_tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Sector:
    id: str
    name: str
    entity_class: str
    regimes: tuple[str, ...]
    supervisor: str
    org: dict[str, Any]
    significance_hints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Config:
    regimes: dict[str, Regime]
    sectors: dict[str, Sector]
    policy: dict[str, Any]
    conflicts: list[dict[str, Any]]

    def sector(self, sector_id: str) -> Sector:
        try:
            return self.sectors[sector_id]
        except KeyError as exc:
            raise ConfigError(f"unknown sector '{sector_id}'; known: {sorted(self.sectors)}") from exc

    def regimes_for(self, sector_id: str) -> list[Regime]:
        return [self.regimes[r] for r in self.sector(sector_id).regimes]


def _read(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_config(config_dir: Path) -> Config:
    config_dir = Path(config_dir)
    regimes: dict[str, Regime] = {}
    for path in sorted((config_dir / "regimes").glob("*.yaml")):
        raw = _read(path)
        deadlines = tuple(Deadline(**d) for d in raw["deadlines"])
        regimes[raw["id"]] = Regime(
            id=raw["id"], name=raw["name"], authority=raw["authority"],
            applies_when_flag=raw["applies_when_flag"], deadlines=deadlines,
            report_templates=raw.get("report_templates", {}),
            corpus_tags=tuple(raw.get("corpus_tags", [])),
        )

    sectors: dict[str, Sector] = {}
    for path in sorted((config_dir / "sectors").glob("*.yaml")):
        raw = _read(path)
        unknown = [r for r in raw["regimes"] if r not in regimes]
        if unknown:
            raise ConfigError(f"{path.name}: unknown regimes {unknown}")
        sectors[raw["id"]] = Sector(
            id=raw["id"], name=raw["name"], entity_class=raw["entity_class"],
            regimes=tuple(raw["regimes"]), supervisor=raw["supervisor"], org=raw.get("org", {}),
            significance_hints=raw.get("significance_hints", {}),
        )

    policy = _read(config_dir / "policy.yaml")
    conflicts = _read(config_dir / "conflicts.yaml").get("conflicts", [])
    return Config(regimes=regimes, sectors=sectors, policy=policy, conflicts=conflicts)


@lru_cache(maxsize=8)
def cached_config(config_dir: str) -> Config:
    return load_config(Path(config_dir))
