"""Deterministic checks of numeric requirements: "not less than 60 min" vs "45 min".

Language models are unreliable at comparing numbers with units, so the model's job is to
*extract* the requirement and the actual value as text; the comparison happens here, in
code, with unit conversion and a readable explanation.

    check_requirement("not less than 1.5 m", "1200 mm")
    -> Check(ok=False, message="1200 mm (1.2 m) does not meet >= 1.5 m")

No dependencies. Units cover common engineering, safety and operations quantities;
extend ``UNITS`` for new domains. Temperatures are compared only in the same unit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# unit -> (dimension, factor to the dimension's base unit)
UNITS: dict[str, tuple[str, float]] = {
    # length
    "mm": ("length", 1e-3), "cm": ("length", 1e-2), "m": ("length", 1.0), "km": ("length", 1e3),
    # area / volume
    "mm2": ("area", 1e-6), "cm2": ("area", 1e-4), "m2": ("area", 1.0),
    "l": ("volume", 1e-3), "litre": ("volume", 1e-3), "liter": ("volume", 1e-3), "m3": ("volume", 1.0),
    # time
    "s": ("time", 1.0), "sec": ("time", 1.0), "min": ("time", 60.0), "h": ("time", 3600.0),
    "hour": ("time", 3600.0), "hours": ("time", 3600.0), "day": ("time", 86400.0), "days": ("time", 86400.0),
    # mass / force / pressure
    "g": ("mass", 1e-3), "kg": ("mass", 1.0), "t": ("mass", 1e3), "tonne": ("mass", 1e3),
    "n": ("force", 1.0), "kn": ("force", 1e3), "mn": ("force", 1e6),
    "pa": ("pressure", 1.0), "kpa": ("pressure", 1e3), "mpa": ("pressure", 1e6), "bar": ("pressure", 1e5),
    # electrical / power / energy
    "v": ("voltage", 1.0), "kv": ("voltage", 1e3), "a": ("current", 1.0), "ma": ("current", 1e-3),
    "w": ("power", 1.0), "kw": ("power", 1e3), "mw": ("power", 1e6),
    "wh": ("energy", 3600.0), "kwh": ("energy", 3.6e6), "mwh": ("energy", 3.6e9),
    # speed / flow / other
    "m/s": ("speed", 1.0), "km/h": ("speed", 1 / 3.6), "kn_speed": ("speed", 0.514444),
    "m3/h": ("flow", 1 / 3600), "l/min": ("flow", 1e-3 / 60),
    "%": ("ratio", 0.01), "db": ("level_db", 1.0), "lux": ("illuminance", 1.0),
    "mm/s": ("vibration", 1e-3),
    "degc": ("temp_c", 1.0), "°c": ("temp_c", 1.0), "c": ("temp_c", 1.0),
}

_ALIASES = {"m²": "m2", "mm²": "mm2", "m³": "m3", "minutes": "min", "minute": "min", "mins": "min",
            "seconds": "s", "second": "s", "metres": "m", "meters": "m", "metre": "m", "meter": "m",
            "millimetres": "mm", "millimeters": "mm", "percent": "%", "knots": "kn_speed", "kt": "kn_speed"}

_OPS = [  # phrase -> operator, longest phrases first
    ("not less than", ">="), ("no less than", ">="), ("at least", ">="), ("minimum of", ">="),
    ("minimum", ">="), ("not exceeding", "<="), ("not more than", "<="),
    ("no more than", "<="), ("at most", "<="), ("maximum of", "<="), ("maximum", "<="),
    ("up to", "<="), ("less than", "<"), ("greater than", ">"), ("more than", ">"), ("exceeding", ">"),
    (">=", ">="), ("≥", ">="), ("<=", "<="), ("≤", "<="), (">", ">"), ("<", "<"), ("=", "=="),
]

_NUM_UNIT = re.compile(r"(?P<num>[-+]?\d+(?:[  ]?\d{3})*(?:[.,]\d+)?)\s*(?P<unit>[a-zA-Z°%²³/]+[23]?)?")


class QuantityError(ValueError):
    pass


@dataclass(frozen=True)
class Quantity:
    value: float
    unit: str
    dimension: str
    base_value: float

    def __str__(self) -> str:
        v = int(self.value) if self.value == int(self.value) else self.value
        return f"{v} {self.unit}".strip()


def _unit_key(raw: str | None) -> str:
    if not raw:
        return ""
    u = raw.strip().lower()
    return _ALIASES.get(u, _ALIASES.get(raw.strip(), u))


def parse_quantity(text: str, default_unit: str | None = None) -> Quantity:
    m = _NUM_UNIT.search(text)
    if not m:
        raise QuantityError(f"no number found in '{text}'")
    num = m["num"].replace(" ", "").replace(" ", "")
    if "," in num and "." not in num:
        num = num.replace(",", ".")  # European decimal comma
    unit = _unit_key(m["unit"]) or (_unit_key(default_unit) if default_unit else "")
    if unit and unit not in UNITS:
        raise QuantityError(f"unknown unit '{m['unit']}' in '{text}' (add it to quantities.UNITS)")
    dim, factor = UNITS.get(unit, ("dimensionless", 1.0))
    value = float(num)
    return Quantity(value=value, unit=m["unit"] or default_unit or "", dimension=dim, base_value=value * factor)


def parse_requirement(text: str) -> tuple[str, Quantity]:
    low = text.lower()
    op = next((o for phrase, o in _OPS if phrase in low), "==")
    return op, parse_quantity(text)


@dataclass(frozen=True)
class Check:
    ok: bool | None          # None = could not be decided (incompatible units, unparseable)
    operator: str
    required: str
    actual: str
    message: str


def check_requirement(requirement: str, actual: str, rel_tol: float = 1e-9) -> Check:
    try:
        op, req = parse_requirement(requirement)
        act = parse_quantity(actual, default_unit=req.unit)
    except QuantityError as exc:
        return Check(None, "?", requirement, actual, f"could not check: {exc}")
    if req.dimension != act.dimension:
        return Check(None, op, str(req), str(act),
                     f"could not check: {act} is {act.dimension}, requirement is {req.dimension}")
    a, r = act.base_value, req.base_value
    tol = rel_tol * max(abs(a), abs(r), 1.0)
    ok = {">=": a >= r - tol, "<=": a <= r + tol, ">": a > r + tol, "<": a < r - tol,
          "==": abs(a - r) <= tol}[op]
    shown = str(act)
    if act.unit and req.unit and _unit_key(act.unit) != _unit_key(req.unit):
        conv = a / UNITS[_unit_key(req.unit)][1]
        conv_s = int(conv) if conv == int(conv) else round(conv, 4)
        shown = f"{act} ({conv_s} {req.unit})"
    verb = "meets" if ok else "does not meet"
    return Check(ok, op, str(req), str(act), f"{shown} {verb} {op} {req}")
