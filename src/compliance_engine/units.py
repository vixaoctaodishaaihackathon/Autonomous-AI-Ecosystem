"""Unit normalisation against the control-list parameter table.

A number quoted in the wrong unit is a silent misclassification: 0.25 "kbit"
read as 0.25 bit would clear an encryption control that the real value breaks.
The Rego matcher invalidates any fact whose unit is not the unit its parameter
declares, so the boundary converts units that provably mean the same thing and
passes everything else through untouched for the engine to escalate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# token -> size in the family's base unit
_FAMILIES: dict[str, dict[str, float]] = {
    "length": {"nm": 1e-9, "um": 1e-6, "mm": 1e-3, "cm": 1e-2, "m": 1.0, "km": 1e3},
    "energy": {"mJ": 1e-3, "J": 1.0, "kJ": 1e3, "MJ": 1e6},
    "size": {"bit": 1.0, "kbit": 1e3, "Mbit": 1e6, "Gbit": 1e9, "byte": 8.0, "kB": 8e3, "MB": 8e6, "GB": 8e9},
    "rate": {"bit/s": 1.0, "kbit/s": 1e3, "Mbit/s": 1e6, "Gbit/s": 1e9},
    "throughput": {"tops": 1.0, "Mtops": 1e6, "Gtops": 1e9},
    "count": {"count": 1.0},
}

_BASE_FOR_UNIT = {
    token: (family, factor)
    for family, tokens in _FAMILIES.items()
    for token, factor in tokens.items()
}


@dataclass(frozen=True)
class NormalisationNote:
    parameter: str
    original_unit: str | None
    original_value: Any
    resolved_unit: str | None
    reason: str


def _tidy(number: float) -> Any:
    rounded = round(number)
    if abs(number - rounded) < 1e-9:
        return rounded
    return round(number, 9)


def _family_for(unit: str) -> tuple[str, float] | None:
    return _BASE_FOR_UNIT.get(unit)


def normalise_fact(name: str, fact: dict, expected_unit: str | None) -> tuple[dict, NormalisationNote | None]:
    """Return the fact with its value expressed in the parameter's declared unit."""
    if expected_unit is None or not isinstance(fact.get("value"), (int, float)):
        return fact, None

    supplied = fact.get("unit")
    if supplied == expected_unit:
        return fact, None

    if supplied is None:
        return fact, NormalisationNote(
            parameter=name,
            original_unit=None,
            original_value=fact["value"],
            resolved_unit=None,
            reason="no unit supplied; the engine treats the parameter as unresolved",
        )

    supplied_family = _family_for(supplied)
    expected_family = _family_for(expected_unit)
    if supplied_family is None or expected_family is None:
        return fact, NormalisationNote(
            parameter=name,
            original_unit=supplied,
            original_value=fact["value"],
            resolved_unit=expected_unit,
            reason="unit outside the conversion table; left for the engine to escalate",
        )
    if supplied_family[0] != expected_family[0]:
        return fact, NormalisationNote(
            parameter=name,
            original_unit=supplied,
            original_value=fact["value"],
            resolved_unit=expected_unit,
            reason=f"unit belongs to the {supplied_family[0]} family, not {expected_family[0]}",
        )

    scaled = fact["value"] * supplied_family[1] / expected_family[1]
    updated = {**fact, "value": _tidy(scaled), "unit": expected_unit}
    return updated, NormalisationNote(
        parameter=name,
        original_unit=supplied,
        original_value=fact["value"],
        resolved_unit=expected_unit,
        reason="converted within the same unit family",
    )


def normalise_parameters(
    params: dict[str, dict], param_meta: dict[str, Any]
) -> tuple[dict[str, dict], list[NormalisationNote]]:
    notes: list[NormalisationNote] = []
    resolved: dict[str, dict] = {}
    for name, fact in params.items():
        meta = param_meta.get(name) or {}
        expected_unit = meta.get("unit") if isinstance(meta, dict) else None
        updated, note = normalise_fact(name, fact, expected_unit)
        resolved[name] = updated
        if note is not None:
            notes.append(note)
    return resolved, notes
