"""Fact extraction: an input to the engine, never a participant in its verdict.

Extraction answers one question - "what does this document say a parameter is" -
and always stamps its own provenance so the policy can weigh it. The Rego packs
treat machine-extracted facts as able to raise risk but never to retire it, so
this module holding no reference to decisions, licences or permissions is a
structural guarantee rather than a convention.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Protocol

import httpx

GEMINI_SOURCE = "GEMINI_EXTRACTION"
PARSER_SOURCE = "RULE_BASED_PARSER"

_PARAM_NAMES = (
    "symmetric_key_bits",
    "asymmetric_key_bits",
    "cotp_mops",
    "positioning_accuracy_um",
    "simultaneously_controllable_axes",
    "crypto_function",
    "primary_function_is_crypto",
    "generally_available_retail",
    "mass_market_declared",
    "crypto_algorithm_custom",
    "source_code_available_for_declassification",
    "wireless_encryption_function",
    "ir_focal_plane_array",
    "wavelength_nm",
    "pulse_energy_mj",
    "max_data_transfer_rate_mbps",
)

_UNITS = {
    "symmetric_key_bits": "bit",
    "asymmetric_key_bits": "bit",
    "cotp_mops": "Mtops",
    "positioning_accuracy_um": "um",
    "simultaneously_controllable_axes": "count",
    "wavelength_nm": "nm",
    "pulse_energy_mj": "mJ",
    "max_data_transfer_rate_mbps": "Mbit/s",
}


class Extractor(Protocol):
    name: str

    async def extract(self, text: str) -> dict[str, dict[str, Any]]: ...


def _quote_id(quote: str) -> int:
    return int(hashlib.sha256(quote.encode("utf-8")).hexdigest()[:8], 16)


class DeterministicParser:
    """Reads a handful of unambiguous parameter patterns out of spec text.

    Used when no Gemini key is configured, and in tests: it is deliberately a
    real (if narrow) parser so the pipeline shape stays honest offline.
    """

    name = "deterministic-parser"

    _PATTERNS: tuple[tuple[str, re.Pattern, Any], ...] = (
        ("symmetric_key_bits", re.compile(r"\b(?:AES|DES|3DES|SM4)[- ]?(256|192|128)\b", re.I), int),
        ("asymmetric_key_bits", re.compile(r"\bRSA[- ]?(4096|2048|1024)\b", re.I), int),
        ("positioning_accuracy_um", re.compile(r"(?:accuracy|resolution)[^0-9]{0,12}([0-9]+(?:\.[0-9]+)?)\s*(?:um|µm|microns?)\b", re.I), float),
        ("wavelength_nm", re.compile(r"(\d{3,4})\s*nm\b", re.I), int),
        ("cotp_mops", re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*(?:Mtops|million operations per second)\b", re.I), float),
        ("simultaneously_controllable_axes", re.compile(r"(\d)\s*(?:axis|axes)\b", re.I), int),
    )

    def _crypto_presence(self, text: str) -> dict[str, dict[str, Any]] | None:
        if re.search(r"\bencrypt|\bdecrypt|cryptograph|\bAES\b|\bRSA\b|\bTLS\b", text, re.I) is None:
            return None
        quote_match = re.search(r".{0,60}(?:encrypt|cryptograph|AES|RSA|TLS).{0,60}", text, re.I | re.S)
        quote = (quote_match.group(0) if quote_match else text[:120]).strip()
        return {
            "crypto_function": {
                "value": True,
                "evidence": {
                    "source": PARSER_SOURCE,
                    "ref": f"parsed:crypto_function:{_quote_id(quote)}",
                    "quote": quote,
                    "confidence": 0.62,
                },
            }
        }

    async def extract(self, text: str) -> dict[str, dict[str, Any]]:
        facts: dict[str, dict[str, Any]] = {}
        for param, pattern, caster in self._PATTERNS:
            match = pattern.search(text)
            if match is None:
                continue
            value = caster(match.group(1))
            unit = _UNITS.get(param)
            fact: dict[str, Any] = {"value": value}
            if unit:
                fact["unit"] = unit
            fact["evidence"] = {
                "source": PARSER_SOURCE,
                "ref": f"parsed:{param}:{match.start()}",
                "quote": match.group(0).strip(),
                "confidence": 0.7,
            }
            facts[param] = fact
        for key, value in (self._crypto_presence(text) or {}).items():
            if key not in facts:
                facts[key] = value
        return facts


class GeminiExtractor:
    """Gemini behind a forced JSON schema, so it can only ever emit facts."""

    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash", timeout: float = 30.0,
                 transport: httpx.AsyncBaseTransport | None = None):
        self._key = api_key
        self._model = model
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def aclose(self) -> None:
        await self._client.aclose()

    def _schema(self) -> dict:
        return {
            "type": "OBJECT",
            "properties": {
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        name: {
                            "type": "OBJECT",
                            "properties": {
                                "value": {"type": "NUMBER" if unit else "BOOLEAN"},
                                "unit": {"type": "STRING"},
                                "quote": {"type": "STRING"},
                                "confidence": {"type": "NUMBER"},
                            },
                            "required": ["value", "quote", "confidence"],
                        }
                        for name, unit in _UNITS.items()
                    },
                },
                "crypto_function": {"type": "BOOLEAN"},
            },
            "required": ["parameters"],
        }

    async def extract(self, text: str) -> dict[str, dict[str, Any]]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:generateContent"
        body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                "Extract only technical parameters that this text states. "
                                "Never infer a value you cannot quote, and never decide whether "
                                "the item is controlled. Copy the shortest span that supports each "
                                "value into `quote`, and give `confidence` as the probability that "
                                "the quoted span really means this value for this parameter. "
                                "Omit parameters the text does not state.\n\n---\n" + text
                            )
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0.0,
                "responseMimeType": "application/json",
                "responseSchema": self._schema(),
            },
        }
        response = await self._client.post(url, params={"key": self._key}, json=body)
        response.raise_for_status()
        payload = response.json()
        try:
            text_out = payload["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Gemini returned no usable content") from exc

        parsed = json.loads(text_out)
        return self._to_facts(parsed)

    def _to_facts(self, parsed: dict[str, Any]) -> dict[str, dict[str, Any]]:
        facts: dict[str, dict[str, Any]] = {}
        for param, entry in (parsed.get("parameters") or {}).items():
            if param not in _UNITS or not isinstance(entry, dict) or entry.get("value") is None:
                continue
            quote = str(entry.get("quote") or "")[:500]
            fact: dict[str, Any] = {"value": entry["value"]}
            unit = entry.get("unit") or _UNITS[param]
            fact["unit"] = unit
            fact["evidence"] = {
                "source": GEMINI_SOURCE,
                "ref": f"gemini:{param}:{_quote_id(quote)}",
                "quote": quote,
                "confidence": float(entry.get("confidence") or 0.0),
            }
            facts[param] = fact
        crypto = parsed.get("crypto_function")
        if isinstance(crypto, bool):
            facts["crypto_function"] = {
                "value": crypto,
                "evidence": {
                    "source": GEMINI_SOURCE,
                    "ref": "gemini:crypto_function",
                    "quote": "model classification of the stated functions",
                    "confidence": 0.8,
                },
            }
        return facts


def build_extractor(api_key: str | None, model: str = "gemini-2.5-flash") -> Extractor:
    if api_key:
        return GeminiExtractor(api_key=api_key, model=model)
    return DeterministicParser()
