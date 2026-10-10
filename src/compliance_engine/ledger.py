"""Append-only, hash-chained decision ledger.

An auditor has to be able to prove that a stored verdict was never edited after
the fact. Each entry carries the previous entry's hash, so rewriting or dropping
any historical record breaks the chain from that point on, and `verify_chain`
says exactly where.

The clock inside `payload["input"]` is the one the policy used; `recorded_at` is
only when the service wrote the line and never feeds a decision.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


def canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def entry_hash(*, seq: int, prev_hash: str, payload: Any) -> str:
    material = f"{seq}|{prev_hash}|{canonical(payload)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def new_decision_id() -> str:
    return f"dec_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class DecisionLedger:
    def __init__(self, path: Path):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def entries(self) -> Iterator[dict]:
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def _tail(self) -> tuple[int, str]:
        seq, last_hash = 0, GENESIS
        for entry in self.entries():
            seq = entry["seq"] + 1
            last_hash = entry["entry_hash"]
        return seq, last_hash

    def append(self, payload: dict) -> dict:
        with self._lock:
            seq, prev_hash = self._tail()
            entry = {
                "seq": seq,
                "recorded_at": utc_now_iso(),
                "prev_hash": prev_hash,
                "payload": payload,
            }
            entry["entry_hash"] = entry_hash(seq=seq, prev_hash=prev_hash, payload=payload)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(canonical(entry) + "\n")
            return entry

    def find(self, decision_id: str) -> dict | None:
        for entry in self.entries():
            if entry.get("payload", {}).get("decision_id") == decision_id:
                return entry
        return None

    def verify_chain(self) -> dict:
        expected_seq = 0
        prev_hash = GENESIS
        checked = 0
        for entry in self.entries():
            if entry["seq"] != expected_seq or entry["prev_hash"] != prev_hash:
                return {"ok": False, "checked": checked, "broken_at_seq": entry["seq"], "reason": "chain link"}
            recomputed = entry_hash(
                seq=entry["seq"], prev_hash=entry["prev_hash"], payload=entry["payload"]
            )
            if recomputed != entry["entry_hash"]:
                return {"ok": False, "checked": checked, "broken_at_seq": entry["seq"], "reason": "payload edited"}
            prev_hash = entry["entry_hash"]
            expected_seq += 1
            checked += 1
        return {"ok": True, "checked": checked, "broken_at_seq": None, "reason": None}
