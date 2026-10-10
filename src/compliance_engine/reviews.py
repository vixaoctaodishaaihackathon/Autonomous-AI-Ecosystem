"""Human review queue.

Every verdict the engine could not clear on its own is an open review, derived
from the ledger rather than stored twice: the queue cannot drift from the record
of what was actually decided. Closures are appended to their own hash-chained
file so "who signed this transfer, and when" is auditable to the same standard
as the decision itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ledger import DecisionLedger, GENESIS, canonical, entry_hash, utc_now_iso
import json
import threading


class ReviewQueue:
    def __init__(self, ledger: DecisionLedger, closures_path: Path):
        self._ledger = ledger
        self._path = Path(closures_path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    def _closed_ids(self) -> dict[str, dict]:
        closed: dict[str, dict] = {}
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                closed[entry["payload"]["decision_id"]] = entry
        return closed

    def open_reviews(self) -> list[dict]:
        closed = self._closed_ids()
        reviews = []
        for entry in self._ledger.entries():
            payload = entry["payload"]
            result = payload.get("result", {})
            if not result.get("escalation", {}).get("required"):
                continue
            decision_id = payload["decision_id"]
            if decision_id in closed:
                continue
            reviews.append(
                {
                    "decision_id": decision_id,
                    "engine": result.get("engine") or result.get("pack"),
                    "tenant_id": payload.get("tenant_id"),
                    "decision": result.get("decision"),
                    "queue": result.get("escalation", {}).get("queue"),
                    "sla_hours": result.get("escalation", {}).get("sla_hours"),
                    "reasons": result.get("ambiguities", []),
                    "obligations": result.get("obligations", []),
                    "recorded_at": entry["recorded_at"],
                }
            )
        return reviews

    def close(self, decision_id: str, *, reviewer: str, outcome: str, note: str) -> dict:
        record = self._ledger.find(decision_id)
        if record is None:
            raise KeyError(decision_id)
        with self._lock:
            seq, prev_hash = self._tail()
            payload = {
                "decision_id": decision_id,
                "reviewer": reviewer,
                "outcome": outcome,
                "note": note,
                "original_decision": record["payload"]["result"].get("decision"),
                "closed_at": utc_now_iso(),
            }
            entry = {"seq": seq, "recorded_at": payload["closed_at"], "prev_hash": prev_hash, "payload": payload}
            entry["entry_hash"] = entry_hash(seq=seq, prev_hash=prev_hash, payload=payload)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(canonical(entry) + "\n")
            return entry

    def _tail(self) -> tuple[int, str]:
        seq, last_hash = 0, GENESIS
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                seq = entry["seq"] + 1
                last_hash = entry["entry_hash"]
        return seq, last_hash

    def verify_chain(self) -> dict[str, Any]:
        expected_seq, prev_hash, checked = 0, GENESIS, 0
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry["seq"] != expected_seq or entry["prev_hash"] != prev_hash:
                    return {"ok": False, "checked": checked, "broken_at_seq": entry["seq"]}
                if entry_hash(seq=entry["seq"], prev_hash=entry["prev_hash"], payload=entry["payload"]) != entry["entry_hash"]:
                    return {"ok": False, "checked": checked, "broken_at_seq": entry["seq"]}
                prev_hash = entry["entry_hash"]
                expected_seq += 1
                checked += 1
        return {"ok": True, "checked": checked, "broken_at_seq": None}
