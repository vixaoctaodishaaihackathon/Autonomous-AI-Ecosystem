"""The pillar-1 guardrail and the audit trail, proven end to end.

Everything here tests the same proposition from the outside: a model can add
facts, it cannot add permission.
"""

from __future__ import annotations

import json

from compliance_engine.app import create_app
from compliance_engine.config import Settings
from compliance_engine.ledger import DecisionLedger
from fastapi.testclient import TestClient

NOW_MS = 1_791_633_600_000


def ev(source: str, ref: str, confidence: float = 0.99) -> dict:
    return {"source": source, "ref": ref, "quote": "as printed", "confidence": confidence}


def fact(value, unit, source, ref, confidence=0.99) -> dict:
    return {"value": value, "unit": unit, "evidence": ev(source, ref, confidence)}


def body(parameters: dict, **overrides) -> dict:
    doc = {
        "tenant_id": "tnt_vega_manufacturing",
        "request_id": "req-guardrail-1",
        "destination_country": "DE",
        "intent": {"activity": "EXPORT"},
        "item": {"sku": "VCU-500", "description": "vehicle domain controller assembly",
                 "technical_parameters": parameters},
        "end_user": {"screening_status": "CLEAR", "screening_ref": "scr-99"},
        "evidence": {"declassification_or_notification_evidence": "EX-2026-113"},
        "clock": {"milliseconds": NOW_MS},
    }
    doc.update(overrides)
    return doc


MASS_MARKET_HUMAN = {
    "crypto_function": fact(True, None, "MANUAL_VERIFICATION", "spec-1"),
    "symmetric_key_bits": fact(128, "bit", "MANUAL_VERIFICATION", "spec-1"),
    "mass_market_declared": fact(True, None, "CERTIFICATE", "cert-4"),
    "generally_available_retail": fact(True, None, "DECLARATION", "decl-4"),
    "crypto_algorithm_custom": fact(False, None, "MANUAL_VERIFICATION", "spec-1"),
    "source_code_available_for_declassification": fact(True, None, "SIGNED_SPEC_SHEET", "spec-1"),
}

MASS_MARKET_MODEL_SPOOF = {
    **MASS_MARKET_HUMAN,
    "crypto_function": fact(True, None, "GEMINI_EXTRACTION", "doc-1#p2", 0.97),
    "symmetric_key_bits": fact(128, "bit", "GEMINI_EXTRACTION", "doc-1#p2", 0.97),
    "crypto_algorithm_custom": fact(False, None, "GEMINI_EXTRACTION", "doc-1#p2", 0.97),
    "source_code_available_for_declassification": fact(True, None, "GEMINI_EXTRACTION", "doc-1#p2", 0.97),
}


def test_extraction_can_never_retire_a_control(client):
    from_model = client.post("/v1/export-control/decisions", json=body(MASS_MARKET_MODEL_SPOOF)).json()
    assert from_model["result"]["rules_verdict"] == "HUMAN_REVIEW"
    assert "EXCLUSION_RESTS_ON_EXTRACTED_FACTS" in from_model["result"]["ambiguities"]

    from_human = client.post("/v1/export-control/decisions", json=body(MASS_MARKET_HUMAN)).json()
    assert from_human["result"]["rules_verdict"] == "ALLOW"


def test_a_high_confidence_claim_does_not_outrank_a_missing_document(client):
    spoofed = {
        **MASS_MARKET_MODEL_SPOOF,
        "generally_available_retail": fact(True, None, "GEMINI_EXTRACTION", "doc-1#p3", 0.99),
        "mass_market_declared": fact(True, None, "GEMINI_EXTRACTION", "doc-1#p3", 0.99),
    }
    result = client.post("/v1/export-control/decisions", json=body(spoofed)).json()["result"]
    assert result["decision"] != "ALLOW"


def test_low_confidence_extraction_is_flagged_even_when_it_agrees(client):
    shaky = {
        "crypto_function": {"value": True, "unit": None,
                            "evidence": {"source": "GEMINI_EXTRACTION", "ref": "doc-1#p2",
                                         "quote": "AES-256", "confidence": 0.41}},
        "symmetric_key_bits": {"value": 256, "unit": "bit",
                               "evidence": {"source": "GEMINI_EXTRACTION", "ref": "doc-1#p2",
                                            "quote": "AES-256", "confidence": 0.41}},
    }
    result = client.post("/v1/export-control/decisions", json=body(shaky)).json()["result"]
    assert "FACT_CONFIDENCE_BELOW_THRESHOLD" in result["ambiguities"]


def test_the_facts_endpoint_returns_facts_and_no_verdict(client):
    response = client.post("/v1/export-control/facts", json={"text": "Domain controller with AES-256 encryption and ±12.5 um positioning accuracy."})
    assert response.status_code == 200
    payload = response.json()
    assert payload["authoritative"] is False
    assert "technical_parameters" in payload
    assert not any(key in payload for key in ("decision", "rules_verdict"))
    sources = {fact["evidence"]["source"] for fact in payload["technical_parameters"].values()}
    assert sources == {"RULE_BASED_PARSER"}


def test_extracted_facts_can_be_fed_into_the_engine_but_not_shortcut_it(client):
    extracted = client.post(
        "/v1/export-control/facts", json={"text": "Industrial controller, RSA-2048 key exchange."}
    ).json()["technical_parameters"]
    result = client.post("/v1/export-control/decisions", json=body(extracted)).json()["result"]
    assert result["decision"] != "ALLOW"
    assert set(result["evidence_quality"]["llm_sourced_params"]) == set(extracted)


def test_every_decision_is_recorded_and_the_chain_verifies(client):
    payload = client.post("/v1/export-control/decisions", json=body(MASS_MARKET_HUMAN)).json()
    assert client.get(f"/v1/decisions/{payload['decision_id']}").status_code == 200
    verification = client.get("/v1/ledger/verify").json()
    assert verification["decisions"]["ok"] is True
    assert verification["decisions"]["checked"] >= 1


def test_editing_a_recorded_decision_breaks_the_chain(client, settings):
    client.post("/v1/export-control/decisions", json=body(MASS_MARKET_HUMAN))
    client.post("/v1/data-transfer/gate", json={
        "tenant_id": "tnt_vega_manufacturing",
        "operation": {"type": "CROSS_BORDER_ANALYTICS", "processing_region": "eu-de-1"},
        "dataset": {"registry_id": "reg-vega-customer", "purpose": "cross_border_operational_analytics",
                    "origin_jurisdiction": "DE", "categories": ["customer_pii"], "subject_count": 10,
                    "retention_days_requested": 30},
    })
    assert client.get("/v1/ledger/verify").json()["decisions"]["ok"] is True

    path = settings.ledger_path
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["result"]["decision"] = "ALLOW"
    lines[0] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verification = client.get("/v1/ledger/verify").json()["decisions"]
    assert verification["ok"] is False
    assert verification["broken_at_seq"] == 0


def test_the_review_queue_is_derived_from_the_ledger_and_closes_auditably(client):
    escalated = client.post("/v1/data-transfer/gate", json={
        "tenant_id": "tnt_vega_manufacturing",
        "operation": {"type": "CROSS_BORDER_ANALYTICS", "processing_region": "in-mh-1"},
        "dataset": {"registry_id": "reg-vega-customer", "purpose": "cross_border_operational_analytics",
                    "origin_jurisdiction": "DE", "categories": ["customer_pii"], "subject_count": 1200,
                    "retention_days_requested": 365, "relationship": "CONTROLLER_TO_PROCESSOR"},
    }).json()
    assert escalated["requires_human_review"] is True

    open_ids = [review["decision_id"] for review in client.get("/v1/reviews").json()["open"]]
    assert escalated["decision_id"] in open_ids

    bad_close = client.post(f"/v1/reviews/{escalated['decision_id']}/close",
                            json={"reviewer": "not-an-identity", "outcome": "APPROVED"})
    assert bad_close.status_code == 422

    closed = client.post(
        f"/v1/reviews/{escalated['decision_id']}/close",
        json={"reviewer": "privacy-officer@vega.example", "outcome": "APPROVED", "note": "SCC verified"},
    )
    assert closed.status_code == 200
    remaining = [review["decision_id"] for review in client.get("/v1/reviews").json()["open"]]
    assert escalated["decision_id"] not in remaining
    assert client.get("/v1/ledger/verify").json()["review_closures"]["ok"] is True


def test_a_missing_sidecar_is_a_fault_not_a_default_allow(opa_url, settings, tmp_path):
    broken = Settings(**{**settings.__dict__, "opa_base_url": "http://127.0.0.1:1"})
    with TestClient(create_app(broken)) as client_without_opa:
        assert client_without_opa.get("/readyz").status_code == 503
        response = client_without_opa.post("/v1/export-control/decisions", json=body(MASS_MARKET_HUMAN))
        assert response.status_code == 503


def test_ledger_files_are_hash_chained_from_an_empty_start(tmp_path):
    ledger = DecisionLedger(tmp_path / "fresh.jsonl")
    first = ledger.append({"decision_id": "a", "result": {}})
    second = ledger.append({"decision_id": "b", "result": {}})
    assert first["prev_hash"] == "0" * 64
    assert second["prev_hash"] == first["entry_hash"]
    assert ledger.verify_chain()["ok"] is True


# A verdict that does not say which policy artifact produced it cannot be replayed
# or defended later, so scripts/policy_build.sh stamps a revision into the bundle.
def test_a_stamped_policy_revision_travels_with_the_verdict(client):
    sidecar = client.app.state.opa
    original_read = sidecar.read

    async def read_with_revision(path):
        if path.endswith("policy_build/revision"):
            return "20261010T000000Z"
        return await original_read(path)

    sidecar.read = read_with_revision
    client.app.state.revision_cache = {"value": None, "at": 0.0}

    payload = client.post("/v1/data-transfer/gate", json={
        "tenant_id": "tnt_vega_manufacturing",
        "operation": {"type": "CROSS_BORDER_ANALYTICS", "processing_region": "eu-de-1"},
        "dataset": {"registry_id": "reg-vega-customer", "purpose": "cross_border_operational_analytics",
                    "origin_jurisdiction": "DE", "categories": ["customer_pii"], "subject_count": 10,
                    "retention_days_requested": 30},
    }).json()
    assert payload["policy_revision"] == "20261010T000000Z"
    stored = client.get(f"/v1/decisions/{payload['decision_id']}").json()
    assert stored["payload"]["policy_revision"] == "20261010T000000Z"
    assert client.get("/v1/policies/version").json()["served_policy_revision"] == "20261010T000000Z"
