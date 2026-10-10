"""Export control decisions through the HTTP boundary."""

from __future__ import annotations

NOW_MS = 1_791_633_600_000  # 2026-10-10T12:00:00Z, inside every table window


def ev(source: str, ref: str) -> dict:
    return {"source": source, "ref": ref, "quote": "as printed in the source document", "confidence": 0.99}


def fact(value, unit, source, ref) -> dict:
    return {"value": value, "unit": unit, "evidence": ev(source, ref)}


def request(parameters: dict, **overrides) -> dict:
    body = {
        "tenant_id": "tnt_vega_manufacturing",
        "request_id": "req-api-0001",
        "destination_country": "DE",
        "intent": {"activity": "EXPORT"},
        "item": {
            "sku": "VCU-500",
            "description": "vehicle domain controller assembly",
            "technical_parameters": parameters,
        },
        "end_user": {"screening_status": "CLEAR", "screening_ref": "scr-99"},
        "evidence": {},
        "clock": {"milliseconds": NOW_MS},
    }
    body.update(overrides)
    return body


CRYPTO = {
    "crypto_function": fact(True, None, "MANUAL_VERIFICATION", "spec-1"),
    "symmetric_key_bits": fact(256, "bit", "MANUAL_VERIFICATION", "spec-1"),
}

MASS_MARKET = {
    "crypto_function": fact(True, None, "MANUAL_VERIFICATION", "spec-1"),
    "symmetric_key_bits": fact(128, "bit", "MANUAL_VERIFICATION", "spec-1"),
    "mass_market_declared": fact(True, None, "CERTIFICATE", "cert-4"),
    "generally_available_retail": fact(True, None, "DECLARATION", "decl-4"),
    "crypto_algorithm_custom": fact(False, None, "MANUAL_VERIFICATION", "spec-1"),
    "source_code_available_for_declassification": fact(True, None, "SIGNED_SPEC_SHEET", "spec-1"),
}


def test_health_and_ready(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").json()["status"] == "ready"


def test_policies_version_reports_table_authority(client):
    body = client.get("/v1/policies/version").json()
    table_ids = {table["table_id"] for table in body["tables"]}
    assert "dual_use_controls" in table_ids
    assert "residency_rules" in table_ids
    assert body["authority_unverified"], "illustrative tables must be reported as unverified"


def test_controlled_encryption_requires_an_authorisation(client):
    response = client.post("/v1/export-control/decisions", json=request(CRYPTO))
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["rules_verdict"] == "REQUIRE_LICENCE"
    assert result["control_code"] == "5A002"
    assert "OBTAIN_EXPORT_AUTHORISATION" in result["obligations"]
    assert response.json()["requires_human_review"] is True


def test_silence_about_a_parameter_is_not_a_clearance(client):
    body = request({"positioning_accuracy_um": fact(12.5, "um", "MANUAL_VERIFICATION", "spec-2")})
    result = client.post("/v1/export-control/decisions", json=body).json()["result"]
    assert result["rules_verdict"] == "HUMAN_REVIEW"
    assert "NO_CONTROL_MATCHED_REQUIRES_POSITIVE_DETERMINATION" in result["ambiguities"]


def test_a_convertible_unit_is_normalised_before_the_engine_sees_it(client):
    # 0.25 Mbit of symmetric key length is 250,000 bit: above the control's
    # threshold. Left as "0.25" it would have read as a trivially small key.
    body = request(
        {
            "crypto_function": fact(True, None, "MANUAL_VERIFICATION", "spec-1"),
            "symmetric_key_bits": fact(0.25, "Mbit", "MANUAL_VERIFICATION", "spec-1"),
        }
    )
    response = client.post("/v1/export-control/decisions", json=body).json()
    assert response["result"]["rules_verdict"] == "REQUIRE_LICENCE"
    notes = {note["parameter"]: note["reason"] for note in response["fact_normalisation"]}
    assert "converted" in notes["symmetric_key_bits"]


def test_an_unresolvable_unit_is_passed_through_for_the_engine_to_flag(client):
    body = request(
        {
            "crypto_function": fact(True, None, "MANUAL_VERIFICATION", "spec-1"),
            "symmetric_key_bits": fact(256, "furlongs", "MANUAL_VERIFICATION", "spec-1"),
        }
    )
    response = client.post("/v1/export-control/decisions", json=body).json()
    assert response["result"]["rules_verdict"] != "ALLOW"
    assert "FACT_UNIT_NOT_RESOLVED" in response["result"]["ambiguities"]
    reasons = {note["parameter"]: note["reason"] for note in response["fact_normalisation"]}
    assert "conversion table" in reasons["symmetric_key_bits"]


def test_embargoed_destination_is_prohibited(client):
    body = request(CRYPTO, destination_country="KP")
    payload = client.post("/v1/export-control/decisions", json=body).json()
    assert payload["result"]["decision"] == "PROHIBITED"
    assert payload["result"]["terminal"] is True
    assert payload["requires_human_review"] is False


def test_screening_absent_never_clears(client):
    body = request(CRYPTO, end_user={})
    result = client.post("/v1/export-control/decisions", json=body).json()["result"]
    assert "END_USER_SCREENING_ABSENT" in result["ambiguities"]
    assert result["decision"] != "ALLOW"


def test_missing_evidence_reference_is_rejected_at_the_boundary(client):
    bad = {
        "crypto_function": {
            "value": True,
            "evidence": {"source": "MANUAL_VERIFICATION", "ref": "  ", "confidence": 0.9},
        }
    }
    assert client.post("/v1/export-control/decisions", json=request(bad)).status_code == 422


def test_unknown_source_token_is_rejected_at_the_boundary(client):
    bad = {"symmetric_key_bits": {"value": 256, "unit": "bit", "evidence": {"source": "VIBES", "ref": "x-1"}}}
    assert client.post("/v1/export-control/decisions", json=request(bad)).status_code == 422


def test_tenant_header_must_match_the_request(client):
    response = client.post(
        "/v1/export-control/decisions",
        json=request(CRYPTO),
        headers={"X-Tenant-Id": "tnt_someone_elses"},
    )
    assert response.status_code == 403


def test_decision_is_replayable_from_the_recorded_input(client, settings):
    payload = client.post("/v1/export-control/decisions", json=request(CRYPTO)).json()
    recorded = client.get(f"/v1/decisions/{payload['decision_id']}").json()
    replay = client.post("/v1/export-control/decisions", json=recorded["payload"]["input"]).json()
    assert replay["result"]["decision"] == payload["result"]["decision"]
    assert replay["result"]["policy"]["digest"] == payload["result"]["policy"]["digest"]
