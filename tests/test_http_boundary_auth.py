"""Who may talk to the boundary, and what a rejected caller leaves behind.

The policy is unchanged here: these tests prove that an unauthenticated caller
cannot reach it, and cannot write a row into the audit ledger either.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from compliance_engine import app as app_module
from compliance_engine.app import create_app
from compliance_engine.config import Settings

KEY = "test-only-secret-long-enough"
WINDOW_START = 1_791_633_600.0  # a whole minute, so the limiter cannot roll over mid-test

BODY = {
    "tenant_id": "tnt_vega_manufacturing",
    "request_id": "req-auth-0001",
    "destination_country": "DE",
    "item": {
        "sku": "VCU-500",
        "description": "vehicle domain controller assembly",
        "technical_parameters": {
            "crypto_function": {
                "value": True,
                "evidence": {"source": "MANUAL_VERIFICATION", "ref": "spec-1"},
            },
            "symmetric_key_bits": {
                "value": 256,
                "unit": "bit",
                "evidence": {"source": "MANUAL_VERIFICATION", "ref": "spec-1"},
            },
        },
    },
    "end_user": {"screening_status": "CLEAR", "screening_ref": "scr-99"},
    "clock": {"milliseconds": int(WINDOW_START * 1000)},
}


@pytest.fixture()
def guarded(opa_url, tmp_path, request):
    """Builds the same app the boundary ships, with a bearer key configured."""

    def build(**overrides) -> TestClient:
        settings = Settings(
            opa_base_url=opa_url,
            ledger_path=tmp_path / "decisions.jsonl",
            review_closures_path=tmp_path / "review_closures.jsonl",
            gemini_api_key=None,
            api_key=KEY,
            **overrides,
        )
        client = TestClient(create_app(settings))
        client.__enter__()
        request.addfinalizer(client.__exit__)
        return client

    return build


def bearer() -> dict[str, str]:
    return {"Authorization": f"Bearer {KEY}"}


def test_health_stays_open_for_the_platform(guarded):
    client = guarded()
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_a_decision_requires_the_bearer_key(guarded):
    client = guarded()
    refused = client.post("/v1/export-control/decisions", json=BODY)
    assert refused.status_code == 401
    assert refused.headers["WWW-Authenticate"] == "Bearer"

    allowed = client.post("/v1/export-control/decisions", json=BODY, headers=bearer())
    assert allowed.status_code == 200
    assert allowed.json()["result"]["decision"] == "REQUIRE_LICENCE"


@pytest.mark.parametrize("header", [
    {"Authorization": f"Bearer {KEY}x"},
    {"Authorization": KEY},
    {"Authorization": f"Basic {KEY}"},
    {"X-Api-Key": KEY},
])
def test_only_an_exact_bearer_token_gets_through(guarded, header):
    assert guarded().post("/v1/export-control/decisions", json=BODY, headers=header).status_code == 401


def test_recorded_verdicts_are_not_public(guarded):
    client = guarded()
    decision_id = client.post("/v1/export-control/decisions", json=BODY, headers=bearer()).json()["decision_id"]

    assert client.get(f"/v1/decisions/{decision_id}").status_code == 401
    assert client.get("/v1/ledger/verify").status_code == 401
    assert client.get(f"/v1/decisions/{decision_id}", headers=bearer()).status_code == 200


def test_a_rejected_call_records_nothing(guarded):
    client = guarded()
    for _ in range(5):
        assert client.post("/v1/export-control/decisions", json=BODY).status_code == 401
    assert client.get("/v1/ledger/verify", headers=bearer()).json()["decisions"]["checked"] == 0


def test_a_key_holder_cannot_flood_the_ledger(guarded, monkeypatch):
    class FrozenClock:
        @staticmethod
        def time() -> float:
            return WINDOW_START

        @staticmethod
        def monotonic() -> float:
            return time.monotonic()

    monkeypatch.setattr(app_module, "time", FrozenClock)
    client = guarded(rate_limit_per_minute=3)
    for _ in range(3):
        assert client.post("/v1/export-control/decisions", json=BODY, headers=bearer()).status_code == 200

    limited = client.get("/v1/policies/version", headers=bearer())
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1


def test_the_engine_refuses_a_secret_that_is_not_a_secret(opa_url):
    with pytest.raises(ValueError, match="too short"):
        create_app(Settings(opa_base_url=opa_url, api_key="abc"))
