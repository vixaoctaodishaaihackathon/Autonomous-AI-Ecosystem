"""Cross-border data residency and transfer gate through the HTTP boundary."""

from __future__ import annotations

NOW_MS = 1_791_633_600_000


def dataset(**overrides) -> dict:
    base = {
        "registry_id": "reg-vega-customer",
        "purpose": "cross_border_operational_analytics",
        "origin_jurisdiction": "DE",
        "categories": ["customer_pii"],
        "subject_count": 1200,
        "retention_days_requested": 365,
        "row_level_read": True,
        "relationship": "CONTROLLER_TO_PROCESSOR",
        "aggregation": {"is_aggregate": False},
    }
    base.update(overrides)
    return base


def request(region: str, *, tenant="tnt_vega_manufacturing", data=None, flags=None, evidence=None,
            agent_id=None, writes_pii=False) -> dict:
    return {
        "tenant_id": tenant,
        "request_id": "job-api-0001",
        "operation": {
            "type": "CROSS_BORDER_ANALYTICS",
            "processing_region": region,
            "agent_id": agent_id,
            "writes_pii": writes_pii,
        },
        "dataset": dataset(**(data or {})),
        "flags": flags if flags is not None else {"importer_is_public_authority": False},
        "evidence": evidence or {},
        "clock": {"milliseconds": NOW_MS},
    }


def gate(client, body) -> dict:
    response = client.post("/v1/data-transfer/gate", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_in_region_job_clears_the_rules_but_not_the_authority_ceiling(client):
    payload = gate(client, request("eu-de-1"))
    result = payload["result"]
    assert result["cross_border"] is False
    assert result["rules_verdict"] == "ALLOW"
    assert result["decision"] == "HUMAN_REVIEW"
    assert result["authority_ceiling_applied"] is True


def test_adequacy_is_the_route_that_needs_no_sign_off(client):
    payload = gate(client, request("ap-northeast-1"))
    result = payload["result"]
    assert result["transfer_mechanism"] == "EU_ADEQUACY"
    assert result["rules_verdict"] == "ALLOW"
    assert "KEEP_ADEQUACY_SNAPSHOT_VERSION" in result["obligations"]


def test_a_contract_route_needs_a_named_human_even_when_evidenced(client):
    payload = gate(client, request("in-mh-1"))
    result = payload["result"]
    assert result["transfer_mechanism"] == "SCC_MODULE_2_C2P"
    assert result["missing_evidence"] == []
    assert "TRANSFER_MECHANISM_NEEDS_HUMAN_SIGN_OFF" in result["ambiguities"]
    assert payload["requires_human_review"] is True


def test_unanswered_route_questions_block_without_denying(client):
    body = request("in-mh-1", data={"relationship": None}, flags={"importer_is_public_authority": None})
    result = gate(client, body)["result"]
    assert result["rules_verdict"] == "REQUIRE_MECHANISM"
    assert result["terminal"] is False
    assert result["pending_mechanisms"]
    assert "TRANSFER_ROUTE_PENDING_FACTS" in result["ambiguities"]


def test_claiming_a_mechanism_is_not_proving_it(client):
    body = request(
        "us-east-1",
        flags={"importer_certified_dpf": True, "data_subject_explicit_consent": True,
               "transfer_is_repetitive": False},
        evidence={},
    )
    result = gate(client, body)["result"]
    assert "EU_US_DPF" in result["applicable_mechanisms"]
    assert "dpf_program_participant_ref" in result["missing_evidence"]
    assert result["decision"] != "ALLOW"


def test_hard_localised_payment_data_cannot_be_dispatched_anywhere_else(client):
    body = request(
        "ae-1",
        tenant="tnt_northwind_healthlogistics",
        data={
            "registry_id": "reg-nw-payments",
            "purpose": "route_optimisation",
            "origin_jurisdiction": "IN",
            "categories": ["payment_card_data"],
            "retention_days_requested": 60,
        },
    )
    payload = gate(client, body)
    result = payload["result"]
    assert result["decision"] == "DENY"
    assert result["terminal"] is True
    assert "HARD_LOCALISATION_VIOLATED" in result["ambiguities"]
    assert payload["requires_human_review"] is False


def test_volume_above_the_sovereign_threshold_needs_the_filing(client):
    shared = {
        "tenant": "tnt_orchid_mobility",
        "data": {
            "registry_id": "reg-oc-shanghai-plant",
            "purpose": "predictive_maintenance",
            "origin_jurisdiction": "CN",
            "categories": ["customer_pii"],
            "subject_count": 250_000,
            "retention_days_requested": 90,
        },
        "flags": {"cac_assessment_passed": False, "standard_contract_filed_with_provincial_cac": False},
    }
    without = gate(client, request("in-mh-1", **shared))["result"]
    assert "VOLUME_ABOVE_SOVEREIGN_THRESHOLD_WITHOUT_APPROVAL" in without["ambiguities"]

    with_approval = gate(
        client,
        request("in-mh-1", **{**shared, "flags": {"cac_assessment_passed": True},
                               "evidence": {"cac_filing_approval_ref": "CAC-SH-2026-0093"}}),
    )["result"]
    assert "VOLUME_ABOVE_SOVEREIGN_THRESHOLD_WITHOUT_APPROVAL" not in with_approval["ambiguities"]
    assert with_approval["transfer_mechanism"] == "CN_CAC_SECURITY_ASSESSMENT"


def test_agent_scope_is_enforced_by_the_same_gate(client):
    body = request("eu-de-1", agent_id="agt-pricing-scout-eu")
    body["dataset"]["purpose"] = "price_optimisation"
    result = gate(client, body)["result"]
    assert "AGENT_PURPOSE_SCOPE_VIOLATION" in result["ambiguities"] or result["decision"] == "DENY"


def test_unregistered_agent_is_rejected(client):
    result = gate(client, request("eu-de-1", agent_id="agt-rogue"))["result"]
    assert result["decision"] == "DENY"
    assert "AGENT_NOT_REGISTERED_FOR_TENANT" in result["ambiguities"]


def test_unknown_tenant_has_no_policy_scope(client):
    result = gate(client, request("eu-de-1", tenant="tnt_does_not_exist"))["result"]
    assert result["decision"] == "DENY"
    assert "TENANT_NOT_REGISTERED_NO_POLICY_SCOPE" in result["ambiguities"]


def test_a_region_outside_the_topology_escalates(client):
    result = gate(client, request("moon-1"))["result"]
    assert result["rules_verdict"] == "HUMAN_REVIEW"
    assert "PROCESSING_REGION_NOT_IN_TOPOLOGY" in result["ambiguities"]


def test_empty_category_list_is_not_a_clearance(client):
    body = request("eu-de-1", data={"categories": ["  "]})
    assert client.post("/v1/data-transfer/gate", json=body).status_code == 422
