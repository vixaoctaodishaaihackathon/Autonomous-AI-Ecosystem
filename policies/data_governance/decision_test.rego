package policy.data_governance_test
import rego.v1
import data.policy.data_governance

# 2026-10-10T12:00:00Z - inside every table's effective window and cadence.
now := 1791633600000
# 2027-06-01T00:00:00Z - past the residency table's 90-day cadence.
much_later := 1811808000000

# object.union deep-merges nested objects, which would leak the default dataset
# into tests meant to replace it, so patches replace top-level keys here.
override(base, patch) := out if {
	keys := {k | k := object.keys(base)[_]} | {k | k := object.keys(patch)[_]}
	out := {k: object.get(patch, k, object.get(base, k, null)) | some k in keys}
}

dataset_default := {
	"registry_id": "reg-vega-customer",
	"purpose": "cross_border_operational_analytics",
	"origin_jurisdiction": "DE",
	"categories": ["customer_pii"],
	"subject_count": 1200,
	"retention_days_requested": 365,
	"row_level_read": true,
	"relationship": "CONTROLLER_TO_PROCESSOR",
	"aggregation": {"is_aggregate": false},
}

flags_default := {"importer_is_public_authority": false}

op(region, agent) := {"type": "CROSS_BORDER_ANALYTICS", "processing_region": region, "agent_id": agent}

job(dataset_patch, flags_patch, extra) := out if {
	defaults := {
		"request_id": "job-0001",
		"tenant_id": "tnt_vega_manufacturing",
		"operation": op("eu-de-1", null),
		"dataset": override(dataset_default, dataset_patch),
		"flags": override(flags_default, flags_patch),
		"evidence": {},
		"clock": {"milliseconds": now},
	}
	out := override(defaults, extra)
}

telemetry(region, k) := job(
	{
		"registry_id": "reg-vega-line-telemetry",
		"purpose": "predictive_maintenance",
		"categories": ["vehicle_sensor_telemetry"],
		"row_level_read": false,
		"retention_days_requested": 90,
		"aggregation": {"is_aggregate": true, "k_anonymity": k},
	},
	{},
	{"operation": op(region, null)},
)

# --- the in-region baseline --------------------------------------------------

test_in_region_processing_stays_within_scope if {
	result := data_governance.result with input as job({}, {}, {})
	result.cross_border == false
	result.origin_jurisdiction == "DE"
	result.processing_jurisdiction == "DE"
	result.rules_verdict == "ALLOW"
	result.residency[0].reason == "SAME_JURISDICTION_PROCESSING"
}

# Sovereign tables are illustrative: even a clean in-region job cannot be
# auto-cleared by the engine alone.
test_unverified_tables_cap_the_clearance if {
	result := data_governance.result with input as job({}, {}, {})
	result.rules_verdict == "ALLOW"
	result.decision == "HUMAN_REVIEW"
	result.authority_ceiling_applied == true
	result.terminal == false
}

# --- the transfer mechanism ladder ----------------------------------------

test_adequacy_is_the_only_route_that_auto_clears if {
	result := data_governance.result with input as job({}, {}, {"operation": op("ap-northeast-1", null)})
	result.cross_border == true
	result.transfer_mechanism == "EU_ADEQUACY"
	result.residency[0].verdict == "ALLOW"
	result.residency[0].reason == "ADEQUACY_COVERS_DESTINATION"
	result.rules_verdict == "ALLOW"
	"KEEP_ADEQUACY_SNAPSHOT_VERSION" in result.obligations
	not "ENFORCE_RESIDENCY_PRECONDITION" in result.obligations
}

test_us_adequacy_is_conditional_not_assumed if {
	result := data_governance.result with input as job({}, {}, {"operation": op("us-east-1", null)})
	result.transfer_mechanism == "SCC_MODULE_2_C2P"
	"EU_US_DPF" in result.pending_mechanisms
	result.rules_verdict == "HUMAN_REVIEW"
	"TRANSFER_MECHANISM_NEEDS_HUMAN_SIGN_OFF" in result.ambiguities
}

test_certified_importer_with_evidence_selects_dpf if {
	input_doc := job(
		{},
		{"importer_certified_dpf": true},
		{"operation": op("us-east-1", null), "evidence": {"dpf_program_participant_ref": "DPF-7781"}},
	)
	result := data_governance.result with input as input_doc
	result.transfer_mechanism == "EU_US_DPF"
	# A contract-based route is registered, not rubber-stamped.
	result.rules_verdict == "HUMAN_REVIEW"
}

test_scc_is_only_selected_when_every_document_is_on_file if {
	# Vega's tenant file carries the SCC, TRA and supplementary-measures refs.
	result := data_governance.result with input as job({}, {}, {"operation": op("in-mh-1", null)})
	result.transfer_mechanism == "SCC_MODULE_2_C2P"
	count(result.missing_evidence) == 0
}

test_unanswered_route_questions_review_rather_than_deny if {
	input_doc := job(
		{"relationship": null},
		{"importer_is_public_authority": null},
		{"operation": op("in-mh-1", null)},
	)
	result := data_governance.result with input as input_doc
	count(result.applicable_mechanisms) == 0
	count(result.pending_mechanisms) > 0
	result.transfer_mechanism == null
	result.rules_verdict == "REQUIRE_MECHANISM"
	"TRANSFER_ROUTE_PENDING_FACTS" in result.ambiguities
	result.terminal == false
	result.escalation.required == true
}

# The pillar-1 guardrail, stated for data instead of goods: a model can assert
# that a mechanism applies, but only a registered document makes it selectable.
test_claimed_mechanism_without_evidence_never_clears if {
	input_doc := job(
		{"relationship": "CONTROLLER_TO_PROCESSOR"},
		{"importer_certified_dpf": true, "data_subject_explicit_consent": true, "transfer_is_repetitive": false},
		{"operation": op("us-east-1", null), "evidence": {}},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict != "ALLOW"
	result.decision != "ALLOW"
	"EU_US_DPF" in result.applicable_mechanisms
	"dpf_program_participant_ref" in result.missing_evidence
}

test_derogation_never_auto_clears_even_perfectly_evidenced if {
	input_doc := job(
		{"relationship": null},
		{
			"importer_is_public_authority": null,
			"data_subject_explicit_consent": true,
			"transfer_is_repetitive": false,
		},
		{
			"operation": op("in-mh-1", null),
			"evidence": {"consent_record_ref": "CONSENT-VEGA-2026-01"},
		},
	)
	result := data_governance.result with input as input_doc
	result.transfer_mechanism == "DEROGATION_EXPLICIT_CONSENT"
	result.rules_verdict == "HUMAN_REVIEW"
	"MECHANISM_ABOVE_HUMAN_APPROVAL_CEILING" in result.ambiguities
}

# --- residency modes ---------------------------------------------------------

test_hard_localised_payment_data_cannot_leave_its_jurisdiction if {
	input_doc := job(
		{
			"registry_id": "reg-nw-payments",
			"purpose": "route_optimisation",
			"origin_jurisdiction": "IN",
			"categories": ["payment_card_data"],
		},
		{},
		{
			"tenant_id": "tnt_northwind_healthlogistics",
			"operation": op("ae-1", null),
		},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	result.terminal == true
	"HARD_LOCALISATION_VIOLATED" in result.ambiguities
	"TOKENISATION" in result.obligations
}

test_german_payroll_cannot_be_processed_in_france if {
	# Same bloc, different member state: BDSG S.26 keeps works-council data home.
	input_doc := job(
		{"registry_id": "reg-vega-payroll", "purpose": "statutory_reporting", "categories": ["employee_payroll"]},
		{},
		{"operation": op("eu-fr-1", null)},
	)
	result := data_governance.result with input as input_doc
	result.cross_border == true
	result.rules_verdict == "DENY"
	"RESIDENCY_MODE_NOT_SATISFIED_IN_DESTINATION" in result.ambiguities
	"WORKS_COUNCIL_CONSULTED" in result.obligations
}

test_vehicle_telemetry_below_k_is_not_an_anonymous_aggregate if {
	input_doc := telemetry("in-mh-1", 10)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"RESIDENCY_MODE_NOT_SATISFIED_IN_DESTINATION" in result.ambiguities
}

test_k_anonymised_telemetry_still_needs_a_lawful_route if {
	input_doc := telemetry("in-mh-1", 60)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "HUMAN_REVIEW"
	result.transfer_mechanism == "SCC_MODULE_2_C2P"
	"GEO_GENERALISATION_TO_H3_RES_5" in result.obligations
}

test_row_level_telemetry_read_in_region_is_fine if {
	result := data_governance.result with input as telemetry("eu-de-1", 60)
	result.cross_border == false
	result.residency[0].verdict == "ALLOW"
}

# --- the two policy packs meet here ----------------------------------------

test_technical_data_must_already_have_an_export_decision if {
	input_doc := job(
		{
			"registry_id": "reg-vega-line-telemetry",
			"purpose": "predictive_maintenance",
			"categories": ["manufacturing_process_telemetry"],
		},
		{},
		{},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "HUMAN_REVIEW"
	"TECHNICAL_DATA_NOT_YET_EXPORT_SCREENED" in result.ambiguities
	"RUN_EXPORT_CONTROL_PACK_FIRST" in result.obligations
}

test_technical_data_with_export_decision_ref_clears_that_screen if {
	input_doc := job(
		{
			"registry_id": "reg-vega-line-telemetry",
			"purpose": "predictive_maintenance",
			"categories": ["manufacturing_process_telemetry"],
		},
		{},
		{"evidence": {"export_control_decision_ref": "exp-dec-0001"}},
	)
	result := data_governance.result with input as input_doc
	not "TECHNICAL_DATA_NOT_YET_EXPORT_SCREENED" in result.ambiguities
	"TECHNICAL_DATA_EXPORT_SCREEN" in result.obligations
}

# --- special categories, purpose and retention -----------------------------

test_special_category_without_consent_document_is_rejected if {
	input_doc := job(
		{"registry_id": "reg-vega-occupational-health", "categories": ["health_or_biometric"]},
		{},
		{},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"SPECIAL_CATEGORY_WITHOUT_LAWFUL_BASIS_EVIDENCE" in result.ambiguities
}

test_tenant_level_consent_evidence_counts_if_the_request_omits_it if {
	input_doc := job(
		{
			"registry_id": "reg-nw-patient-route",
			"purpose": "route_optimisation",
			"origin_jurisdiction": "IN",
			"categories": ["health_or_biometric"],
		},
		{},
		{"tenant_id": "tnt_northwind_healthlogistics", "operation": op("in-mh-1", null)},
	)
	result := data_governance.result with input as input_doc
	not "SPECIAL_CATEGORY_WITHOUT_LAWFUL_BASIS_EVIDENCE" in result.ambiguities
	not "SPECIAL_CATEGORY_CONSENT_ON_FILE" in result.ambiguities
	"DPIA_REQUIRED" in result.obligations
}

test_purpose_prohibited_for_the_category_is_rejected if {
	input_doc := job(
		{
			"registry_id": "reg-nw-patient-route",
			"purpose": "price_optimisation",
			"origin_jurisdiction": "IN",
			"categories": ["health_or_biometric"],
		},
		{},
		{"tenant_id": "tnt_northwind_healthlogistics"},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"PURPOSE_PROHIBITED_FOR_DATA_CATEGORY" in result.ambiguities
}

test_retention_beyond_the_category_maximum_is_rejected if {
	input_doc := job({"retention_days_requested": 1000}, {}, {})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"RETENTION_EXCEEDS_CATEGORY_MAX" in result.ambiguities
}

test_category_not_declared_in_the_registry_stays_open if {
	# Kept inside India so the only thing this job fails on is the registry entry.
	input_doc := job(
		{
			"registry_id": "reg-nw-payments",
			"origin_jurisdiction": "IN",
			"categories": ["payment_card_data", "health_or_biometric"],
			"retention_days_requested": 60,
		},
		{},
		{
			"tenant_id": "tnt_northwind_healthlogistics",
			"operation": op("in-mh-1", null),
		},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "HUMAN_REVIEW"
	"DATA_CATEGORY_NOT_DECLARED_IN_REGISTRY" in result.ambiguities
}

test_category_with_no_residency_rule_is_not_treated_as_unrestricted if {
	input_doc := job({"categories": ["quantum_key_material"]}, {}, {})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "HUMAN_REVIEW"
	"CATEGORY_HAS_NO_RESIDENCY_RULE" in result.ambiguities
}

test_empty_payload_is_not_a_clearance if {
	input_doc := job({"categories": []}, {}, {})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "HUMAN_REVIEW"
	"PAYLOAD_HAS_NO_DECLARED_CATEGORIES" in result.ambiguities
}

# --- tenant sovereignty and geography --------------------------------------

test_unknown_tenant_has_no_policy_scope_and_is_rejected if {
	input_doc := job({}, {}, {"tenant_id": "tnt_does_not_exist"})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	result.terminal == true
	"TENANT_NOT_REGISTERED_NO_POLICY_SCOPE" in result.ambiguities
}

test_expressly_forbidden_region_beats_the_allowlist if {
	input_doc := job(
		{"registry_id": "reg-oc-shanghai-plant", "purpose": "predictive_maintenance", "origin_jurisdiction": "CN", "categories": ["customer_pii"], "subject_count": 500},
		{"cac_assessment_passed": false, "standard_contract_filed_with_provincial_cac": false},
		{"tenant_id": "tnt_orchid_mobility", "operation": op("eu-de-1", null)},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"REGION_EXPRESSLY_FORBIDDEN_FOR_TENANT" in result.ambiguities
}

test_region_outside_the_tenant_footprint_is_rejected if {
	input_doc := job({}, {}, {"operation": {"type": "CROSS_BORDER_ANALYTICS", "processing_region": "br-sp-1", "agent_id": null}})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"REGION_NOT_IN_TENANT_APPROVED_FOOTPRINT" in result.ambiguities
}

test_region_missing_from_the_topology_escalates if {
	input_doc := job({}, {}, {"operation": {"type": "CROSS_BORDER_ANALYTICS", "processing_region": "moon-1", "agent_id": null}})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "HUMAN_REVIEW"
	"PROCESSING_REGION_NOT_IN_TOPOLOGY" in result.ambiguities
}

test_registry_origin_overrides_the_job_manifest if {
	input_doc := job({"origin_jurisdiction": "AE"}, {}, {})
	result := data_governance.result with input as input_doc
	result.origin_jurisdiction == "DE"
	result.rules_verdict == "HUMAN_REVIEW"
	"MANIFEST_ORIGIN_DISAGREES_WITH_REGISTRY" in result.ambiguities
}

# --- sovereign volume thresholds -------------------------------------------

test_volume_above_the_cac_threshold_without_assessment_is_rejected if {
	input_doc := job(
		{
			"registry_id": "reg-oc-shanghai-plant",
			"purpose": "predictive_maintenance",
			"origin_jurisdiction": "CN",
			"categories": ["customer_pii"],
			"subject_count": 250000,
		},
		{"cac_assessment_passed": false, "standard_contract_filed_with_provincial_cac": false},
		{"tenant_id": "tnt_orchid_mobility", "operation": op("in-mh-1", null)},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"VOLUME_ABOVE_SOVEREIGN_THRESHOLD_WITHOUT_APPROVAL" in result.ambiguities
	"NO_LAWFUL_TRANSFER_ROUTE_AVAILABLE" in result.ambiguities
}

test_volume_approval_document_opens_the_route if {
	input_doc := job(
		{
			"registry_id": "reg-oc-shanghai-plant",
			"purpose": "predictive_maintenance",
			"origin_jurisdiction": "CN",
			"categories": ["customer_pii"],
			"subject_count": 250000,
		},
		{"cac_assessment_passed": true},
		{
			"tenant_id": "tnt_orchid_mobility",
			"operation": op("in-mh-1", null),
			"evidence": {"cac_filing_approval_ref": "CAC-SH-2026-0093"},
		},
	)
	result := data_governance.result with input as input_doc
	result.transfer_mechanism == "CN_CAC_SECURITY_ASSESSMENT"
	result.rules_verdict == "HUMAN_REVIEW"
	not "VOLUME_ABOVE_SOVEREIGN_THRESHOLD_WITHOUT_APPROVAL" in result.ambiguities
}

# --- agent envelopes ---------------------------------------------------------

test_unregistered_agent_is_rejected if {
	input_doc := job({}, {}, {"operation": op("eu-de-1", "agt-rogue")})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"AGENT_NOT_REGISTERED_FOR_TENANT" in result.ambiguities
}

test_agent_cannot_work_outside_its_registered_purpose if {
	input_doc := job({}, {}, {"operation": op("eu-de-1", "agt-pricing-scout-eu")})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"AGENT_PURPOSE_SCOPE_VIOLATION" in result.ambiguities
}

test_eu_pricing_agent_cannot_read_from_an_indian_region if {
	input_doc := job(
		{"purpose": "competitive_pricing_intelligence", "registry_id": "reg-vega-customer"},
		{},
		{"operation": op("in-mh-1", "agt-pricing-scout-eu")},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"AGENT_REGION_SCOPE_VIOLATION" in result.ambiguities
}

test_aggregate_only_agent_denied_row_level_read if {
	input_doc := job(
		{
			"registry_id": "reg-nw-patient-route",
			"purpose": "route_optimisation",
			"origin_jurisdiction": "IN",
			"categories": ["customer_pii"],
		},
		{},
		{"tenant_id": "tnt_northwind_healthlogistics", "operation": op("in-mh-1", "agt-route-optimizer-in")},
	)
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"AGENT_MUST_READ_AGGREGATES_ONLY" in result.ambiguities
}

test_agent_write_path_needs_explicit_pii_authorisation if {
	base := job({}, {}, {})
	input_doc := override(base, {"operation": {"type": "CROSS_BORDER_ANALYTICS", "processing_region": "eu-de-1", "agent_id": "agt-doc-intake-eu", "writes_pii": true}})
	result := data_governance.result with input as input_doc
	result.rules_verdict == "DENY"
	"AGENT_NOT_AUTHORISED_FOR_PII_WRITE_PATH" in result.ambiguities
}

# --- policy currency and determinism ---------------------------------------

test_stale_residency_table_escalates if {
	input_doc := job({}, {}, {"clock": {"milliseconds": much_later}})
	result := data_governance.result with input as input_doc
	"POLICY_TABLE_STALE_OR_NOT_EFFECTIVE" in result.ambiguities
	result.decision != "ALLOW"
}

test_decision_is_replayable_from_input_alone if {
	a := data_governance.result with input as job({}, {}, {})
	b := data_governance.result with input as job({}, {}, {})
	a.policy.digest == b.policy.digest
	a.replay.input_sha256 == b.replay.input_sha256
	a.decision == b.decision
	a.transfer_mechanism == b.transfer_mechanism
}

# -- totality ----------------------------------------------------------------
# A mistyped or empty request must produce a decision with reasons. If a rule
# went undefined the gate would stop applying silently, which is the failure mode
# this engine exists to prevent.

test_a_bare_request_still_reaches_a_decision if {
	result := data_governance.result with input as {}
	result.rules_verdict == "DENY"
	result.terminal == true
	"TENANT_NOT_REGISTERED_NO_POLICY_SCOPE" in result.ambiguities
	"PAYLOAD_HAS_NO_DECLARED_CATEGORIES" in result.ambiguities
	count(result.obligations) > 0
}

test_null_sections_behave_like_absent_sections if {
	nulls := {
		"tenant_id": "tnt_vega_manufacturing",
		"operation": null,
		"dataset": null,
		"flags": null,
		"evidence": null,
		"clock": {"milliseconds": now},
	}
	absent := {
		"tenant_id": "tnt_vega_manufacturing",
		"clock": {"milliseconds": now},
	}
	with_nulls := data_governance.result with input as nulls
	with_absent := data_governance.result with input as absent
	with_nulls.decision == with_absent.decision
	with_nulls.ambiguities == with_absent.ambiguities
	with_nulls.decision != "ALLOW"
}

test_a_non_list_category_field_escalates_instead_of_disappearing if {
	result := data_governance.result with input as job({"categories": "customer_pii"}, {}, {})
	result.rules_verdict == "HUMAN_REVIEW"
	"PAYLOAD_HAS_NO_DECLARED_CATEGORIES" in result.ambiguities
}
