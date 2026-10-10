package policy.export_control_test
import rego.v1
import data.policy.export_control

# 2026-10-10T12:00:00Z - inside every table's effective window and review cadence.
now := 1791633600000
# 2027-06-01T00:00:00Z - past the dual-use table's 180-day cadence.
much_later := 1811808000000

ev(source, ref) := {"source": source, "ref": ref, "quote": "as printed in the source document", "confidence": 0.99}

fp(value, unit, source, ref) := {"value": value, "unit": unit, "evidence": ev(source, ref)}

# object.union deep-merges nested objects, which would silently leak the default
# end_user / evidence into tests meant to remove them, so overrides replace
# top-level keys here.
override(defaults, extra) := out if {
	keys := {k | k := object.keys(defaults)[_]} | {k | k := object.keys(extra)[_]}
	out := {k: object.get(extra, k, object.get(defaults, k, null)) | some k in keys}
}

simple(params) := req(params, {})

req(params, extra) := out if {
	defaults := {
		"request_id": "req-0001",
		"tenant_id": "tnt_vega_manufacturing",
		"destination_country": "DE",
		"intent": {"activity": "EXPORT"},
		"item": {
			"sku": "VCU-500",
			"description": "vehicle domain controller assembly",
			"technical_parameters": params,
		},
		"end_user": {"screening_status": "CLEAR", "screening_ref": "scr-99"},
		"evidence": {},
		"clock": {"milliseconds": now},
	}
	out := override(defaults, extra)
}

crypto_params(source) := {
	"crypto_function": fp(true, null, source, "spec-1"),
	"symmetric_key_bits": fp(256, "bit", source, "spec-1"),
}

mass_market(source) := {
	"crypto_function": fp(true, null, source, "spec-1"),
	"symmetric_key_bits": fp(128, "bit", source, "spec-1"),
	"mass_market_declared": fp(true, null, "CERTIFICATE", "cert-4"),
	"generally_available_retail": fp(true, null, "DECLARATION", "decl-4"),
	"crypto_algorithm_custom": fp(false, null, source, "spec-1"),
	"source_code_available_for_declassification": fp(true, null, "SIGNED_SPEC_SHEET", "spec-1"),
}

notification := {"declassification_or_notification_evidence": "EX-2026-113"}

# --- classification --------------------------------------------------------

test_controlled_encryption_requires_authorisation if {
	result := export_control.result with input as simple(crypto_params("MANUAL_VERIFICATION"))
	result.rules_verdict == "REQUIRE_LICENCE"
	result.control_code == "5A002"
}

test_authorisation_satisfies_licence_requirement if {
	doc := req(
		crypto_params("MANUAL_VERIFICATION"),
		{
			"evidence": {
				"export_authorisation": {
					"reference": "BAFA-2026-0042",
					"destinations": ["DE", "US"],
					"categories": ["5.A"],
					"valid_until_ms": 1893456000000,
				},
			},
		},
	)
	result := export_control.result with input as doc
	result.rules_verdict == "ALLOW"
}

test_no_control_match_is_not_the_same_as_uncontrolled if {
	result := export_control.result with input as simple({
		"positioning_accuracy_um": fp(12.5, "um", "MANUAL_VERIFICATION", "spec-2"),
	})
	result.rules_verdict == "HUMAN_REVIEW"
	"NO_CONTROL_MATCHED_REQUIRES_POSITIVE_DETERMINATION" in result.ambiguities
}

test_partial_parameters_are_indeterminate_not_clear if {
	result := export_control.result with input as simple({
		"crypto_function": fp(true, null, "MANUAL_VERIFICATION", "spec-1"),
	})
	result.rules_verdict == "HUMAN_REVIEW"
	"INCOMPLETE_CLASSIFICATION_PARAMETER_UNRESOLVED" in result.ambiguities
}

test_two_controls_matching_is_ambiguous if {
	params := object.union(crypto_params("MANUAL_VERIFICATION"), {
		"cotp_mops": fp(900, "Mtops", "MANUAL_VERIFICATION", "spec-3"),
	})
	result := export_control.result with input as simple(params)
	result.rules_verdict == "HUMAN_REVIEW"
	"AMBIGUOUS_CLASSIFICATION_MULTIPLE_CONTROLS" in result.ambiguities
}

test_wrong_unit_invalidates_the_fact if {
	result := export_control.result with input as simple({
		"crypto_function": fp(true, null, "MANUAL_VERIFICATION", "spec-1"),
		"symmetric_key_bits": fp(0.25, "kbit", "MANUAL_VERIFICATION", "spec-1"),
	})
	"FACT_UNIT_NOT_RESOLVED" in result.ambiguities
	result.rules_verdict == "HUMAN_REVIEW"
}

test_controlled_vocabulary_without_parameters_escalates if {
	params := {"max_data_transfer_rate_mbps": fp(10, "Mbit/s", "MANUAL_VERIFICATION", "spec-4")}
	item := {"sku": "X", "description": "quantum key distribution module", "technical_parameters": params}
	result := export_control.result with input as override(simple(params), {"item": item})
	result.rules_verdict == "HUMAN_REVIEW"
	"UNMATCHED_BUT_CONTROLLED_VOCABULARY_PRESENT" in result.ambiguities
}

# --- extraction may raise risk, never retire it ----------------------------

test_extraction_alone_cannot_claim_mass_market if {
	doc := req(mass_market("GEMINI_EXTRACTION"), {"evidence": notification})
	result := export_control.result with input as doc
	result.rules_verdict == "HUMAN_REVIEW"
	"EXCLUSION_RESTS_ON_EXTRACTED_FACTS" in result.ambiguities
}

test_human_confirmed_mass_market_exclusion_clears if {
	result := export_control.result with input as req(mass_market("MANUAL_VERIFICATION"), {"evidence": notification})
	result.rules_verdict == "ALLOW"
}

test_incidental_crypto_claim_always_needs_a_human if {
	car := {
		"crypto_function": fp(true, null, "MANUAL_VERIFICATION", "spec-1"),
		"symmetric_key_bits": fp(128, "bit", "MANUAL_VERIFICATION", "spec-1"),
		"primary_function_is_crypto": fp(false, null, "MANUAL_VERIFICATION", "teardown-9"),
		"crypto_algorithm_custom": fp(false, null, "MANUAL_VERIFICATION", "teardown-9"),
	}
	doc := req(car, {"evidence": {"primary_function_teardown_evidence": "TD-9"}})
	result := export_control.result with input as doc
	result.rules_verdict == "HUMAN_REVIEW"
	"EXCLUSION_REQUIRES_HUMAN_VERIFICATION_BY_POLICY" in result.ambiguities
}

test_exclusion_without_its_own_evidence_stays_open if {
	result := export_control.result with input as simple(mass_market("MANUAL_VERIFICATION"))
	result.rules_verdict == "HUMAN_REVIEW"
	"EXCLUSION_EVIDENCE_MISSING" in result.ambiguities
}

test_untraceable_fact_blocks_decision if {
	params := {
		"crypto_function": {"value": true, "unit": null, "evidence": {"source": "MANUAL_VERIFICATION", "ref": "", "confidence": 0.99}},
	}
	result := export_control.result with input as simple(params)
	"UNTRACEABLE_FACT_PROVENANCE" in result.ambiguities
}

test_low_confidence_extraction_needs_confirmation if {
	params := {
		"crypto_function": {"value": true, "unit": null, "evidence": {"source": "GEMINI_EXTRACTION", "ref": "doc-1#p2", "quote": "AES-256", "confidence": 0.41}},
		"symmetric_key_bits": {"value": 256, "unit": "bit", "evidence": {"source": "GEMINI_EXTRACTION", "ref": "doc-1#p2", "quote": "AES-256", "confidence": 0.41}},
	}
	result := export_control.result with input as simple(params)
	"FACT_CONFIDENCE_BELOW_THRESHOLD" in result.ambiguities
}

# --- destination, end user, activity --------------------------------------

test_embargoed_destination_is_prohibited_even_if_unclassified if {
	doc := req(
		{"positioning_accuracy_um": fp(12.5, "um", "MANUAL_VERIFICATION", "spec-2")},
		{"destination_country": "KP"},
	)
	result := export_control.result with input as doc
	result.decision == "PROHIBITED"
	result.terminal == true
}

test_high_risk_destination_denies_before_licence if {
	doc := req(crypto_params("MANUAL_VERIFICATION"), {"destination_country": "RU"})
	result := export_control.result with input as doc
	result.rules_verdict == "DENY"
	"SANCTIONS_DEROGATION_ASSESSMENT" in result.obligations
}

test_category_override_only_tightens if {
	doc := req(crypto_params("MANUAL_VERIFICATION"), {"destination_country": "CN"})
	result := export_control.result with input as doc
	result.rules_verdict == "DENY"
	"DESTINATION_CATEGORY_OVERRIDE" in result.ambiguities
}

test_missing_denyparty_screen_never_allows if {
	doc := req(crypto_params("MANUAL_VERIFICATION"), {"end_user": {}})
	result := export_control.result with input as doc
	"END_USER_SCREENING_ABSENT" in result.ambiguities
	result.rules_verdict != "ALLOW"
}

test_deny_party_hit_denies if {
	doc := req(
		crypto_params("MANUAL_VERIFICATION"),
		{"end_user": {"screening_status": "HIT", "screening_ref": "scr-3"}},
	)
	result := export_control.result with input as doc
	result.rules_verdict == "DENY"
}

test_red_flag_indicator_escalates_to_human if {
	doc := req(
		mass_market("MANUAL_VERIFICATION"),
		{
			"evidence": notification,
			"end_user": {"screening_status": "CLEAR", "screening_ref": "scr-1", "indicators": ["freight_forwarder_unrelated_to_order"]},
		},
	)
	result := export_control.result with input as doc
	result.rules_verdict == "HUMAN_REVIEW"
	"RED_FLAG_INDICATORS_PRESENT" in result.ambiguities
}

test_intangible_technology_transfer_is_controlled if {
	params := {"simultaneously_controllable_axes": fp(5, "count", "MANUAL_VERIFICATION", "spec-5")}
	doc := req(params, {"intent": {"activity": "PROVIDE_TECHNOLOGY"}})
	result := export_control.result with input as doc
	"INTANGIBLE_TECHNOLOGY_TRANSFER_IS_CONTROLLED" in result.ambiguities
	result.rules_verdict == "REQUIRE_LICENCE"
}

test_expired_authorisation_does_not_clear if {
	doc := req(
		crypto_params("MANUAL_VERIFICATION"),
		{
			"evidence": {
				"export_authorisation": {
					"reference": "BAFA-2025-9999",
					"destinations": ["DE"],
					"categories": ["5.A"],
					"valid_until_ms": 1700000000000,
				},
			},
		},
	)
	result := export_control.result with input as doc
	result.rules_verdict == "REQUIRE_LICENCE"
}

test_authorisation_for_other_destination_does_not_clear if {
	doc := req(
		crypto_params("MANUAL_VERIFICATION"),
		{
			"evidence": {
				"export_authorisation": {
					"reference": "BAFA-2026-0043",
					"destinations": ["US"],
					"categories": ["5.A"],
					"valid_until_ms": 1893456000000,
				},
			},
		},
	)
	result := export_control.result with input as doc
	result.rules_verdict == "REQUIRE_LICENCE"
}

# --- policy authority and freshness ---------------------------------------

test_unverified_rule_tables_cap_every_clearance if {
	doc := req(mass_market("MANUAL_VERIFICATION"), {"evidence": notification})
	result := export_control.result with input as doc
	result.rules_verdict == "ALLOW"
	result.decision == "HUMAN_REVIEW"
	result.authority_ceiling_applied == true
}

test_stale_rule_table_escalates if {
	doc := req(crypto_params("MANUAL_VERIFICATION"), {"clock": {"milliseconds": much_later}})
	result := export_control.result with input as doc
	"POLICY_TABLE_STALE_OR_NOT_EFFECTIVE" in result.ambiguities
}

test_missing_clock_is_not_silently_treated_as_current if {
	doc := object.remove(simple(crypto_params("MANUAL_VERIFICATION")), ["clock"])
	result := export_control.result with input as doc
	"POLICY_TABLE_STALE_OR_NOT_EFFECTIVE" in result.ambiguities
	# A clockless request can be escalated (licence required) but never cleared.
	result.decision != "ALLOW"
	result.policy.clock_ms == null
}

test_unknown_destination_never_allows if {
	doc := req(crypto_params("MANUAL_VERIFICATION"), {"destination_country": "XX"})
	result := export_control.result with input as doc
	"DESTINATION_NOT_IN_RULE_TABLE" in result.ambiguities
}

test_decision_is_replayable_from_input_alone if {
	a := export_control.result with input as simple(crypto_params("MANUAL_VERIFICATION"))
	b := export_control.result with input as simple(crypto_params("MANUAL_VERIFICATION"))
	a.policy.digest == b.policy.digest
	a.replay.input_sha256 == b.replay.input_sha256
	a.decision == b.decision
}

# -- totality ----------------------------------------------------------------

test_a_bare_request_still_reaches_a_decision if {
	result := export_control.result with input as {}
	result.rules_verdict == "HUMAN_REVIEW"
	result.terminal == false
	result.escalation.required == true
	count(result.ambiguities) > 0
}

test_null_sections_behave_like_absent_sections if {
	nulls := {
		"tenant_id": "tnt_vega_manufacturing",
		"item": null,
		"intent": null,
		"evidence": null,
		"end_user": null,
		"governance": null,
		"clock": {"milliseconds": 1791633600000},
	}
	absent := {
		"tenant_id": "tnt_vega_manufacturing",
		"clock": {"milliseconds": 1791633600000},
	}
	with_nulls := export_control.result with input as nulls
	with_absent := export_control.result with input as absent
	with_nulls.decision == with_absent.decision
	with_nulls.ambiguities == with_absent.ambiguities
	with_nulls.decision != "ALLOW"
}
