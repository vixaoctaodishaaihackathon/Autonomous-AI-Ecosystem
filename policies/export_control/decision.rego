package policy.export_control
import rego.v1
import data.policy.common

# ===========================================================================
# Export control / dual-use determination.
#
# Asymmetry the whole design rests on:
#   * a RESTRICTIVE conclusion (licence required, denied) may be reached from
#     machine-extracted facts alone;
#   * a PERMISSIVE conclusion (this item is not controlled) may never rest on
#     machine-extracted facts alone - it needs an authoritative, traceable fact
#     or a human. Extraction can raise risk; it can never retire it.
# ===========================================================================

tables := data.tables.dual_use_controls
controls := object.get(tables, "controls", [])
contract := object.get(tables, "matching_contract", {})
catch_all_rules := object.get(tables, "catch_alls", [])
destination_table := object.get(data.tables.destinations, "destinations", {})

tenant := object.get(input, "tenant_id", "")
request_id := object.get(input, "request_id", null)
destination := object.get(input, "destination_country", "")
item := common.section(input, "item")
intent := common.section(input, "intent")
governance := common.section(input, "governance")
activity := object.get(intent, "activity", "EXPORT")
evidence := common.section(input, "evidence")
end_user := common.section(input, "end_user")
min_confidence := out if {
	value := object.get(governance, "min_fact_confidence", 0.85)
	is_number(value)
	out := value
}
default min_confidence := 0.85

# -- records ---------------------------------------------------------------
default dest_record := null

dest_record := r if {
	r := destination_table[destination]
}

tech_param_names := object.keys(technical_params)

default matched_control := null

matched_control := c if {
	count(matched_controls) == 1
	c := control_by_id(matched_controls[0])
}

# -- fact provenance -------------------------------------------------------
authoritative_sources := {"MANUAL_VERIFICATION", "CERTIFICATE", "DECLARATION", "SIGNED_SPEC_SHEET", "REGULATOR_RULING", "ERP_MASTER_DATA"}
# Anything a machine worked out, whether a model or a regex, sits here: it can
# raise risk but never retire it.
llm_sources := {"GEMINI_EXTRACTION", "LLM_EXTRACTION", "MODEL_EXTRACTED", "RULE_BASED_PARSER"}

default evidence_of(name) := {}

evidence_of(name) := ev if {
	p := technical_params[name]
	ev := object.get(p, "evidence", {})
}

fact_source(name) := object.get(evidence_of(name), "source", "UNKNOWN")

fact_traceable(name) := true if {
	object.get(evidence_of(name), "ref", "") != ""
}
default fact_traceable(name) := false

fact_llm_only(name) := true if {
	fact_source(name) in llm_sources
}
default fact_llm_only(name) := false

fact_authoritative(name) := true if {
	fact_source(name) in authoritative_sources
}
default fact_authoritative(name) := false

fact_under_confirmed(name) := true if {
	ev := evidence_of(name)
	confidence := object.get(ev, "confidence", null)
	is_number(confidence)
	confidence < min_confidence
}
default fact_under_confirmed(name) := false

untraceable_facts := out if {
	out := sort([n | n := tech_param_names[_]; not fact_traceable(n)])
}

llm_facts := out if {
	out := sort([n | n := tech_param_names[_]; fact_llm_only(n)])
}

under_confirmed_facts := out if {
	out := sort([n | n := tech_param_names[_]; fact_under_confirmed(n)])
}

# -- classification --------------------------------------------------------
params_of(ctrl) := names if {
	names := sort(control_params(ctrl))
}

control_ids_with(status) := out if {
	out := [c.control_id | c := controls[_]; control_status(c) == status]
}

matched_controls := out if {
	out := sort(control_ids_with("TRUE"))
}
indeterminate_controls := out if {
	out := sort(control_ids_with("INDETERMINATE"))
}
malformed_controls := out if {
	out := sort(control_ids_with("INVALID"))
}

engaged_params := out if {
	out := sort({p |
		c := controls[_]
		status := control_status(c)
		status != "NOT_APPLICABLE"
		names := params_of(c)
		p := names[_]
	})
}

missing_facts := out if {
	out := sort([p | p := engaged_params[_]; not param_present(p)])
}

control_by_id(id) := c if {
	c := controls[_]
	c.control_id == id
}

# -- exclusions ------------------------------------------------------------
exclusion_list(ctrl) := out if {
	out := object.get(ctrl, "exclusions", [])
}

exclusion_params(excl) := out if {
	conds := object.get(excl, "conditions", [])
	out := sort({p |
		c := conds[_]
		names := cond_params(c)
		p := names[_]
	} | {p | p := object.get(excl, "required_params", [])[_]})
}

evidence_has(key) := true if {
	value := object.get(evidence, key, null)
	value != null
	value != ""
	value != false
}
default evidence_has(key) := false

still_requires_met(excl) := true if {
	requires := object.get(excl, "still_requires", [])
	missing := [r | item := requires[_]; r := item; not evidence_has(r)]
	count(missing) == 0
}
default still_requires_met(excl) := false

# A clearance-grade exclusion must rest entirely on authoritative, traceable
# facts. One extracted parameter anywhere in the exclusion is enough to keep the
# item in review, because that single fact is what turned "controlled" into
# "exempt".
exclusion_facts_authoritative(excl) := true if {
	names := exclusion_params(excl)
	count(names) > 0
	every n in names {
		fact_authoritative(n)
	}
	every n in names {
		fact_traceable(n)
	}
}
default exclusion_facts_authoritative(excl) := false

exclusion_effect(excl) := object.get(excl, "effect", null)

exclusion_report(ctrl) := out if {
	out := [
		report
		|
		excl := exclusion_list(ctrl)[_]
		status := exclusion_status(excl)
		report := {
			"exclusion_id": excl.exclusion_id,
			"status": status,
			"effect": exclusion_effect(excl),
			"still_requires_met": still_requires_met(excl),
			"facts_authoritative": exclusion_facts_authoritative(excl),
			"blocks_clearance": blocks_clearance(excl),
		}
	]
}

blocks_clearance(excl) := true if {
	exclusion_status(excl) == "TRUE"
	not still_requires_met(excl)
}
blocks_clearance(excl) := true if {
	exclusion_status(excl) == "TRUE"
	not exclusion_facts_authoritative(excl)
}
blocks_clearance(excl) := true if {
	exclusion_status(excl) == "TRUE"
	exclusion_effect(excl) == "DOWNGRADE_TO_REVIEW"
}
default blocks_clearance(excl) := false

clearing_exclusions(ctrl) := out if {
	out := [
		excl.exclusion_id
		|
		excl := exclusion_list(ctrl)[_]
		exclusion_status(excl) == "TRUE"
		still_requires_met(excl)
		exclusion_facts_authoritative(excl)
		exclusion_effect(excl) != "DOWNGRADE_TO_REVIEW"
	]
}

blocking_exclusion_reports(ctrl) := out if {
	out := [
		{
			"exclusion_id": excl.exclusion_id,
			"reason": blocking_reason(excl),
		}
		|
		excl := exclusion_list(ctrl)[_]
		exclusion_status(excl) == "TRUE"
		blocks_clearance(excl)
	]
}

blocking_reason(excl) := "EXCLUSION_EVIDENCE_MISSING" if {
	not still_requires_met(excl)
}
blocking_reason(excl) := "EXCLUSION_RESTS_ON_EXTRACTED_FACTS" if {
	still_requires_met(excl)
	not exclusion_facts_authoritative(excl)
}
blocking_reason(excl) := "EXCLUSION_REQUIRES_HUMAN_VERIFICATION_BY_POLICY" if {
	still_requires_met(excl)
	exclusion_facts_authoritative(excl)
	exclusion_effect(excl) == "DOWNGRADE_TO_REVIEW"
}

# -- category scan ---------------------------------------------------------
scan_hits := out if {
	description := lower(object.get(item, "description", ""))
	out := [
		{"rule_id": rule.rule_id, "term": term}
		|
		rule := catch_all_rules[_]
		terms := object.get(rule, "terms", [])
		term := terms[_]
		contains(description, lower(term))
	]
}

# -- screens ---------------------------------------------------------------
make_screen(decision, reasons, obligations, refs) := out if {
	out := {
		"decision": decision,
		"reasons": reasons,
		"obligations": obligations,
		"refs": refs,
	}
}

allow_screen := out if {
	out := make_screen("ALLOW", [], [], [])
}

table_meta := object.get(tables, "authority", {})
table_report := common.table_report(table_meta)

screen_tables := out if {
	table_report.stale == false
	out := allow_screen
}
screen_tables := out if {
	table_report.stale == true
	out := make_screen("HUMAN_REVIEW", ["POLICY_TABLE_STALE_OR_NOT_EFFECTIVE"], ["REFRESH_CONTROL_LIST"], [table_report.table_version])
}

screen_integrity := out if {
	dest_record != null
	count(malformed_controls) == 0
	out := make_screen("ALLOW", [], [], [])
}
screen_integrity := out if {
	dest_record == null
	out := make_screen("HUMAN_REVIEW", ["DESTINATION_NOT_IN_RULE_TABLE"], ["ESCALATE_TO_TRADE_COMPLIANCE"], [destination])
}
screen_integrity := out if {
	dest_record != null
	count(malformed_controls) > 0
	out := make_screen("HUMAN_REVIEW", ["POLICY_TABLE_MALFORMED_CONDITION"], ["ESCALATE_TO_TRADE_COMPLIANCE"], malformed_controls)
}

# Default-deny posture: "no control matched" is never "uncontrolled".
screen_classification := out if {
	out := classified_screen
}

# The five classification outcomes below are mutually exclusive by construction.
classified_screen := out if {
	count(matched_controls) == 1
	out := control_outcome(matched_control)
}
classified_screen := out if {
	count(matched_controls) > 1
	out := make_screen("HUMAN_REVIEW", ["AMBIGUOUS_CLASSIFICATION_MULTIPLE_CONTROLS"], ["ESCALATE_TO_TRADE_COMPLIANCE"], matched_controls)
}
classified_screen := out if {
	count(matched_controls) == 0
	count(indeterminate_controls) > 0
	out := make_screen("HUMAN_REVIEW", ["INCOMPLETE_CLASSIFICATION_PARAMETER_UNRESOLVED"], ["SUPPLY_MISSING_TECHNICAL_PARAMETERS"], indeterminate_controls)
}
classified_screen := out if {
	count(matched_controls) == 0
	count(indeterminate_controls) == 0
	count(scan_hits) > 0
	out := make_screen("HUMAN_REVIEW", ["UNMATCHED_BUT_CONTROLLED_VOCABULARY_PRESENT"], ["ESCALATE_TO_TRADE_COMPLIANCE"], [hit.rule_id | hit := scan_hits[_]])
}
classified_screen := out if {
	count(matched_controls) == 0
	count(indeterminate_controls) == 0
	count(scan_hits) == 0
	out := make_screen(
		"HUMAN_REVIEW",
		["NO_CONTROL_MATCHED_REQUIRES_POSITIVE_DETERMINATION", "NO_MATCH_IS_NOT_THE_SAME_AS_UNCONTROLLED"],
		["ESCALATE_TO_TRADE_COMPLIANCE"],
		[contract.no_control_matched_outcome],
	)
}

control_outcome(ctrl) := out if {
	count(clearing_exclusions(ctrl)) > 0
	out := make_screen("ALLOW", ["CONTROL_CLEARED_BY_EVIDENCED_EXCLUSION"], ["RECORD_EXCLUSION_BASIS"], [ctrl.control_id])
}
control_outcome(ctrl) := out if {
	count(clearing_exclusions(ctrl)) == 0
	count(blocking_exclusion_reports(ctrl)) > 0
	reasons := [b.reason | b := blocking_exclusion_reports(ctrl)[_]]
	out := make_screen("HUMAN_REVIEW", reasons, ["ESCALATE_TO_TRADE_COMPLIANCE", "SUPPLY_EXCLUSION_EVIDENCE"], [ctrl.control_id])
}
control_outcome(ctrl) := out if {
	count(clearing_exclusions(ctrl)) == 0
	count(blocking_exclusion_reports(ctrl)) == 0
	requirement := object.get(ctrl, "licence_requirement", "EXPORT_AUTHORISATION")
	out := make_screen(licence_label(requirement), ["CONTROL_MATCHED"], ["DECLARE_CONTROL_CODE", "OBTAIN_EXPORT_AUTHORISATION", "BLOCK_SHIPMENT_PENDING_AUTHORISATION"], [ctrl.control_id])
}

licence_label("EXPORT_AUTHORISATION") := "REQUIRE_LICENCE"
licence_label("LICENCE_EXEMPT_NOTIFICATION") := "HUMAN_REVIEW"
licence_label("PROHIBITED") := "PROHIBITED"
licence_label(other) := "HUMAN_REVIEW" if {
	not other in {"EXPORT_AUTHORISATION", "LICENCE_EXEMPT_NOTIFICATION", "PROHIBITED"}
}

screen_destination := out if {
	dest_record == null
	out := make_screen("HUMAN_REVIEW", ["DESTINATION_UNKNOWN"], ["ESCALATE_TO_TRADE_COMPLIANCE"], [])
}
screen_destination := out if {
	dest_record != null
	presumption := object.get(dest_record, "presumption", "HUMAN_REVIEW")
	out := destination_outcome(presumption)
}

destination_outcome("PROHIBITED") := out if {
	out := make_screen("PROHIBITED", ["DESTINATION_EMBARGO_PROHIBITION"], ["STOP_NO_LICENCE_PATH"], [dest_record.name])
}
destination_outcome("DENY_REQUIRED") := out if {
	out := make_screen("DENY", ["DESTINATION_PRESUMPTION_OF_REFUSAL"], ["ESCALATE_TO_TRADE_COMPLIANCE", "SANCTIONS_DEROGATION_ASSESSMENT"], [dest_record.name])
}
destination_outcome("LICENCE") := out if {
	out := make_screen("REQUIRE_LICENCE", ["DESTINATION_CASE_BY_CASE_AUTHORISATION"], ["OBTAIN_EXPORT_AUTHORISATION", "END_USE_CERTIFICATE"], [dest_record.name])
}
destination_outcome("OPEN") := out if {
	out := make_screen("ALLOW", ["DESTINATION_GENERAL_AUTHORISATION_AVAILABLE"], ["CITE_GENERAL_AUTHORISATION_SCHEME"], [dest_record.name])
}
destination_outcome(other) := out if {
	not other in {"PROHIBITED", "DENY_REQUIRED", "LICENCE", "OPEN"}
	out := make_screen("HUMAN_REVIEW", ["DESTINATION_PRESUMPTION_UNMODELLED"], ["ESCALATE_TO_TRADE_COMPLIANCE"], [])
}

# Category override can only tighten the verdict, never loosen it.
override_entry := out if {
	dest_record != null
	matched_control != null
	overrides := object.get(dest_record, "category_overrides", {})
	out := object.get(overrides, matched_control.category, null)
}
default override_entry := null

screen_override := out if {
	override_entry == null
	out := allow_screen
}
screen_override := out if {
	override_entry == "DENY_REQUIRED"
	out := make_screen("DENY", ["DESTINATION_CATEGORY_OVERRIDE"], ["ESCALATE_TO_TRADE_COMPLIANCE"], [destination])
}
screen_override := out if {
	override_entry == "PROHIBITED"
	out := make_screen("PROHIBITED", ["DESTINATION_CATEGORY_OVERRIDE"], ["STOP_NO_LICENCE_PATH"], [destination])
}
screen_override := out if {
	override_entry != null
	override_entry != "DENY_REQUIRED"
	override_entry != "PROHIBITED"
	out := make_screen("REQUIRE_LICENCE", ["DESTINATION_CATEGORY_OVERRIDE"], ["OBTAIN_EXPORT_AUTHORISATION"], [destination])
}

screen_end_user := out if {
	status := object.get(end_user, "screening_status", "NOT_RUN")
	out := end_user_outcome(status)
}

end_user_outcome("CLEAR") := out if {
	out := make_screen("ALLOW", [], [], [object.get(end_user, "screening_ref", null)])
}
end_user_outcome("STALE") := out if {
	out := make_screen("HUMAN_REVIEW", ["END_USER_SCREENING_STALE"], ["RERUN_DENY_PARTY_SCREENING"], [])
}
end_user_outcome("NOT_RUN") := out if {
	out := make_screen("HUMAN_REVIEW", ["END_USER_SCREENING_ABSENT"], ["RERUN_DENY_PARTY_SCREENING"], [])
}
end_user_outcome("HIT") := out if {
	out := make_screen("DENY", ["DENY_PARTY_HIT"], ["STOP_AND_REPORT"], [object.get(end_user, "screening_ref", null)])
}
end_user_outcome(other) := out if {
	not other in {"CLEAR", "STALE", "NOT_RUN", "HIT"}
	out := make_screen("HUMAN_REVIEW", ["END_USER_SCREENING_STATUS_UNKNOWN"], ["ESCALATE_TO_TRADE_COMPLIANCE"], [])
}

red_flag_indicators := out if {
	indicators := object.get(end_user, "indicators", [])
	out := sort([i | i := indicators[_]])
}

screen_red_flags := out if {
	count(red_flag_indicators) > 0
	out := make_screen("HUMAN_REVIEW", ["RED_FLAG_INDICATORS_PRESENT"], ["END_USE_STATEMENT_REQUIRED", "ESCALATE_TO_TRADE_COMPLIANCE"], red_flag_indicators)
}
screen_red_flags := out if {
	count(red_flag_indicators) == 0
	out := allow_screen
}

# Intangible transfers of technology need authorisation just like shipments.
screen_activity := out if {
	activity in ["PROVIDE_TECHNOLOGY", "TRANSFER", "REEXPORT"]
	count(matched_controls) > 0
	out := make_screen("REQUIRE_LICENCE", ["INTANGIBLE_TECHNOLOGY_TRANSFER_IS_CONTROLLED"], ["AUTHORISE_TECHNICAL_DATA_ACCESS"], [activity])
}
screen_activity := out if {
	activity in ["PROVIDE_TECHNOLOGY", "TRANSFER", "REEXPORT"]
	count(matched_controls) == 0
	out := make_screen("HUMAN_REVIEW", ["TECHNOLOGY_TRANSFER_CLASSIFICATION_UNRESOLVED"], ["ESCALATE_TO_TRADE_COMPLIANCE"], [activity])
}
screen_activity := out if {
	not activity in ["PROVIDE_TECHNOLOGY", "TRANSFER", "REEXPORT"]
	out := allow_screen
}

# A permissive verdict may not stand on extracted facts alone.
permissive_basis_weak := true if {
	names := engaged_params
	llm_only := [n | n := names[_]; fact_llm_only(n)]
	authoritative := [n | n := names[_]; fact_authoritative(n)]
	count(llm_only) > 0
	count(authoritative) == 0
}
default permissive_basis_weak := false

would_clear_item := true if {
	count(matched_controls) == 1
	count(clearing_exclusions(matched_control)) > 0
}
default would_clear_item := false

# The item would clear on the strength of an exclusion, but nothing behind that
# exclusion is authoritative. This is the one state the extraction gate exists to
# stop, and it has to be a single boolean so the screens below stay exclusive.
extraction_only_clear := true if {
	would_clear_item
	permissive_basis_weak
}
default extraction_only_clear := false

screen_evidence := out if {
	count(untraceable_facts) > 0
	out := make_screen("HUMAN_REVIEW", ["UNTRACEABLE_FACT_PROVENANCE"], ["ATTACH_EVIDENCE_REF_TO_FACTS"], untraceable_facts)
}
screen_evidence := out if {
	count(untraceable_facts) == 0
	count(under_confirmed_facts) > 0
	out := make_screen("HUMAN_REVIEW", ["FACT_CONFIDENCE_BELOW_THRESHOLD"], ["HUMAN_CONFIRM_TECHNICAL_PARAMETERS"], under_confirmed_facts)
}
screen_evidence := out if {
	count(untraceable_facts) == 0
	count(under_confirmed_facts) == 0
	extraction_only_clear
	out := make_screen("HUMAN_REVIEW", ["EXTRACTION_ALONE_CANNOT_CLEAR_AN_ITEM"], ["HUMAN_CONFIRM_TECHNICAL_PARAMETERS"], llm_facts)
}
screen_evidence := out if {
	count(untraceable_facts) == 0
	count(under_confirmed_facts) == 0
	not extraction_only_clear
	out := allow_screen
}

screen_fact_units := out if {
	count(unit_invalid_params) == 0
	out := allow_screen
}
screen_fact_units := out if {
	count(unit_invalid_params) > 0
	out := make_screen("HUMAN_REVIEW", ["FACT_UNIT_NOT_RESOLVED"], ["NORMALISE_UNITS_BEFORE_DECISION"], unit_invalid_params)
}

unit_invalid_params := out if {
	out := sort([n | n := tech_param_names[_]; param_present(n); not unit_ok(n)])
}

# A valid authorisation can satisfy a licence requirement -------------------
licence_object := out if {
	out := object.get(evidence, "export_authorisation", null)
}
default licence_object := null

licence_covers_destination := true if {
	destinations := object.get(licence_object, "destinations", [])
	destination in destinations
}
default licence_covers_destination := false

licence_covers_category := true if {
	categories := object.get(licence_object, "categories", [])
	matched_control != null
	matched_control.category in categories
}
default licence_covers_category := false

licence_not_expired := true if {
	expiry := object.get(licence_object, "valid_until_ms", null)
	is_number(expiry)
	is_number(common.clock_ms)
	expiry > common.clock_ms
}
default licence_not_expired := false

licence_reference_present := true if {
	object.get(licence_object, "reference", "") != ""
}
default licence_reference_present := false

authorisation_valid := true if {
	licence_reference_present
	licence_covers_destination
	licence_covers_category
	licence_not_expired
}
default authorisation_valid := false

resolve_licence(d) := "ALLOW" if {
	d == "REQUIRE_LICENCE"
	authorisation_valid
	count(indeterminate_controls) == 0
	count(malformed_controls) == 0
}
resolve_licence(d) := "REQUIRE_LICENCE" if {
	d == "REQUIRE_LICENCE"
	not authorisation_valid
}
resolve_licence(d) := d if {
	d != "REQUIRE_LICENCE"
}

screens := out if {
	out := [
		screen_tables,
		screen_integrity,
		screen_classification,
		screen_destination,
		screen_override,
		screen_end_user,
		screen_red_flags,
		screen_activity,
		screen_evidence,
		screen_fact_units,
	]
}

uncapped_decision := out if {
	restricted := common.most_restrictive({s.decision | s := screens[_]})
	out := resolve_licence(restricted)
}

authority_unverified := true if {
	table_report.unverified_authority == true
}
default authority_unverified := false

final_decision := out if {
	authority_unverified
	out := common.cap(uncapped_decision, "HUMAN_REVIEW")
}
final_decision := out if {
	not authority_unverified
	out := uncapped_decision
}

ambiguities := out if {
	out := sort({r | s := screens[_]; r := s.reasons[_]})
}

obligations := out if {
	out := sort({o | s := screens[_]; o := s.obligations[_]})
}

basis_refs := out if {
	out := sort({r | s := screens[_]; r := s.refs[_]; r != null})
}

control_reports := out if {
	out := [
		{
			"control_id": ctrl.control_id,
			"status": control_status(ctrl),
			"present_params": params_of(ctrl),
			"missing_params": [p | p := params_of(ctrl)[_]; not param_present(p)],
			"exclusions": exclusion_report(ctrl),
		}
		|
		ctrl := controls[_]
		status := control_status(ctrl)
		status != "NOT_APPLICABLE"
	]
}

result := out if {
	out := {
		"engine": "export_control",
		"pack": "policy.export_control",
		"request_id": request_id,
		"tenant_id": tenant,
		"destination": destination,
		"activity": activity,
		"decision": final_decision,
		"rules_verdict": uncapped_decision,
		"terminal": final_decision in {"ALLOW", "PROHIBITED", "DENY"},
		"control_code": control_code_value,
		"matched_controls": matched_controls,
		"candidate_controls": indeterminate_controls,
		"controls": control_reports,
		"ambiguities": ambiguities,
		"missing_facts": missing_facts,
		"obligations": obligations,
		"basis": basis_refs,
		"evidence_quality": {
			"llm_sourced_params": llm_facts,
			"untraceable_params": untraceable_facts,
			"under_confirmed_params": under_confirmed_facts,
			"clearance_allowed_from_extraction_alone": false,
		},
		"authority_ceiling_applied": authority_unverified,
		"escalation": {
			"required": final_decision in {"HUMAN_REVIEW", "REQUIRE_LICENCE"},
			"queue": "trade_compliance",
			"sla_hours": object.get(governance, "review_sla_hours", 24),
		},
		"policy": {
			"digest": common.policy_digest([table_report, matched_controls, final_decision]),
			"tables": [table_report],
			"authority_unverified_tables": unverified_table_ids,
			"clock_ms": common.clock_ms,
		},
		"replay": {
			"input_sha256": crypto.sha256(json.marshal(input)),
		},
	}
}

control_code_value := out if {
	count(matched_controls) >= 1
	out := matched_controls[0]
}
default control_code_value := null

unverified_table_ids := out if {
	table_report.unverified_authority == true
	out := [table_report.table_id]
}
default unverified_table_ids := []
