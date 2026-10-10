package policy.data_governance
import rego.v1
import data.policy.common

# ===========================================================================
# Screens for the cross-border transfer gate. Each screen returns
# {decision, reasons, obligations, refs}; the verdict is the most restrictive,
# then capped by rule-table authority and by the selected mechanism's ceiling.
# ===========================================================================

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

governance := common.section(input, "governance")

screen_tenant := out if {
	tenant == null
	out := make_screen("DENY", ["TENANT_NOT_REGISTERED_NO_POLICY_SCOPE"], ["REJECT_JOB_DISPATCH"], [tenant_id])
}
screen_tenant := out if {
	tenant != null
	tenant_registry == null
	out := make_screen("HUMAN_REVIEW", ["REGISTRY_NOT_DECLARED_BY_TENANT"], ["REGISTER_DATA_REGISTRY"], [registry_id])
}
screen_tenant := out if {
	tenant != null
	tenant_registry != null
	count(unknown_categories) > 0
	out := make_screen("HUMAN_REVIEW", ["CATEGORY_HAS_NO_RESIDENCY_RULE"], ["EXTEND_RESIDENCY_TABLE"], unknown_categories)
}
screen_tenant := out if {
	tenant != null
	tenant_registry != null
	count(unknown_categories) == 0
	count(undeclared_categories) > 0
	out := make_screen("HUMAN_REVIEW", ["DATA_CATEGORY_NOT_DECLARED_IN_REGISTRY"], ["RECLASSIFY_PAYLOAD"], undeclared_categories)
}
screen_tenant := out if {
	tenant != null
	tenant_registry != null
	count(undeclared_categories) == 0
	count(unknown_categories) == 0
	out := allow_screen
}

origin_disagreement := out if {
	origin_conflict
	out := make_screen("HUMAN_REVIEW", ["MANIFEST_ORIGIN_DISAGREES_WITH_REGISTRY"], ["TRUST_REGISTRY_ORIGIN"], [registry_jurisdiction])
}
origin_disagreement := out if {
	not origin_conflict
	out := allow_screen
}

screen_region := out if {
	region_known
	processing_region in forbidden_regions
	out := make_screen("DENY", ["REGION_EXPRESSLY_FORBIDDEN_FOR_TENANT"], ["REJECT_JOB_DISPATCH"], [processing_region])
}
screen_region := out if {
	region_known
	not processing_region in forbidden_regions
	not processing_region in approved_regions
	out := make_screen("DENY", ["REGION_NOT_IN_TENANT_APPROVED_FOOTPRINT"], ["REJECT_JOB_DISPATCH"], [processing_region])
}
screen_region := out if {
	not region_known
	out := make_screen("HUMAN_REVIEW", ["PROCESSING_REGION_NOT_IN_TOPOLOGY"], ["REFRESH_REGION_TABLE"], [processing_region])
}
screen_region := out if {
	region_known
	processing_region in approved_regions
	not processing_region in forbidden_regions
	out := allow_screen
}

screen_purpose := out if {
	purpose in approved_purposes
	count(prohibited_purpose_hits) == 0
	out := allow_screen
}
screen_purpose := out if {
	not purpose in approved_purposes
	count(prohibited_purpose_hits) == 0
	out := make_screen("DENY", ["PURPOSE_OUTSIDE_CONTRACTED_SCOPE"], ["REJECT_JOB_DISPATCH"], [purpose])
}
screen_purpose := out if {
	count(prohibited_purpose_hits) > 0
	out := make_screen("DENY", ["PURPOSE_PROHIBITED_FOR_DATA_CATEGORY"], ["REJECT_JOB_DISPATCH"], prohibited_purpose_hits)
}

residency_verdict_set := out if {
	out := {item.verdict | item := residency_evaluations[_]}
}

# A category that needs a transfer mechanism stops being an open question once a
# registered, evidenced mechanism has actually been selected: from that point the
# binding constraint is the named human signing it, not a missing route. Without
# a route the verdict stays REQUIRE_MECHANISM so the pipeline knows why it halted.
gate_verdict(v) := "HUMAN_REVIEW" if {
	v == "REQUIRE_MECHANISM"
	selected_mechanism != null
}
gate_verdict(v) := v if {
	v != "REQUIRE_MECHANISM"
}
gate_verdict(v) := v if {
	v == "REQUIRE_MECHANISM"
	selected_mechanism == null
}

residency_gate_verdicts := out if {
	out := {gate_verdict(v) | some v in residency_verdict_set}
}

residency_open_items := out if {
	out := [item | item := residency_evaluations[_]; item.verdict != "ALLOW"]
}

screen_residency := out if {
	count(categories) > 0
	count(residency_verdict_set) > 0
	count(residency_open_items) == 0
	out := allow_screen
}
screen_residency := out if {
	count(categories) > 0
	count(residency_verdict_set) > 0
	count(residency_open_items) > 0
	out := make_screen(
		common.most_restrictive(residency_gate_verdicts),
		sort([residency_reason(item.category) | item := residency_open_items[_]]),
		["ENFORCE_RESIDENCY_PRECONDITION"],
		sort([item.category | item := residency_open_items[_]]),
	)
}
screen_residency := out if {
	count(categories) == 0
	out := make_screen("HUMAN_REVIEW", ["PAYLOAD_HAS_NO_DECLARED_CATEGORIES"], ["CLASSIFY_PAYLOAD"], [])
}
# Categories were declared but none of them resolves to a rule, so residency
# simply cannot be stated. Escalate rather than let the gate fall silent.
screen_residency := out if {
	count(categories) > 0
	count(residency_verdict_set) == 0
	out := make_screen("HUMAN_REVIEW", ["RESIDENCY_STATE_UNDETERMINED"], ["CLASSIFY_PAYLOAD"], sort(categories))
}

screen_mechanism := out if {
	not cross_border
	out := allow_screen
}
# Adequacy (or an equivalent) can satisfy residency outright, so no category is
# left asking for a mechanism - but the route that was still selected carries its
# standing obligations with it.
screen_mechanism := out if {
	cross_border
	count(residency_needs_categories) == 0
	out := make_screen("ALLOW", [], common.field(selected_mechanism_record, "obligations", []), [selected_mechanism])
}
screen_mechanism := out if {
	cross_border
	count(residency_needs_categories) > 0
	selected_mechanism != null
	mechanism_ceiling != null
	out := make_screen(mechanism_ceiling, ["MECHANISM_ABOVE_HUMAN_APPROVAL_CEILING"], ["ESCALATE_TO_PRIVACY_OFFICE"], [selected_mechanism])
}
screen_mechanism := out if {
	cross_border
	count(residency_needs_categories) > 0
	selected_mechanism != null
	mechanism_ceiling == null
	not mechanism_auto_clears
	out := make_screen("HUMAN_REVIEW", ["TRANSFER_MECHANISM_NEEDS_HUMAN_SIGN_OFF"], ["ESCALATE_TO_PRIVACY_OFFICE", "TRANSFER_REGISTER_ENTRY"], [selected_mechanism])
}
screen_mechanism := out if {
	cross_border
	count(residency_needs_categories) > 0
	selected_mechanism != null
	mechanism_ceiling == null
	mechanism_auto_clears
	out := make_screen("ALLOW", [], common.field(selected_mechanism_record, "obligations", []), [selected_mechanism])
}
screen_mechanism := out if {
	cross_border
	count(residency_needs_categories) > 0
	selected_mechanism == null
	count(applicable_mechanism_ids) > 0
	out := make_screen("HUMAN_REVIEW", ["MECHANISM_APPLICABLE_BUT_UNEVIDENCED"], ["ATTACH_TRANSFER_EVIDENCE"], unmet_evidence)
}
screen_mechanism := out if {
	cross_border
	count(residency_needs_categories) > 0
	selected_mechanism == null
	count(applicable_mechanism_ids) == 0
	count(pending_mechanism_ids) > 0
	out := make_screen("HUMAN_REVIEW", ["TRANSFER_ROUTE_PENDING_FACTS"], ["ANSWER_TRANSFER_QUESTIONNAIRE"], pending_mechanism_ids)
}
screen_mechanism := out if {
	cross_border
	count(residency_needs_categories) > 0
	selected_mechanism == null
	count(applicable_mechanism_ids) == 0
	count(pending_mechanism_ids) == 0
	out := make_screen("DENY", ["NO_LAWFUL_TRANSFER_ROUTE_AVAILABLE"], ["REJECT_JOB_DISPATCH"], [effective_origin, processing_jurisdiction])
}

residency_needs_categories := out if {
	out := sort([item.category | item := residency_evaluations[_]; item.verdict == "REQUIRE_MECHANISM"])
}

screen_special_category := out if {
	count(special_categories_present) == 0
	out := allow_screen
}
screen_special_category := out if {
	count(special_categories_present) > 0
	evidence_present("consent_record_ref")
	out := make_screen("ALLOW", [], ["CONSENT_WITHDRAWAL_ROUTING"], special_categories_present)
}
screen_special_category := out if {
	count(special_categories_present) > 0
	not evidence_present("consent_record_ref")
	out := make_screen("DENY", ["SPECIAL_CATEGORY_WITHOUT_LAWFUL_BASIS_EVIDENCE"], ["REJECT_JOB_DISPATCH"], special_categories_present)
}

screen_retention := out if {
	count(retention_violations) == 0
	out := allow_screen
}
screen_retention := out if {
	count(retention_violations) > 0
	out := make_screen("DENY", ["RETENTION_EXCEEDS_CATEGORY_MAX"], ["SHORTEN_RETENTION_WINDOW"], retention_violations)
}

# Volume-triggered sovereign approval (e.g. PIPL Art.40 CAC assessment).
volume_threshold := out if {
	config := jurisdiction_config(effective_origin)
	config != null
	threshold := common.field(config, "requires_cac_assessment_above", null)
	threshold != null
	out := threshold
}
default volume_threshold := null

screen_volume := out if {
	volume_threshold == null
	out := allow_screen
}
screen_volume := out if {
	volume_threshold != null
	is_number(subject_count)
	subject_count <= volume_threshold
	out := allow_screen
}
screen_volume := out if {
	volume_threshold != null
	is_number(subject_count)
	subject_count > volume_threshold
	evidence_present("cac_filing_approval_ref")
	out := make_screen("ALLOW", [], ["REASSESS_ON_MATERIAL_VOLUME_CHANGE"], [subject_count])
}
screen_volume := out if {
	volume_threshold != null
	is_number(subject_count)
	subject_count > volume_threshold
	not evidence_present("cac_filing_approval_ref")
	out := make_screen("DENY", ["VOLUME_ABOVE_SOVEREIGN_THRESHOLD_WITHOUT_APPROVAL"], ["REJECT_JOB_DISPATCH"], [subject_count])
}

# Process/technical data is itself potentially controlled technology, so the
# export pack has to have already run over the same payload.
technical_data_categories := out if {
	out := sort([item.category |
		item := residency_evaluations[_]
		item.category == "manufacturing_process_telemetry"
	])
}
default technical_data_categories := []

screen_technical_data := out if {
	count(technical_data_categories) == 0
	out := allow_screen
}
screen_technical_data := out if {
	count(technical_data_categories) > 0
	evidence_present("export_control_decision_ref")
	out := make_screen("ALLOW", [], ["TECHNICAL_DATA_EXPORT_SCREEN"], [object.get(evidence, "export_control_decision_ref", null)])
}
screen_technical_data := out if {
	count(technical_data_categories) > 0
	not evidence_present("export_control_decision_ref")
	out := make_screen("HUMAN_REVIEW", ["TECHNICAL_DATA_NOT_YET_EXPORT_SCREENED"], ["RUN_EXPORT_CONTROL_PACK_FIRST"], technical_data_categories)
}

# Agent scope: an autonomous agent may only act inside the purpose, region and
# read/write envelope the tenant registered it in. Each violation is its own
# boolean so the screen stays single-valued when several apply at once.
agent_unregistered := true if {
	agent_id != null
	tenant_agent == null
}
default agent_unregistered := false

agent_purpose_violation := true if {
	agent_id != null
	tenant_agent != null
	not purpose in common.field(tenant_agent, "allowed_purposes", [])
}
default agent_purpose_violation := false

agent_region_violation := true if {
	agent_id != null
	tenant_agent != null
	not processing_region in common.field(tenant_agent, "operating_regions", [])
}
default agent_region_violation := false

agent_row_level_violation := true if {
	agent_id != null
	tenant_agent != null
	common.field(tenant_agent, "aggregate_only_read", false) == true
	not is_aggregate
}
default agent_row_level_violation := false

agent_pii_write_violation := true if {
	agent_id != null
	tenant_agent != null
	common.field(tenant_agent, "may_write_pii", false) == false
	writes_pii
	any_sensitive
}
default agent_pii_write_violation := false

agent_violations := out if {
	out := sort({v |
		v := {"AGENT_PURPOSE_SCOPE_VIOLATION", "AGENT_REGION_SCOPE_VIOLATION", "AGENT_MUST_READ_AGGREGATES_ONLY", "AGENT_NOT_AUTHORISED_FOR_PII_WRITE_PATH"}[_]
		agent_violation_reason(v)
	})
}

agent_violation_reason("AGENT_PURPOSE_SCOPE_VIOLATION") if {
	agent_purpose_violation
}
agent_violation_reason("AGENT_REGION_SCOPE_VIOLATION") if {
	agent_region_violation
}
agent_violation_reason("AGENT_MUST_READ_AGGREGATES_ONLY") if {
	agent_row_level_violation
}
agent_violation_reason("AGENT_NOT_AUTHORISED_FOR_PII_WRITE_PATH") if {
	agent_pii_write_violation
}

screen_agent := out if {
	agent_id == null
	out := allow_screen
}
screen_agent := out if {
	agent_unregistered
	out := make_screen("DENY", ["AGENT_NOT_REGISTERED_FOR_TENANT"], ["REJECT_JOB_DISPATCH"], [agent_id])
}
screen_agent := out if {
	agent_id != null
	not agent_unregistered
	count(agent_violations) > 0
	out := make_screen("DENY", agent_violations, ["REJECT_JOB_DISPATCH"], [agent_id, purpose, processing_region])
}
screen_agent := out if {
	agent_id != null
	not agent_unregistered
	count(agent_violations) == 0
	out := make_screen("ALLOW", [], ["RECORD_AGENT_DECISION_PROVENANCE"], [agent_id])
}

any_sensitive := true if {
	item := residency_evaluations[_]
	item.sensitive == true
}
default any_sensitive := false

table_reports := out if {
	out := [
		common.table_report(residency_meta),
		common.table_report(mechanism_meta),
		common.table_report(jurisdiction_meta),
	]
}

unverified_tables := out if {
	out := [report | report := table_reports[_]; report.unverified_authority == true]
}

stale_tables := out if {
	out := [report | report := table_reports[_]; report.stale == true]
}

screen_table_currency := out if {
	count(unverified_tables) == 0
	count(stale_tables) == 0
	out := allow_screen
}
screen_table_currency := out if {
	count(stale_tables) > 0
	out := make_screen("HUMAN_REVIEW", ["POLICY_TABLE_STALE_OR_NOT_EFFECTIVE"], ["REFRESH_POLICY_TABLES"], [report.table_id | report := stale_tables[_]])
}
screen_table_currency := out if {
	count(stale_tables) == 0
	count(unverified_tables) > 0
	out := allow_screen
}

screens := out if {
	out := [
		screen_tenant,
		origin_disagreement,
		screen_region,
		screen_purpose,
		screen_residency,
		screen_mechanism,
		screen_special_category,
		screen_retention,
		screen_volume,
		screen_technical_data,
		screen_agent,
		screen_table_currency,
	]
}

uncapped_decision := out if {
	out := common.most_restrictive({s.decision | s := screens[_]})
}

authority_ceiling_applies := true if {
	count(unverified_tables) > 0
	uncapped_decision == "ALLOW"
}
default authority_ceiling_applies := false

final_decision := out if {
	authority_ceiling_applies
	out := "HUMAN_REVIEW"
}
final_decision := out if {
	not authority_ceiling_applies
	out := uncapped_decision
}

obligations := out if {
	from_screens := {o | s := screens[_]; o := s.obligations[_]}
	from_categories := {o | item := residency_evaluations[_]; o := item.obligations[_]}
	combined := from_screens | from_categories
	out := sort(combined)
}

ambiguities := out if {
	out := sort({r | s := screens[_]; r := s.reasons[_]})
}

basis_refs := out if {
	out := sort({r | s := screens[_]; r := s.refs[_]; r != null})
}

result := out if {
	out := {
		"engine": "data_governance",
		"pack": "policy.data_governance",
		"request_id": request_id,
		"tenant_id": tenant_id,
		"operation_type": operation_type,
		"origin_jurisdiction": effective_origin,
		"processing_region": processing_region,
		"processing_jurisdiction": processing_jurisdiction,
		"cross_border": cross_border,
		"decision": final_decision,
		"rules_verdict": uncapped_decision,
		"terminal": final_decision in {"ALLOW", "DENY", "PROHIBITED"},
		"transfer_mechanism": selected_mechanism,
		"applicable_mechanisms": applicable_mechanism_ids,
		"pending_mechanisms": pending_mechanism_ids,
		"ready_mechanisms": ready_mechanism_ids,
		"missing_evidence": unmet_evidence,
		"residency": residency_evaluations,
		"obligations": obligations,
		"ambiguities": ambiguities,
		"basis": basis_refs,
		"authority_ceiling_applied": authority_ceiling_applies,
		"escalation": {
			"required": final_decision in {"HUMAN_REVIEW", "REQUIRE_MECHANISM"},
			"queue": "privacy_office",
			"sla_hours": object.get(governance, "review_sla_hours", 24),
		},
		"policy": {
			"digest": common.policy_digest([table_reports, final_decision, selected_mechanism]),
			"tables": table_reports,
			"authority_unverified_tables": [report.table_id | report := unverified_tables[_]],
			"clock_ms": common.clock_ms,
		},
		"replay": {
			"input_sha256": crypto.sha256(json.marshal(input)),
		},
	}
}
