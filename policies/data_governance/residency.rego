package policy.data_governance
import rego.v1
import data.policy.common

# ===========================================================================
# Cross-border data residency + transfer gate.
#
# This pack runs BEFORE any cross-border analytics job is dispatched; its output
# is a precondition on the pipeline. The engine cannot be talked into clearing a
# transfer by anything a model asserts about the data - mechanisms are selected
# from evidence references, not from claims.
# ===========================================================================

residency_tables := data.tables.residency_rules
jurisdiction_tables := data.tables.jurisdictions
region_tables := data.tables.regions
mechanism_tables := data.tables.transfer_mechanisms

residency_meta := object.get(residency_tables, "authority", {})
mechanism_meta := object.get(mechanism_tables, "authority", {})
jurisdiction_meta := object.get(jurisdiction_tables, "authority", {})

tenant_id := object.get(input, "tenant_id", "")
request_id := object.get(input, "request_id", null)
operation := common.section(input, "operation")
dataset := common.section(input, "dataset")
evidence := common.section(input, "evidence")
flags := common.section(input, "flags")

operation_type := object.get(operation, "type", "CROSS_BORDER_ANALYTICS")
processing_region := object.get(operation, "processing_region", "")
agent_id := object.get(operation, "agent_id", null)
purpose := object.get(dataset, "purpose", "")
registry_id := object.get(dataset, "registry_id", "")
origin_jurisdiction := object.get(dataset, "origin_jurisdiction", "")
categories := common.list(dataset, "categories", [])
subject_count := object.get(dataset, "subject_count", 0)
retention_days := object.get(dataset, "retention_days_requested", 0)
aggregation := common.section(dataset, "aggregation")
is_aggregate := object.get(aggregation, "is_aggregate", false) == true
row_level := object.get(dataset, "row_level_read", true) == true
# Only an agent that can write back into the record system is on the PII write
# path; a read-only extraction agent in-region is a different risk.
writes_pii := object.get(operation, "writes_pii", false) == true

known_modes := {"SOURCE_ONLY", "DE_ONLY", "REGION_ALLOWLIST", "ADEQUACY_OR_BETTER", "AGGREGATE_ONLY_CROSS_BORDER", "UNRESTRICTED"}

# -- tenant ------------------------------------------------------------------
default tenant := null

tenant := t if {
	t := data.tenants[tenant_id]
}

default tenant_registry := null

tenant_registry := r if {
	registries := common.field(tenant, "registries", [])
	r := registries[_]
	r.registry_id == registry_id
}

default tenant_agent := null

tenant_agent := a if {
	agents := common.field(tenant, "agents", [])
	a := agents[_]
	a.agent_id == agent_id
}

tenant_evidence := common.field(tenant, "transfer_evidence", {})

approved_regions := common.field(tenant, "approved_processing_regions", [])
forbidden_regions := common.field(tenant, "forbidden_processing_regions", [])
approved_purposes := common.field(tenant, "approved_purposes", [])

declared_categories := out if {
	tenant_registry != null
	out := common.field(tenant_registry, "categories", [])
}
default declared_categories := []

undeclared_categories := out if {
	out := sort([c | c := categories[_]; not c in declared_categories])
}

# -- geography ---------------------------------------------------------------
default region_record(region) := null

region_record(region) := r if {
	r := region_tables.regions[region]
}

default region_jurisdiction(region) := null

region_jurisdiction(region) := j if {
	record := region_record(region)
	record != null
	j := record.jurisdiction
}

processing_jurisdiction := region_jurisdiction(processing_region)
region_known := region_record(processing_region) != null

default registry_jurisdiction := null

registry_jurisdiction := j if {
	tenant_registry != null
	j := common.field(tenant_registry, "jurisdiction", null)
	j != null
}

# The registry's own jurisdiction wins over a caller-supplied string when both
# are present, so a job manifest cannot self-declare a friendlier origin.
effective_origin := out if {
	registry_jurisdiction != null
	out := registry_jurisdiction
}
effective_origin := out if {
	registry_jurisdiction == null
	out := origin_jurisdiction
}

origin_conflict := true if {
	registry_jurisdiction != null
	origin_jurisdiction != ""
	registry_jurisdiction != origin_jurisdiction
}
default origin_conflict := false

same_jurisdiction := true if {
	region_known
	effective_origin != ""
	processing_jurisdiction == effective_origin
}
default same_jurisdiction := false

cross_border := true if {
	region_known
	not same_jurisdiction
}
default cross_border := false

default jurisdiction_config(jurisdiction) := null

jurisdiction_config(jurisdiction) := c if {
	c := jurisdiction_tables.jurisdictions[jurisdiction]
}

has_bloc(jurisdiction) if {
	record := region_tables.regions[_]
	record.jurisdiction == jurisdiction
}

bloc_of_jurisdiction(jurisdiction) := b if {
	record := region_tables.regions[_]
	record.jurisdiction == jurisdiction
	b := record.block
}
bloc_of_jurisdiction(jurisdiction) := jurisdiction if {
	not has_bloc(jurisdiction)
}

origin_bloc := bloc_of_jurisdiction(effective_origin)
processing_bloc := common.field(region_record(processing_region), "block", null)

# Adequacy is a bloc-level instrument (the EU decides for its member states), so
# a German-origin job is evaluated against the EU adequacy list, not a DE one.
adequate_now := true if {
	origin_bloc == "EU"
	target := jurisdiction_tables.adequacy.recognised[processing_jurisdiction]
	target != null
}
default adequate_now := false

# -- category rules ----------------------------------------------------------
default category_rule(category) := null

category_rule(category) := r if {
	r := residency_tables.categories[category]
}

unknown_categories := out if {
	out := sort([c | c := categories[_]; category_rule(c) == null])
}

mode_of(category) := out if {
	rule := category_rule(category)
	rule != null
	override := common.field(common.field(rule, "jurisdiction_override", {}), effective_origin, null)
	override != null
	out := override
}
mode_of(category) := out if {
	rule := category_rule(category)
	rule != null
	override := common.field(common.field(rule, "jurisdiction_override", {}), effective_origin, null)
	override == null
	out := common.field(rule, "residency_mode", "UNRESTRICTED")
}

min_k(category) := out if {
	rule := category_rule(category)
	out := common.field(rule, "min_k_anonymity_for_cross_border_aggregate", null)
}

k_value := object.get(aggregation, "k_anonymity", null)

aggregate_ok(category) := true if {
	is_aggregate
	required := min_k(category)
	required != null
	is_number(k_value)
	k_value >= required
}
default aggregate_ok(category) := false

in_regional_allowlist(category) := true if {
	rule := category_rule(category)
	allowed := common.field(rule, "allowed_regions", [])
	processing_jurisdiction in allowed
}
default in_regional_allowlist(category) := false

hard_localised(category) := true if {
	rule := category_rule(category)
	common.field(rule, "hard_localisation", false) == true
}
default hard_localised(category) := false

# Residency failures, expressed as sets so several rules can contribute to one
# category without ever producing conflicting values.
residency_denied(category) if {
	not same_jurisdiction
	hard_localised(category)
}
residency_denied(category) if {
	not same_jurisdiction
	mode := mode_of(category)
	mode in {"SOURCE_ONLY", "DE_ONLY"}
}
residency_denied(category) if {
	not same_jurisdiction
	mode_of(category) == "REGION_ALLOWLIST"
	not in_regional_allowlist(category)
}
# Aggregate-only routes: the threshold is the permission. An aggregate that has
# not reached k is not a small aggregate, it is still personal data leaving the
# jurisdiction, so it is denied rather than downgraded to a mechanism question.
residency_denied(category) if {
	not same_jurisdiction
	mode_of(category) == "AGGREGATE_ONLY_CROSS_BORDER"
	not aggregate_ok(category)
}

residency_needs_mechanism(category) if {
	not residency_denied(category)
	not same_jurisdiction
	mode := mode_of(category)
	mode in {"ADEQUACY_OR_BETTER", "REGION_ALLOWLIST", "AGGREGATE_ONLY_CROSS_BORDER"}
	not adequate_now
}
residency_needs_mechanism(category) if {
	not residency_denied(category)
	cross_border
	common.field(category_rule(category), "sensitive", false) == true
	mode_of(category) == "UNRESTRICTED"
	not adequate_now
}

residency_unmodelled(category) if {
	mode := mode_of(category)
	not mode in known_modes
}

residency_verdict(category) := "DENY" if {
	residency_denied(category)
}
residency_verdict(category) := "HUMAN_REVIEW" if {
	not residency_denied(category)
	residency_unmodelled(category)
}
residency_verdict(category) := "REQUIRE_MECHANISM" if {
	not residency_denied(category)
	not residency_unmodelled(category)
	residency_needs_mechanism(category)
}
residency_verdict(category) := "ALLOW" if {
	not residency_denied(category)
	not residency_unmodelled(category)
	not residency_needs_mechanism(category)
}

residency_reason(category) := "HARD_LOCALISATION_VIOLATED" if {
	residency_denied(category)
	hard_localised(category)
}
residency_reason(category) := "RESIDENCY_MODE_NOT_SATISFIED_IN_DESTINATION" if {
	residency_denied(category)
	not hard_localised(category)
}
residency_reason(category) := "RESIDENCY_MODE_UNMODELLED" if {
	not residency_denied(category)
	residency_unmodelled(category)
}
residency_reason(category) := "TRANSFER_MECHANISM_REQUIRED" if {
	not residency_denied(category)
	not same_jurisdiction
	residency_needs_mechanism(category)
}
residency_reason(category) := "ADEQUACY_COVERS_DESTINATION" if {
	not residency_denied(category)
	not residency_needs_mechanism(category)
	not same_jurisdiction
	adequate_now
}
residency_reason(category) := "SAME_JURISDICTION_PROCESSING" if {
	not residency_denied(category)
	not residency_needs_mechanism(category)
	same_jurisdiction
}
default residency_reason(category) := "RESIDENCY_STATE_UNDETERMINED"

residency_evaluations := out if {
	out := [
		{
			"category": category,
			"residency_mode": mode_of(category),
			"verdict": residency_verdict(category),
			"reason": residency_reason(category),
			"sensitive": common.field(category_rule(category), "sensitive", false) == true,
			"special_category": common.field(category_rule(category), "special_category", false) == true,
			"max_retention_days": common.field(category_rule(category), "max_retention_days", null),
			"prohibited_purposes": common.field(category_rule(category), "prohibited_purposes", []),
			"obligations": common.field(category_rule(category), "obligations_always", []),
		}
		|
		category := categories[_]
		category_rule(category) != null
	]
}

prohibited_purpose_hits := out if {
	out := sort([
		category
		|
		item := residency_evaluations[_]
		category := item.category
		blocked := item.prohibited_purposes
		purpose in blocked
	])
}

special_categories_present := out if {
	out := sort([item.category | item := residency_evaluations[_]; item.special_category == true])
}

retention_violations := out if {
	out := sort([
		item.category
		|
		item := residency_evaluations[_]
		max_days := item.max_retention_days
		is_number(max_days)
		is_number(retention_days)
		retention_days > max_days
	])
}

all_residency_verdicts := out if {
	out := sort([item.verdict | item := residency_evaluations[_]])
}

# -- transfer mechanism selection -------------------------------------------
attributes := out if {
	from_flags := flags
	from_request := {
		"destination_jurisdiction": processing_jurisdiction,
		"destination_adequate": adequate_now,
		# A party relationship nobody stated is not a fact the engine may invent:
		# unknown keeps the route ladder indeterminate instead of assuming a role.
		"relationship": common.field(dataset, "relationship", null),
		"subject_count": subject_count,
		"origin_jurisdiction": effective_origin,
		"same_corporate_group": object.get(dataset, "same_corporate_group", false),
	}
	out := object.union(from_flags, from_request)
}

attr(name) := v if {
	v := attributes[name]
}
default attr(name) := null

mech_ops := {"is_true", "is_false", "eq", "in", "not_in", "destination_adequate", "volume_exceeds"}

cond_status(cond) := "INVALID" if {
	op := object.get(cond, "op", "")
	not op in mech_ops
}
cond_status(cond) := "ABSENT" if {
	op := object.get(cond, "op", "")
	op in mech_ops
	not cond_input_known(cond)
}
cond_status(cond) := "TRUE" if {
	op := object.get(cond, "op", "")
	op in mech_ops
	cond_ok(cond)
}
cond_status(cond) := "FALSE" if {
	op := object.get(cond, "op", "")
	op in mech_ops
	cond_input_known(cond)
	not cond_ok(cond)
}

# Whether the fact a condition tests against is actually available. A mechanism
# whose inputs are unknown is pending, not failed - see the ladder in decision.rego.
cond_input_known(cond) := true if {
	object.get(cond, "op", "") == "destination_adequate"
}
cond_input_known(cond) := true if {
	object.get(cond, "op", "") == "volume_exceeds"
	is_number(subject_count)
}
cond_input_known(cond) := true if {
	op := object.get(cond, "op", "")
	op in mech_ops
	not op in {"destination_adequate", "volume_exceeds"}
	attr(object.get(cond, "param", "")) != null
}
default cond_input_known(cond) := false

mechanism_conditions_ok(m) := true if {
	conds := object.get(m, "conditions", [])
	statuses := [cond_status(c) | c := conds[_]]
	count([s | s := statuses[_]; s == "TRUE"]) == count(conds)
}
default mechanism_conditions_ok(m) := false

# A mechanism that would apply if the operator answered the remaining questions
# is an escalation, not a denial: absence of a fact is not proof of ineligibility.
mechanism_conditions_indeterminate(m) := true if {
	conds := object.get(m, "conditions", [])
	statuses := [cond_status(c) | c := conds[_]]
	count([s | s := statuses[_]; s == "FALSE"]) == 0
	count([s | s := statuses[_]; s == "INVALID"]) == 0
	count([s | s := statuses[_]; s == "ABSENT"]) > 0
}
default mechanism_conditions_indeterminate(m) := false

mech_holds("is_true", cond) := true if {
	attr(object.get(cond, "param", "")) == true
}
mech_holds("is_false", cond) := true if {
	attr(object.get(cond, "param", "")) == false
}
mech_holds("eq", cond) := true if {
	attr(object.get(cond, "param", "")) == object.get(cond, "value", null)
}
mech_holds("in", cond) := true if {
	value := attr(object.get(cond, "param", ""))
	list := object.get(cond, "value", [])
	is_array(list)
	value in list
}
mech_holds("not_in", cond) := true if {
	value := attr(object.get(cond, "param", ""))
	list := object.get(cond, "value", [])
	is_array(list)
	not value in list
}
mech_holds("destination_adequate", _cond) := true if {
	attr("destination_adequate") == true
}
mech_holds("volume_exceeds", cond) := true if {
	threshold := object.get(cond, "value", 0)
	is_number(subject_count)
	subject_count > threshold
}

evidence_present(ref) := true if {
	value := lookup_evidence(ref)
	value != null
	value != ""
	value != false
}
default evidence_present(ref) := false

# Evidence may be supplied per request or registered at tenant level; a request
# cannot invent a document the tenant has never signed.
lookup_evidence(ref) := v if {
	v := object.get(evidence, ref, null)
	v != null
}
lookup_evidence(ref) := v if {
	object.get(evidence, ref, null) == null
	v := object.get(tenant_evidence, ref, null)
}

mechanism_missing_evidence(m) := out if {
	refs := object.get(m, "evidence_refs", [])
	out := sort([r | r := refs[_]; not evidence_present(r)])
}

default cond_ok(cond) := false

cond_ok(cond) := true if {
	op := object.get(cond, "op", "")
	op in mech_ops
	mech_holds(op, cond)
}

default mechanism_scope_matches(m) := false

mechanism_scope_matches(m) := true if {
	origins := object.get(m, "exporting_jurisdictions", [])
	effective_origin in origins
}
mechanism_scope_matches(m) := true if {
	origins := object.get(m, "exporting_jurisdictions", [])
	origin_bloc in origins
}

mechanism_applies(m) := true if {
	mechanism_scope_matches(m)
	mechanism_conditions_ok(m)
}
default mechanism_applies(m) := false

mechanism_pending(m) := true if {
	mechanism_scope_matches(m)
	mechanism_conditions_indeterminate(m)
	not mechanism_applies(m)
}
default mechanism_pending(m) := false

mechanism_ready(m) := true if {
	mechanism_applies(m)
	count(mechanism_missing_evidence(m)) == 0
}
default mechanism_ready(m) := false

mechanism_list := object.get(mechanism_tables, "mechanisms", [])

applicable_mechanism_ids := out if {
	out := sort([m.mechanism_id | m := mechanism_list[_]; mechanism_applies(m)])
}

pending_mechanism_ids := out if {
	out := sort([m.mechanism_id | m := mechanism_list[_]; mechanism_pending(m)])
}

ready_mechanism_ids := out if {
	out := sort([m.mechanism_id | m := mechanism_list[_]; mechanism_ready(m)])
}

mechanism_by_id(id) := m if {
	m := mechanism_list[_]
	m.mechanism_id == id
}

selected_mechanism := out if {
	ranked := [
		[m.rank, m.mechanism_id]
		|
		m := mechanism_list[_]
		mechanism_ready(m)
	]
	count(ranked) > 0
	out := sort(ranked)[0][1]
}
default selected_mechanism := null

default selected_mechanism_record := null

selected_mechanism_record := m if {
	selected_mechanism != null
	m := mechanism_by_id(selected_mechanism)
}

# Reported across every route the facts say applies, not just the one that was
# selected: a route that qualifies on flags but has no registered document is a
# standing gap the tenant must close, and hiding it behind an evidenced
# alternative would let an asserted mechanism look resolved.
unmet_evidence := out if {
	out := sort({r | m := mechanism_list[_]; mechanism_applies(m); r := mechanism_missing_evidence(m)[_]})
}

mechanism_ceiling := common.field(selected_mechanism_record, "ceiling", null)

# Adequacy is the only route the engine may clear on its own. Anything that rests
# on a contract the parties signed needs a named human to own it.
mechanism_auto_clears := common.field(selected_mechanism_record, "auto_clear", false) == true
