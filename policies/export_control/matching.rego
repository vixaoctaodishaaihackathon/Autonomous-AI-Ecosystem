package policy.export_control
import rego.v1
import data.policy.common

# ---------------------------------------------------------------------------
# Deterministic three-valued evaluation of control-list parameter conditions.
# The LLM never reaches this layer: it can only supply facts, and every fact
# carries provenance that the decision layer weighs separately.
# ---------------------------------------------------------------------------

tables := data.tables.dual_use_controls
param_meta := object.get(tables, "params", {})

# technical_parameters is a map of parameter name to fact, so it is read as a
# section: an array-shaped or null value degrades to "nothing supplied".
technical_params := out if {
	item := common.section(input, "item")
	out := common.section(item, "technical_parameters")
}

default param(name) := null

param(name) := p if {
	p := technical_params[name]
	is_object(p)
}

param_present(name) if {
	param(name) != null
}

param_value(name) := v if {
	v := param(name).value
}

default expected_unit(name) := null

expected_unit(name) := u if {
	u := param_meta[name].unit
	u != null
}

# A number quoted in the wrong unit is a silent misclassification, and unit
# drift is the most common extraction error. Mismatch invalidates the fact.
unit_ok(name) := true if {
	expected_unit(name) == null
}
unit_ok(name) := true if {
	expected := expected_unit(name)
	expected != null
	u := object.get(param(name), "unit", null)
	u == expected
}
default unit_ok(name) := false

# -- operators ---------------------------------------------------------------

known_ops := {"lt", "lte", "gt", "gte", "eq", "neq", "in", "not_in", "in_range", "is_true", "is_false", "contains_any"}

op_valid(c) := true if {
	c.op in known_ops
}
default op_valid(c) := false

default eval_op(op, a, b) := false

eval_op("lt", a, b) := true if {
	is_number(a)
	is_number(b)
	a < b
}
eval_op("lte", a, b) := true if {
	is_number(a)
	is_number(b)
	a <= b
}
eval_op("gt", a, b) := true if {
	is_number(a)
	is_number(b)
	a > b
}
eval_op("gte", a, b) := true if {
	is_number(a)
	is_number(b)
	a >= b
}
eval_op("eq", a, b) := true if {
	is_number(a)
	is_number(b)
	a == b
}
eval_op("eq", a, b) := true if {
	is_boolean(a)
	is_boolean(b)
	a == b
}
eval_op("eq", a, b) := true if {
	is_string(a)
	is_string(b)
	lower(a) == lower(b)
}
eval_op("neq", a, b) := true if {
	a != b
}
eval_op("in", a, b) := true if {
	is_array(b)
	a in b
}
eval_op("not_in", a, b) := true if {
	is_array(b)
	not a in b
}
eval_op("in_range", a, b) := true if {
	is_number(a)
	is_array(b)
	count(b) == 2
	a >= b[0]
	a <= b[1]
}
eval_op("is_true", a, _b) := true if {
	a == true
}
eval_op("is_false", a, _b) := true if {
	a == false
}
eval_op("contains_any", a, b) := true if {
	is_string(a)
	is_array(b)
	term := b[_]
	contains(lower(a), lower(term))
}

# -- condition status --------------------------------------------------------
# TRUE / FALSE / ABSENT (fact not supplied) / INVALID (malformed or unusable)

cond_params(c) := out if {
	out := {c.param}
	c.param
}
cond_params(c) := out if {
	out := {p | sub := c.any_of[_]; p := sub.param}
	not c.param
	is_array(c.any_of)
}
cond_params(c) := out if {
	out := set()
	not c.param
	not is_array(c.any_of)
}

all_cond_params(conds) := out if {
	out := {p |
		c := conds[_]
		names := cond_params(c)
		p := names[_]
	}
}

cond_status(c) := "INVALID" if {
	not c.param
	not is_array(c.any_of)
}
cond_status(c) := out if {
	is_array(c.any_of)
	not c.param
	out := combine("any_of", [leaf_status(sub) | sub := c.any_of[_]])
}
cond_status(c) := out if {
	c.param
	out := leaf_status(c)
}

# Tables nest exactly one level (an any_of group of leaf comparisons), so the
# group branch calls leaf_status rather than recursing.
leaf_status(c) := "INVALID" if {
	not op_valid(c)
}
leaf_status(c) := "ABSENT" if {
	op_valid(c)
	not param_present(c.param)
}
leaf_status(c) := "INVALID_FACT" if {
	op_valid(c)
	param_present(c.param)
	not unit_ok(c.param)
}
leaf_status(c) := "TRUE" if {
	op_valid(c)
	param_present(c.param)
	unit_ok(c.param)
	eval_op(c.op, param_value(c.param), object.get(c, "value", null))
}
leaf_status(c) := "FALSE" if {
	op_valid(c)
	param_present(c.param)
	unit_ok(c.param)
	not eval_op(c.op, param_value(c.param), object.get(c, "value", null))
}

# Aggregation is deliberately conservative: an unusable or missing fact outranks
# a clean FALSE, because a bad fact could have flipped the conclusion.
combine("any_of", statuses) := "TRUE" if {
	"TRUE" in statuses
}
combine("any_of", statuses) := "INVALID" if {
	not "TRUE" in statuses
	"INVALID" in statuses
}
combine("any_of", statuses) := "INVALID_FACT" if {
	not "TRUE" in statuses
	not "INVALID" in statuses
	"INVALID_FACT" in statuses
}
combine("any_of", statuses) := "ABSENT" if {
	not "TRUE" in statuses
	not "INVALID" in statuses
	not "INVALID_FACT" in statuses
	"ABSENT" in statuses
}
combine("any_of", statuses) := "FALSE" if {
	count(statuses) > 0
	every s in statuses {
		s == "FALSE"
	}
}
combine("all_of", statuses) := "INVALID" if {
	"INVALID" in statuses
}
combine("all_of", statuses) := "INVALID_FACT" if {
	not "INVALID" in statuses
	"INVALID_FACT" in statuses
}
combine("all_of", statuses) := "ABSENT" if {
	not "INVALID" in statuses
	not "INVALID_FACT" in statuses
	"ABSENT" in statuses
}
combine("all_of", statuses) := "FALSE" if {
	not "INVALID" in statuses
	not "INVALID_FACT" in statuses
	not "ABSENT" in statuses
	"FALSE" in statuses
}
combine("all_of", statuses) := "TRUE" if {
	count(statuses) > 0
	every s in statuses {
		s == "TRUE"
	}
}
# An empty group, or a mode the tables never emit, is a malformed table rather
# than a benign outcome.
combine(_mode, statuses) := "INVALID" if {
	count(statuses) == 0
}
combine(mode, statuses) := "INVALID" if {
	count(statuses) > 0
	not mode in {"any_of", "all_of"}
}

# -- control-level status ----------------------------------------------------

control_cond_params(ctrl) := out if {
	out := all_cond_params(object.get(ctrl, "conditions", []))
}

required_params(ctrl) := out if {
	out := object.get(ctrl, "required_params", [])
}

control_params(ctrl) := out if {
	out := control_cond_params(ctrl) | {p | p := required_params(ctrl)[_]}
}

present_params(ctrl) := out if {
	out := {p | p := control_params(ctrl)[_]; param_present(p)}
}

missing_params(ctrl) := out if {
	out := {p | p := control_params(ctrl)[_]; not param_present(p)}
}

control_mode(ctrl) := out if {
	defaults := object.get(tables, "matching_contract", {})
	out := object.get(ctrl, "condition_mode", object.get(defaults, "condition_mode_default", "all_of"))
}

control_raw_status(ctrl) := out if {
	conds := object.get(ctrl, "conditions", [])
	out := combine(control_mode(ctrl), [cond_status(c) | c := conds[_]])
}

# No signal at all about this category's parameters: the control is simply not
# engaged. Completeness of the questionnaire is enforced separately so that
# "not engaged" can never be mistaken for "not controlled".
control_status(ctrl) := "NOT_APPLICABLE" if {
	count(present_params(ctrl)) == 0
}
# A proven match, a malformed condition, or an unusable fact all stand on their
# own: an OR-group that one parameter already satisfies is a match even if the
# alternative parameter was never supplied.
control_status(ctrl) := control_raw_status(ctrl) if {
	count(present_params(ctrl)) > 0
	raw := control_raw_status(ctrl)
	raw in {"TRUE", "INVALID", "INVALID_FACT"}
}
control_status(ctrl) := "INDETERMINATE" if {
	count(present_params(ctrl)) > 0
	raw := control_raw_status(ctrl)
	raw in {"ABSENT", "FALSE"}
	count(missing_params(ctrl)) > 0
}
control_status(ctrl) := "FALSE" if {
	count(present_params(ctrl)) > 0
	control_raw_status(ctrl) == "FALSE"
	count(missing_params(ctrl)) == 0
}

# -- exclusions / downgrades -------------------------------------------------

exclusion_status(excl) := "INVALID" if {
	not is_array(object.get(excl, "conditions", null))
}
exclusion_status(excl) := "ABSENT" if {
	p := {q | q := object.get(excl, "required_params", [])[_]; not param_present(q)}
	count(p) > 0
}
exclusion_status(excl) := out if {
	count({q | q := object.get(excl, "required_params", [])[_]; not param_present(q)}) == 0
	conds := object.get(excl, "conditions", [])
	out := combine(object.get(excl, "condition_mode", "all_of"), [cond_status(c) | c := conds[_]])
}
