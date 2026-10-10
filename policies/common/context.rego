package policy.common
import rego.v1

# ---------------------------------------------------------------------------
# Determinism contract
# Everything a decision depends on arrives through `input` (including the
# clock) or through a versioned data table. This policy reads no system clock,
# env, or network, so a stored (input, policy_digest) pair can be replayed
# byte-for-byte for an auditor.
# ---------------------------------------------------------------------------

default clock_ms := null

clock_ms := input.clock.milliseconds if {
	is_number(input.clock.milliseconds)
}

# object.get() rejects a null receiver with a type error, which silently
# undefines the entire enclosing rule and makes a screen vanish from the verdict
# instead of degrading. Fields read off records that may be absent go through
# this accessor so an absent record yields its fallback.
field(obj, name, fallback) := v if {
	is_object(obj)
	v := object.get(obj, name, fallback)
}
field(obj, name, fallback) := fallback if {
	not is_object(obj)
}

# The same trap one level up: a client may send "evidence": null instead of
# leaving the key out. An optional section that is not an object is treated as an
# absent one, so a mistyped payload degrades into an escalation instead of
# deleting a screen from the verdict.
section(obj, name) := out if {
	value := field(obj, name, {})
	is_object(value)
	out := value
}

section(obj, name) := out if {
	value := field(obj, name, {})
	not is_object(value)
	out := {}
}

# Lists read from input get the same treatment; count() and [_] on null would
# otherwise undefined the whole comprehension.
list(obj, name, fallback) := out if {
	value := field(obj, name, fallback)
	is_array(value)
	out := value
}
list(obj, name, fallback) := out if {
	value := field(obj, name, fallback)
	not is_array(value)
	out := fallback
}

# ---------------------------------------------------------------------------
# Policy freshness. A rule table past its own review cadence is a liability:
# deciding on stale annex/sanctions text is worse than escalating.
# ---------------------------------------------------------------------------

default epoch_ms(d) := null

epoch_ms(d) := null if {
	is_string(d)
	not regex.match(`^\d{4}-\d{2}-\d{2}$`, d)
}

epoch_ms(d) := ms if {
	is_string(d)
	regex.match(`^\d{4}-\d{2}-\d{2}$`, d)
	ns := time.parse_rfc3339_ns(concat("", [d, "T00:00:00Z"]))
	ms := ns / 1000000
}

# A table is usable only if it carries a parsable, non-future effective date.
effective_and_current(table, now) if {
	is_number(now)
	d := object.get(table, "effective_date", "")
	d != ""
	epoch := epoch_ms(d)
	epoch != null
	epoch <= now
}

past_cadence(table, now) if {
	is_number(now)
	d := object.get(table, "effective_date", "")
	epoch := epoch_ms(d)
	epoch != null
	epoch + object.get(table, "review_cadence_days", 30) * 86400000 < now
}

stale(table, now) := true if {
	not is_number(now)
}
stale(table, now) := true if {
	is_number(now)
	not effective_and_current(table, now)
}
stale(table, now) := true if {
	is_number(now)
	effective_and_current(table, now)
	past_cadence(table, now)
}
stale(table, now) := false if {
	is_number(now)
	effective_and_current(table, now)
	not past_cadence(table, now)
}

# ---------------------------------------------------------------------------
# Authority ceiling. Tables not marked VERIFIED may escalate but may never hand
# out a terminal ALLOW. This is what keeps a running compliance engine honest
# while its rule text is still placeholder data.
# ---------------------------------------------------------------------------

authority_unverified(table) := true if {
	status := object.get(table, "status", "UNKNOWN")
	not startswith(status, "VERIFIED")
}
default authority_unverified(table) := false

ceiling_for(table) := "HUMAN_REVIEW" if {
	authority_unverified(table)
}
default ceiling_for(table) := null

table_report(table) := {
	"table_id": object.get(table, "table_id", null),
	"table_version": object.get(table, "table_version", null),
	"authority_status": object.get(table, "status", "UNKNOWN"),
	"effective_date": object.get(table, "effective_date", null),
	"stale": stale(table, clock_ms),
	"unverified_authority": authority_unverified(table),
}

# ---------------------------------------------------------------------------
# Decision algebra
# ---------------------------------------------------------------------------

decision_rank := {
	"ALLOW": 0,
	"NOT_APPLICABLE": 0,
	"HUMAN_REVIEW": 1,
	"REQUIRE_LICENCE": 2,
	"REQUIRE_MECHANISM": 2,
	"DENY": 3,
	"PROHIBITED": 4,
}

# Most restrictive of a set of decisions. Unrecognised or empty input collapses
# to HUMAN_REVIEW rather than silently ranking as ALLOW.
most_restrictive(decisions) := out if {
	valid := {d | d := decisions[_]; is_string(d); object.get(decision_rank, d, null) != null}
	count(valid) > 0
	count(valid) == count(decisions)
	ranks := [object.get(decision_rank, d, 0) | d := valid[_]]
	max_rank := sort(ranks)[count(ranks) - 1]
	out := sort({d | d := valid[_]; object.get(decision_rank, d, 0) == max_rank})[0]
}

default most_restrictive(decisions) := "HUMAN_REVIEW"

# Apply a ceiling from policy authority: a null ceiling is a no-op, and any
# other ceiling may only tighten the verdict, never loosen it.
cap(decision, null) := decision

cap(decision, ceiling) := out if {
	ceiling != null
	out := most_restrictive({decision, ceiling})
}

# Reproducible identifier for the exact inputs a verdict was derived from.
policy_digest(packs) := crypto.sha256(json.marshal(packs))

escalation(required, queue, reason) := {
	"required": required,
	"queue": queue,
	"reason": reason,
}

basis(refs) := out if {
	out := [r | r := refs[_]]
}
