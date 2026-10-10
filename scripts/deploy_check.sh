#!/usr/bin/env sh
# Post-deploy smoke check: does this deployment actually decide, and does it
# remember? Point it at a running engine.
#
#   sh scripts/deploy_check.sh https://<service>.onrender.com
#   sh scripts/deploy_check.sh http://localhost:8080
set -eu

BASE="${1:-${BASE_URL:-http://localhost:8080}}"
BASE="${BASE%/}"
PY="${PYTHON:-python}"
CURL="${CURL:-curl}"
KEY="${ENGINE_API_KEY:-}"

fail() { echo "FAIL: $1" >&2; exit 1; }

get() { "$CURL" -fsS -H "Authorization: Bearer $KEY" "$BASE$1"; }
post() { "$CURL" -fsS -H "Authorization: Bearer $KEY" -X POST "$BASE$1" -H 'content-type: application/json' -d "$2"; }

echo "target $BASE"

if [ -z "$KEY" ]; then
  fail "ENGINE_API_KEY is unset - the deployed boundary answers 401 to this check too. Export the same key the service was given."
fi

# Prove the gate is actually on: an unauthenticated call must be refused before it
# ever reaches validation, so a malformed body still gets 401 rather than 422.
CODE=$("$CURL" -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
  -d '{}' "$BASE/v1/export-control/decisions")
if [ "$CODE" != "401" ]; then
  fail "an unauthenticated decision returned $CODE, not 401 - this deployment is open"
fi
echo "  anonymous   401 as expected"

# /readyz is 503 unless the sidecar answers, so this is the check that distinguishes
# "the web process started" from "the engine can decide anything".
get /readyz > /tmp/dc.ready 2>/dev/null || fail "/readyz did not answer - OPA is not reachable from the engine"
echo "  readyz      $(tr -d '\n' < /tmp/dc.ready)"

get /v1/policies/version > /tmp/dc.version || fail "/v1/policies/version failed"
REVISION=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("served_policy_revision") or "")' /tmp/dc.version)
if [ -z "$REVISION" ]; then
  echo "  revision    NONE - the sidecar is not serving a stamped bundle, so verdicts"
  echo "              cannot cite the policy version that produced them"
else
  echo "  revision    $REVISION"
fi

# Expected values are the ones README documents; if they move, the deployment is not
# the thing that changed, the policy is.
EXPORT_BODY='{
  "tenant_id": "tnt_vega_manufacturing",
  "request_id": "req-deploy-0001",
  "destination_country": "DE",
  "item": {
    "sku": "VCU-500",
    "description": "vehicle domain controller assembly",
    "technical_parameters": {
      "crypto_function":    {"value": true, "evidence": {"source": "MANUAL_VERIFICATION", "ref": "spec-1"}},
      "symmetric_key_bits": {"value": 256, "unit": "bit", "evidence": {"source": "MANUAL_VERIFICATION", "ref": "spec-1"}}
    }
  },
  "end_user": {"screening_status": "CLEAR", "screening_ref": "scr-99"},
  "clock": {"milliseconds": 1791633600000}
}'
post /v1/export-control/decisions "$EXPORT_BODY" > /tmp/dc.export || fail "export-control decision call failed"
"$PY" - /tmp/dc.export <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
r = d["result"]
assert r["decision"] == "REQUIRE_LICENCE", r["decision"]
assert r["control_code"] == "5A002", r["control_code"]
print(f"  export      {r['decision']} {r['control_code']} terminal={r['terminal']} decision_id={d['decision_id']}")
EOF

GATE_BODY='{
  "tenant_id": "tnt_vega_manufacturing",
  "request_id": "job-deploy-0001",
  "operation": {"type": "CROSS_BORDER_ANALYTICS", "processing_region": "in-mh-1"},
  "dataset": {
    "registry_id": "reg-vega-customer",
    "purpose": "cross_border_operational_analytics",
    "origin_jurisdiction": "DE",
    "categories": ["customer_pii"],
    "subject_count": 1200,
    "retention_days_requested": 365,
    "row_level_read": true,
    "relationship": "CONTROLLER_TO_PROCESSOR",
    "aggregation": {"is_aggregate": false}
  },
  "flags": {"importer_is_public_authority": false},
  "clock": {"milliseconds": 1791633600000}
}'
post /v1/data-transfer/gate "$GATE_BODY" > /tmp/dc.gate || fail "transfer gate call failed"
"$PY" - /tmp/dc.gate <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))["result"]
print(f"  transfer    {r['decision']} via {r.get('transfer_mechanism')}"
      f" (rules said {r.get('rules_verdict')}, missing evidence {len(r.get('missing_evidence') or [])})")
assert r["decision"] == "HUMAN_REVIEW", r["decision"]
EOF

get /v1/ledger/verify > /tmp/dc.ledger || fail "/v1/ledger/verify failed"
"$PY" - /tmp/dc.ledger <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))["decisions"]
print(f"  ledger      ok={d['ok']} checked={d['checked']}")
if d["ok"] is not True:
    raise SystemExit(f"chain is broken at seq {d.get('broken_at_seq')}: {d.get('reason')}")
if d["checked"] < 2:
    print("  warning     the two decisions above were not recorded - the ledger path is not writable")
EOF

cat <<'EOF'

Durability is a separate test: redeploy the service, then re-run
  sh scripts/deploy_check.sh <url>
If "ledger checked" is back to 0, the filesystem is ephemeral and this deployment
has no audit trail between releases - see the disk block in render.yaml.
EOF
