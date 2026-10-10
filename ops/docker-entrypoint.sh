#!/usr/bin/env sh
# Container entrypoint: one container, both processes.
#
# Render routes to $PORT, this app listens on ENGINE_PORT, so the two are bridged
# here rather than in the service definition.
set -eu

: "${DATA_DIR:=/app/var}"
export ENGINE_HOST="${ENGINE_HOST:-0.0.0.0}"
export ENGINE_PORT="${ENGINE_PORT:-${PORT:-10000}}"
export LEDGER_PATH="${LEDGER_PATH:-$DATA_DIR/decisions.jsonl}"
export REVIEW_CLOSURES_PATH="${REVIEW_CLOSURES_PATH:-$DATA_DIR/review_closures.jsonl}"

LEDGER_DIR="$(dirname "$LEDGER_PATH")"
mkdir -p "$LEDGER_DIR" "$(dirname "$REVIEW_CLOSURES_PATH")"
[ -w "$LEDGER_DIR" ] || {
  echo "ledger directory $LEDGER_DIR is not writable: verdicts would be decided and then lost" >&2
  exit 1
}

# A container is the thing that gets a public URL, so this is where the service
# refuses to come up open: without a bearer key anyone can write verdicts into the
# ledger and read recorded inputs back through /v1/decisions/{id}.
[ -n "${ENGINE_API_KEY:-}" ] || {
  echo "ENGINE_API_KEY is unset - refusing to start an unauthenticated public engine." >&2
  echo "Set it as a Render Secret Input (and pass it to scripts/deploy_check.sh)." >&2
  exit 1
}

echo "engine :$ENGINE_PORT  sidecar :${OPA_ADDR:-0.0.0.0:8181}  ledger $LEDGER_PATH"

# --bundle serves the compiled artifact baked into the image, so /v1/policies/version
# can report which policy revision produced a verdict. If the sidecar dies the engine
# is left unable to decide anything: /readyz fails, Render restarts the container, and
# both come back together instead of half a service staying up.
sh scripts/opa_serve.sh --bundle &

exec python -m compliance_engine.server
