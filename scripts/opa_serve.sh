#!/usr/bin/env sh
# Start the OPA sidecar.
#
#   sh scripts/opa_serve.sh            # dev: serve policies/ + data/ straight from disk
#   sh scripts/opa_serve.sh --bundle   # ops: hot-reload builds/bundles/policy (run policy_build.sh first)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPA="${OPA:-$ROOT/.tools/opa.exe}"
[ -x "$OPA" ] || OPA="${OPA_BIN:-opa}"
PYTHON="${PYTHON:-python}"
ADDR="${OPA_ADDR:-0.0.0.0:8181}"
STORE_ADDR="${BUNDLE_STORE_ADDR:-127.0.0.1:18182}"

if [ "${1:-}" = "--bundle" ]; then
  BUNDLE="$ROOT/builds/bundles/policy"
  [ -f "$BUNDLE" ] || { echo "no $BUNDLE - run sh scripts/policy_build.sh first"; exit 1; }
  mkdir -p "$ROOT/.tmp"
  STORE_HOST="${STORE_ADDR%:*}"
  STORE_PORT="${STORE_ADDR##*:}"
  # OPA pulls bundles over HTTP only, so the artefact is published from builds/.
  "$PYTHON" -m http.server "$STORE_PORT" --bind "$STORE_HOST" \
    --directory "$ROOT/builds" >"$ROOT/.tmp/bundle_store.log" 2>&1 &
  STORE_PID=$!
  trap 'kill "$STORE_PID" 2>/dev/null || true' EXIT INT TERM
  echo "bundle store http://$STORE_ADDR (pid $STORE_PID)"
  CONFIG="$ROOT/ops/opa-config.generated.yaml"
  sed "s|{{SERVICE_URL}}|http://$STORE_ADDR|" "$ROOT/ops/opa-config.yaml" > "$CONFIG"
  echo "serving bundle $BUNDLE (sidecar re-pulls it on OPA's poll interval)"
  "$OPA" run --server --addr "$ADDR" --config-file "$CONFIG" &
  OPA_PID=$!
  trap 'kill "$OPA_PID" "$STORE_PID" 2>/dev/null || true' EXIT INT TERM
  wait "$OPA_PID"
fi

echo "serving $ROOT/policies + $ROOT/data from disk (edit a rule, re-request, no restart needed for data)"
exec "$OPA" run --server --addr "$ADDR" "$ROOT/policies" "$ROOT/data"
