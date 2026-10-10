#!/usr/bin/env sh
# One-command dev loop: sidecar in one terminal, engine in another.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# src/ layout works without an editable install, so the dev loop does not depend
# on the operator having run pip install first.
PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH

sh scripts/policy_test.sh
mkdir -p var

if [ "${1:-}" = "engine" ]; then
  exec python -m compliance_engine.server
fi
exec sh scripts/opa_serve.sh
