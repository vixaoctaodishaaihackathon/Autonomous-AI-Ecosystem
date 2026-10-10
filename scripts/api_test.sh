#!/usr/bin/env sh
# End-to-end API tests. They start their own OPA sidecar, so no setup is needed.
# Set OPA_BASE_URL to run them against a sidecar that is already serving, e.g.
# the bundle-mode one from `sh scripts/opa_serve.sh --bundle`.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec python -m pytest "$@"
