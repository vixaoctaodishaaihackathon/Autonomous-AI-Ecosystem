#!/usr/bin/env sh
# Run every policy test in the repo against the rule tables.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPA="${OPA:-$ROOT/.tools/opa.exe}"
[ -x "$OPA" ] || OPA="${OPA_BIN:-opa}"

# Replayability lint. A verdict has to be reproducible from its recorded input
# years later, so the packs read the clock out of the request and touch nothing
# outside the policy. OPA has no supported way to forbid these builtins from a
# config file on this build, so the guarantee is checked statically here instead:
# wall-clock reads, network calls, env access and print are refused, while pure
# date maths (time.parse_rfc3339_ns, used on request-supplied dates) stays legal.
offenders=$(find "$ROOT/policies" -name '*.rego' ! -name '*_test.rego' -print0 \
  | xargs -0 grep -nHE 'time\.now_ns|http\.send|\bprint\(|opa\.runtime|\benv\.' \
  || true)
if [ -n "$offenders" ]; then
  echo "policy uses non-replayable builtins:" >&2
  echo "$offenders" >&2
  exit 1
fi

exec "$OPA" test "$ROOT/policies" "$ROOT/data" --fail-on-empty "$@"
