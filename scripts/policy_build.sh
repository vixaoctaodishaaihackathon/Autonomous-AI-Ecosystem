#!/usr/bin/env sh
# Build the policy rules and the rule tables into one hot-reloadable OPA bundle.
#
# A single staging root is used because OPA refuses to merge two implicit bundle
# roots. The rules move from policies/<pack> to <stage>/policy/<pack> so the
# directory tree matches the `package policy.*` declarations, which is what a
# bundle requires. Tests stay out of the bundle: a shipping policy must not carry
# the assertions that describe it.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPA="${OPA:-$ROOT/.tools/opa.exe}"
[ -x "$OPA" ] || OPA="${OPA_BIN:-opa}"

STAGE="$ROOT/builds/stage"
REVISION="$(date -u +%Y%m%dT%H%M%SZ)"

rm -rf "$STAGE"
mkdir -p "$STAGE"
for pack in export_control data_governance common; do
  mkdir -p "$STAGE/policy/$pack"
  for file in "$ROOT/policies/$pack"/*.rego; do
    case "$file" in *_test.rego) continue ;; esac
    cp "$file" "$STAGE/policy/$pack/"
  done
done
# A bundle file rooted at /tables/... becomes data.tables..., so the repo's data/
# directory is staged *as* the bundle root rather than nested inside it. A staged
# data/data tree would resolve to data.data.tables and the rules would read none.
cp -r "$ROOT/data/." "$STAGE/"

# Stamp the artifact's identity into the data tree. This OPA build does not echo a
# bundle revision on the data API and serves no /v1/plugins, so without this the
# ledger could not say which policy version produced a verdict.
mkdir -p "$STAGE/policy_build"
printf '{"revision":"%s","built_at":"%s"}\n' "$REVISION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  > "$STAGE/policy_build/data.json"

# Build from inside the stage so OPA sees relative paths; passing a Git-Bash
# absolute path leaks a Windows path into the archive names.
#
# The artifact is named `policy`, not `policy.tar.gz`: a sidecar configured with
# only a `service` pulls the default resource path /bundles/<name>, and OPA
# detects gzip from the magic bytes, so the extension is what the URL needs to
# match, not what the loader needs.
mkdir -p "$ROOT/builds/bundles"
cd "$STAGE"
"$OPA" build --bundle --revision "$REVISION" --output ../bundles/policy .
cd "$ROOT"
# Leave no second copy of the policy text lying around: an editor that opens a
# stale build/stage file and changes it there changes nothing that is served.
rm -rf "$STAGE"

echo "built builds/bundles/policy revision $REVISION"

# A bundle can build successfully and still serve an empty rule set, so load it
# back and require the tables and packs to actually resolve before publishing it.
BUNDLE="$ROOT/builds/bundles/policy"
tables=$("$OPA" eval -b "$BUNDLE" 'count(object.keys(data.tables))' --format raw)
tenants=$("$OPA" eval -b "$BUNDLE" 'count(object.keys(data.tenants))' --format raw)
packs=$("$OPA" eval -b "$BUNDLE" 'count(object.keys(data.policy))' --format raw)
stamped=$("$OPA" eval -b "$BUNDLE" 'data.policy_build.revision' --format raw)
[ "$tables" -ge 1 ] && [ "$tenants" -ge 1 ] && [ "$packs" -ge 3 ] || {
  echo "bundle is not loadable: tables=$tables tenants=$tenants packs=$packs" >&2
  exit 1
}
[ "$stamped" = "$REVISION" ] || {
  echo "bundle does not carry its own revision: read $stamped, expected $REVISION" >&2
  exit 1
}
echo "bundle verified: $tables tables, $tenants tenants, $packs policy packs, revision $stamped"
echo "run: sh scripts/opa_serve.sh --bundle   (sidecar reloads within its poll interval)"
