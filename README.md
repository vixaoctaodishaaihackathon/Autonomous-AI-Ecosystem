# Deterministic compliance engine

Policy-as-code gate for cross-border enterprise operations: OPA/Rego decides, a
thin FastAPI boundary serves, and a hash-chained ledger records every verdict
with the exact input that produced it.

This is the layer the rest of the ecosystem is not allowed to reason about on
its own. An LLM agent extracts facts from a spec sheet or a customs declaration;
this engine turns those facts into a legal outcome using deterministic rule
tables. The agent never gets to state whether the transfer is lawful.

Three properties the design is built around:

1. **The LLM cannot clear a control.** Facts carry provenance; a permissive
   classification requires an authoritative source. Machine-extracted facts can
   raise risk, never retire it (`test_extraction_can_never_retire_a_control`).
2. **Every verdict is replayable.** The policy reads its clock from the request,
   so re-evaluating a stored input years later returns the same answer. A lint in
   `scripts/policy_test.sh` refuses rules that call `time.now_ns`, `http.send`,
   `print`, `env.` or `opa.runtime`.
3. **An unverified rule table can only tighten, never grant.** Tables marked
   `ILLUSTRATIVE_*` may escalate a job but cannot produce a terminal `ALLOW`
   (`authority_ceiling_applied` in the response tells you when this happened).

## Layout

```
policies/            Rego packs - the only place a legal rule is expressed
  common/            decision algebra, total accessors, evidence helpers
  export_control/    dual-use matching, provenance, licence logic
  data_governance/   residency modes, transfer-mechanism ladder, agent bounds
data/                rule tables (control lists, destinations, jurisdictions,
                     regions, residency rules, mechanisms) + tenant registries
src/compliance_engine/
  app.py             HTTP boundary: validate, normalise, evaluate, record
  schemas.py         request models - shape and provenance only, never legality
  opa.py             async sidecar client
  units.py           unit normalisation against the table's own parameter units
  ledger.py          append-only hash-chained decision log
  reviews.py         review queue derived from the ledger (not a second store)
  extract.py         deterministic parser + optional Gemini fact extractor
ops/opa-config.yaml  sidecar bundle hot-reload config
scripts/             test / build / serve / dev entry points
tests/               end-to-end API tests against a live sidecar
```

## Quickstart

Needs Python 3.11+ and an OPA binary. The scripts use `.tools/opa.exe` when it is
present and fall back to `opa` on `PATH` (override with `OPA=/path/to/opa`); the
tools directory is git-ignored because the sidecar version is a deployment
decision, not a source file.

```sh
python -m venv .venv && . .venv/Activate
pip install -e ".[dev]"
cp .env.example .env                      # no key needed to run

sh scripts/policy_test.sh                 # opa test + replayability lint (69 tests)
sh scripts/dev.sh                         # OPA sidecar on :8181, rules from disk
sh scripts/dev.sh engine                  # in another terminal: engine on :8080
sh scripts/api_test.sh                    # 35 end-to-end tests
```

Release-path run (what production looks like):

```sh
sh scripts/policy_build.sh                # -> builds/bundles/policy, self-verified
sh scripts/opa_serve.sh --bundle          # sidecar + local bundle store
```

`--bundle` mode serves the compiled artifact over HTTP because OPA's bundle
plugin only pulls bundles from an HTTP endpoint (`file://` is not supported).
Rebuild the bundle and the running sidecar picks it up on its own poll interval;
no restart, no engine deploy. `plugins.bundle.polling` cannot be set through the
config shape this OPA build accepts, so reload latency is OPA's default backoff
(observed: ~1-2 min worst case) rather than a fixed 5s. Use disk mode while
authoring rules - it reloads on every request.

Each build stamps its revision into the artifact, and the engine reads it back so
that every ledger entry says which policy version produced the verdict
(`policy_revision` on a decision, `served_policy_revision` on
`/v1/policies/version`). It is `null` in disk mode, where there is no artifact.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz`, `/readyz` | liveness; readiness also requires the sidecar |
| `GET` | `/v1/policies/version` | table versions, authorities, and which are unverified |
| `POST` | `/v1/export-control/decisions` | dual-use classification + licence requirement |
| `POST` | `/v1/data-transfer/gate` | cross-border residency + transfer mechanism |
| `POST` | `/v1/export-control/facts` | document text to facts. Returns facts, never a verdict |
| `GET` | `/v1/reviews` | open human-review items, derived from the ledger |
| `POST` | `/v1/reviews/{decision_id}/close` | named reviewer, recorded in its own chain |
| `GET` | `/v1/decisions/{decision_id}` | the stored verdict and its recorded input |
| `GET` | `/v1/ledger/verify` | hash-chain integrity for decisions and closures |

`/healthz` and `/readyz` stay open for the platform. Everything else answers
`401` without `Authorization: Bearer <ENGINE_API_KEY>` once a key is configured,
which the container requires: `/v1/decisions/{id}` returns the input a caller
recorded, and the decision endpoints write to the ledger.

Unknown JSON fields are rejected with `422`, not ignored: a typo in a compliance
payload must not silently evaluate as an absent fact.

### Export control

```sh
curl -s localhost:8080/v1/export-control/decisions -H 'content-type: application/json' -d '{
  "tenant_id": "tnt_vega_manufacturing",
  "request_id": "req-api-0001",
  "destination_country": "DE",
  "item": {
    "sku": "VCU-500",
    "description": "vehicle domain controller assembly",
    "technical_parameters": {
      "crypto_function":      {"value": true, "evidence": {"source": "MANUAL_VERIFICATION", "ref": "spec-1"}},
      "symmetric_key_bits":   {"value": 256, "unit": "bit", "evidence": {"source": "MANUAL_VERIFICATION", "ref": "spec-1"}}
    }
  },
  "end_user": {"screening_status": "CLEAR", "screening_ref": "scr-99"},
  "clock": {"milliseconds": 1791633600000}
}'
```

`result.decision` is `REQUIRE_LICENCE` with `result.control_code == "5A002"`,
`result.terminal == false`, and `OBTAIN_EXPORT_AUTHORISATION` in obligations.
Parameters are normalised to the units the control table itself declares, so
`{"value": 0.25, "unit": "Mbit"}` becomes `250000` bit; a unit outside that
family is left alone and surfaced as `FACT_UNIT_NOT_RESOLVED` instead of being
guessed at.

### Transfer gate

```sh
curl -s localhost:8080/v1/data-transfer/gate -H 'content-type: application/json' -d '{
  "tenant_id": "tnt_vega_manufacturing",
  "request_id": "job-api-0001",
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
```

`result.decision` is the verdict the caller must obey; `result.rules_verdict` is
what the rules said before the authority ceiling was applied. The example above
selects `SCC_MODULE_2_C2P`, finds the tenant's evidence already on file
(`result.missing_evidence == []`) and still returns `HUMAN_REVIEW` with
`TRANSFER_MECHANISM_NEEDS_HUMAN_SIGN_OFF`: a route that rests on a contract the
parties signed needs a named human, and only `auto_clear` routes - adequacy -
ever clear on their own. A tenant without those documents gets the same route
with the outstanding refs in `result.missing_evidence`; claiming a mechanism is
not proving it.

### Verdict vocabulary

`ALLOW` (0) < `HUMAN_REVIEW` (1) < `REQUIRE_LICENCE` / `REQUIRE_MECHANISM` (2) <
`DENY` (3) < `PROHIBITED` (4). Only `ALLOW`, `DENY` and `PROHIBITED` are
terminal. The two `REQUIRE_*` states are blocking but non-terminal: the pipeline
must stop and go get the missing authorisation or evidence, which is a different
operational action from "this may never happen". Anything the engine cannot work
out collapses to `HUMAN_REVIEW`, never to `ALLOW`.

## Failure semantics

Fail closed, loudly, and never with a silently missing verdict:

- sidecar unreachable → `503`; policy error → `502`; policy undefined → `500`
- malformed/empty/null payload sections still evaluate to a decision (totality
  tests cover this; a null section used to make a whole screen vanish)
- declared data categories that resolve to no rule → `RESIDENCY_STATE_UNDETERMINED`
  and review, not a silent pass
- a decision that is not recorded is a decision that did not happen: the ledger
  append is inside the request path

## Scope and limits

- The rule tables are **modelled from public descriptions of EU 2021/949, the
  Wassenaar dual-use list, EAR CCL, GDPR Chapter V, DPDP, PIPL/CAC and Brazil's
  ANPD**, not transcribed from the instruments. Every table carries
  `status: ILLUSTRATIVE_*`, a `legal_notice`, and a review cadence; `/v1/policies/version`
  lists them. A compliance owner has to replace them with sourced tables before
  any of this is a defence rather than a control.
- Built packs: export control / dual-use, data residency and transfer. Sanctions
  screening and customs/tariff were deliberately not built; the only hook is the
  `end_user.screening_status` precondition, which fails closed when screening is
  `NOT_RUN` or `STALE`.
- Single-node ledger (`var/*.jsonl`) behind a write lock. Multiple replicas need
  shared append-only storage with real CAS; `verify_chain()` is the contract that
  storage has to satisfy.
- Authentication is one shared bearer key (`ENGINE_API_KEY`), enforced at the HTTP
  boundary, not in Rego: unset it and the port is open, which is what the dev loop
  and test suite need, so `ops/docker-entrypoint.sh` refuses to start a container
  without it. It proves *who* called, not *what they may do* - there is still no
  per-tenant authorisation, and `X-Tenant-Id` checked against the body is a bug
  guard, not a boundary. The rate limit is a per-minute counter in this process, so
  it protects one node, not a fleet.
