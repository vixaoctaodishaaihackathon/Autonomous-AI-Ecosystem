# Architecture

What the deterministic compliance engine is, where it sits in the agentic
ecosystem, and what its callers have to do about the answers it gives.

## 1. Position

The ecosystem has three pillars. This repository is the guardrail underneath all
three, not a fourth service off to the side:

| Pillar | Agent side | This engine's side |
| --- | --- | --- |
| 1. Deterministic + LLM hybrid guardrails | parse documents, propose facts | own the classification, and refuse to let a proposed fact clear a control |
| 2. Cross-region multi-tenant ingestion | move and join data | decide residency and transfer legality **before** the sink is written to |
| 3. Autonomous competitor and pricing engine | capture localized prices, recommend | bound what an agent may read, where it may compute, and what may leave the region |

The division of labour is fixed: **agents produce facts, Rego produces verdicts.**
Nothing in `src/compliance_engine` computes a legal outcome, and nothing in
`policies/` reads a document. If a rule change requires a Python change, the
design has been broken.

## 2. Request path

```
 agent / pipeline                 FastAPI boundary                    OPA sidecar
 ----------------                 --------------                      -----------
                                  validate shape + provenance
 normalise units      <----------- tables/dual_use_controls/params ---
 stamp clock from request (absent -> now, then recorded)
                                  POST /v1/data/{query}  with input --> rules + tables
                                  (undefined result = fault, 500, not a default)
 append to hash-chained ledger     decision_id, input, result, policy_revision
 return verdict + obligations      requires_human_review
```

The boundary is thin on purpose: it can only make a decision *less* trustworthy
by adding logic, and it is the place where untrusted input becomes a recorded
artifact.

## 3. Invariants

These are the properties the packs are built around. Each is covered by tests.

1. **Evidence asymmetry.** Sources are partitioned into authoritative
   (`CERTIFICATE`, `DECLARATION`, `SIGNED_SPEC_SHEET`, `REGULATOR_RULING`,
   `ERP_MASTER_DATA`, `MANUAL_VERIFICATION`) and machine
   (`GEMINI_EXTRACTION`, `LLM_EXTRACTION`, `MODEL_EXTRACTED`, `RULE_BASED_PARSER`).
   A permissive classification may only rest on the first set. Extraction can
   *add* risk without limit; it can remove none.
2. **Authority ceiling.** Every table declares `status`. `ILLUSTRATIVE_*` tables
   may escalate but never grant a terminal `ALLOW`; the response carries
   `authority_ceiling_applied: true` so the caller knows the verdict was capped.
3. **Terminality.** `ALLOW`, `DENY`, `PROHIBITED` end the conversation.
   `REQUIRE_LICENCE` / `REQUIRE_MECHANISM` block without ending: the pipeline
   stalls until a named authorisation or document exists, which is operationally
   different from "never do this".
4. **Fail closed, fail visibly.** Unrecognised input ranks to `HUMAN_REVIEW`.
   Unknown destination, undeclared categories, undeterminable residency,
   unparseable units, untraceable evidence: each becomes a named reason string
   rather than a silent pass. Rules are *total* - a malformed or empty payload
   still yields a decision, which matters because a `null` receiver in Rego
   undefines a rule and makes an entire screen vanish from the verdict.
5. **Replayability.** The clock is read from `input.clock`, never from the wall
   clock, and a static lint refuses `time.now_ns`, `http.send`, `print`, `env.`
   and `opa.runtime`. Re-evaluating a stored input returns the stored verdict.
6. **A decision that is not recorded did not happen.** The ledger append is inside
   the request path, not a background flush.

## 4. Pillar 2: the sovereign ingestion pipeline

The gate is a **pre-task precondition**, not a post-hoc audit. A job runner asks
before it materialises anything, and treats the verdict as follows:

- `ALLOW` - proceed, then implement every string in `result.obligations`. They are
  machine-actionable controls (`ENCRYPTION_AT_REST_IN_REGION`,
  `GEO_GENERALISATION_TO_H3_RES_5`, `TOKENISATION`, `NO_PAN_IN_LOGS`), not prose.
- `REQUIRE_MECHANISM` - do not run. `result.pending_mechanisms` and
  `result.missing_evidence` say which documents a human has to obtain.
- `HUMAN_REVIEW` - do not run; the job appears in `/v1/reviews` automatically.
- `DENY` / `PROHIBITED` - hard stop. `terminal: true` means the caller may not
  retry with different framing.

What the gate checks, in order:

1. **Residency.** The dataset's registry pins a home region and jurisdiction;
   `operation.processing_region` is checked against the tenant's
   `approved_processing_regions` and `forbidden_processing_regions`, then against
   the category's residency mode (`SOURCE_ONLY`, `REGION_ALLOWLIST`,
   `ADEQUACY_OR_BETTER`, `AGGREGATE_ONLY_CROSS_BORDER`, `UNRESTRICTED`). Hard
   localisation (payment card data in the reference tenants) is a `DENY`, not a
   review item.
2. **Aggregation.** Only aggregates cross a border under
   `AGGREGATE_ONLY_CROSS_BORDER`, and only if `aggregation.k_anonymity` meets the
   category's `min_k`; a row-level read is refused regardless of how the query is
   written.
3. **Transfer mechanism.** A ladder ordered by rank, each rung with conditions
   over request flags and relationship type, evidence refs, an optional `ceiling`,
   and `auto_clear`. Adequacy is the only rung that clears alone; every contract
   rung (SCC, BCR, Art.49 derogations, CAC filings) needs a human owner even when
   fully evidenced. The engine reports unmet evidence across **all** applicable
   rungs, so a caller cannot shop for the weakest one.
4. **Agent bounds.** `operation.agent_id` is resolved in the tenant registry and
   checked for purpose, operating region, `may_write_pii`, `aggregate_only_read`
   and `min_k_anonymity`. An unregistered agent is not a free agent.
5. **Volume.** Jurisdiction-specific triggers (PIPL/CAC thresholds, DPDP notice
   conditions) escalate on subject count and retention, with filing evidence
   required above the threshold.

Tenant isolation is structural: rule tables are global, tenants live in
`data/tenants/<id>/`, and each request carries its own registry, evidence and
agent set. There is no cross-tenant rule state.

## 5. Pillar 3: the pricing agent

A browser/headline-capture agent is the highest-risk component in the ecosystem
because its inputs are other companies' web pages and its outputs feed commercial
decisions. It is bound by the same two endpoints:

- **Before capture or analysis**, the job calls `/v1/data-transfer/gate` with
  `operation.agent_id` set to the registered scout (e.g. `tool_class:
  browser_capture`, `allowed_purposes: [competitive_pricing_intelligence]`,
  `autonomy_level: RECOMMEND_ONLY`, operating regions in the tenant's list). The
  engine's answer decides where the agent may compute and whether a localised
  price dataset may leave the region at all. `RECOMMEND_ONLY` is the registry's
  statement that a human approves any price commitment; the gate refuses the same
  agent a `writes_pii: true` job.
- **When the product itself is in scope** - a manufactured item being priced for
  export - the spec sheet goes to `/v1/export-control/facts` for extraction and
  then to `/v1/export-control/decisions` for classification. The facts endpoint
  returns parameters and provenance only; it has no code path that produces a
  verdict, so an agent cannot mistake an extraction for clearance.

The pricing engine's own outputs are not this service's concern; it stays
advisory. What this engine guarantees is that a pricing recommendation cannot be
built on data that was not allowed to be in that region, and that a controlled
item cannot be quoted into a destination that requires an authorisation nobody
obtained.

## 6. Audit surface

`var/decisions.jsonl` is append-only and hash-chained: `entry_hash` covers
`(seq, prev_hash, canonical(payload))`, so any edit, deletion or reorder breaks
`verify_chain()` at a specific `broken_at_seq`. Review closures are their own
chain, joined to decisions by `decision_id`; the review queue is *derived* from
the ledger rather than stored twice, so a verdict can not be "closed" in one place
and still open in another.

Replay procedure for an auditor: `GET /v1/decisions/{id}` returns the exact input
including the stamped clock and `policy_revision`; re-POST that input to the same
endpoint on a sidecar serving that artifact and the verdict must match.

## 7. Authoring and release

```
edit policies/ or data/  ->  sh scripts/policy_test.sh   (lint + 69 rule tests)
                          ->  sh scripts/policy_build.sh  (bundle + self-verify)
                          ->  sidecar pulls it on its poll interval
                          ->  sh scripts/api_test.sh OPA_BASE_URL=... (optional: run the
                              API suite against the artifact that just shipped)
```

Tests are excluded from the bundle: a shipping policy must not carry the
assertions that describe it. The build refuses to publish an artifact whose
tables, tenants, packs or stamped revision do not resolve when reloaded.

Rule-table refresh is a compliance-owner task with a stated cadence
(`review_cadence_days`) and a `legal_notice` per table; `/v1/policies/version`
publishes both, plus which tables are still unverified.

## 8. Limits

- Reference tables are modelled from public descriptions of the instruments, not
  transcriptions. They demonstrate the machinery; they are not a legal defence
  until sourced and signed off.
- Sanctions/denied-party and customs/tariff packs are not implemented. Only the
  end-user screening precondition hook exists, and it fails closed on `NOT_RUN`
  and `STALE`.
- The ledger is a single-node file. Replicas need shared append-only storage that
  satisfies the same chain contract.
- Admission is a shared bearer key at the HTTP boundary plus a per-process rate
  limit. It authenticates a caller; it does not authorise one, so a key holder can
  ask about any tenant, and `X-Tenant-Id` remains an accident guard against a
  body/header mismatch rather than a boundary. Per-tenant credentials still belong
  to a gateway, or to a Rego pack that reads them.
