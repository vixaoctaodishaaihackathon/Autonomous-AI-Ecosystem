"""FastAPI boundary in front of the OPA sidecar.

Kept deliberately thin: validate, normalise units, stamp the clock, ask the
policy, record what it said. Any rule about what a verdict means belongs in
Rego, so a change in compliance posture never needs a deployment of this
service.
"""

from __future__ import annotations

import hmac
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .extract import build_extractor
from .ledger import DecisionLedger, new_decision_id, utc_now_iso
from .opa import OpaClient, OpaError, OpaUnavailable, PolicyUndefined
from .reviews import ReviewQueue
from .schemas import ExportControlRequest, TransferGateRequest
from .units import normalise_parameters

TABLE_AUTHORITIES = (
    "tables/dual_use_controls/authority",
    "tables/destinations/authority",
    "tables/residency_rules/authority",
    "tables/transfer_mechanisms/authority",
    "tables/jurisdictions/authority",
    "tables/regions/authority",
)


def create_app(settings: Settings | None = None, opa: OpaClient | None = None) -> FastAPI:
    resolved = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = opa or OpaClient(resolved.opa_base_url, resolved.opa_timeout_seconds)
        app.state.settings = resolved
        app.state.opa = client
        app.state.ledger = DecisionLedger(resolved.ledger_path)
        app.state.reviews = ReviewQueue(app.state.ledger, resolved.review_closures_path)
        app.state.extractor = build_extractor(resolved.gemini_api_key, resolved.gemini_model)
        app.state.param_meta = None
        app.state.param_meta_fetched_at = 0.0
        app.state.revision_cache = {"value": None, "at": 0.0}
        app.state.rate_window = {}
        try:
            yield
        finally:
            await client.aclose()

    app = FastAPI(
        title="Deterministic compliance engine",
        version="0.1.0",
        lifespan=lifespan,
        default_response_class=JSONResponse,
    )

    # Unset ENGINE_API_KEY leaves the boundary open, which is what the dev loop and
    # the test suite need; ops/docker-entrypoint.sh refuses to start a container
    # without it, so the deployment path cannot come up open by accident.
    if resolved.api_key is not None and len(resolved.api_key) < 16:
        raise ValueError("ENGINE_API_KEY is too short to be a shared secret")

    @app.middleware("http")
    async def admit(request: Request, call_next):
        if resolved.api_key is None or request.url.path in ("/healthz", "/readyz"):
            return await call_next(request)

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token.strip(), resolved.api_key):
            return JSONResponse(
                status_code=401,
                content={"detail": "missing or invalid bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Render terminates TLS, so request.client is its proxy; the caller's own
        # address is the first entry of the header it appends.
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        caller = forwarded or (request.client.host if request.client else "unknown")
        window = int(time.time() // 60)
        started, count = app.state.rate_window.get(caller, (window, 0))
        if started != window:
            count = 0
        if count >= resolved.rate_limit_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "rate limit exceeded"},
                headers={"Retry-After": str(max(1, 60 - int(time.time() % 60)))},
            )
        app.state.rate_window[caller] = (window, count + 1)
        if len(app.state.rate_window) > 4096:
            app.state.rate_window = {
                key: value for key, value in app.state.rate_window.items() if value[0] == window
            }
        return await call_next(request)

    async def parameter_meta() -> dict[str, Any]:
        cache_ttl = 60.0
        state = app.state
        if state.param_meta is None or time.monotonic() - state.param_meta_fetched_at > cache_ttl:
            try:
                meta = await state.opa.read(resolved.control_params_query)
            except OpaUnavailable as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except OpaError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            if not isinstance(meta, dict):
                raise HTTPException(status_code=503, detail="control-list parameter table is not available")
            state.param_meta = meta
            state.param_meta_fetched_at = time.monotonic()
        return state.param_meta

    async def served_revision() -> str | None:
        """Identify the policy artifact the sidecar is answering from.

        This is metadata, not a verdict: a sidecar serving rules straight from
        disk in dev mode has no artifact revision, and that must not fail a
        decision that is otherwise answerable.
        """
        cache = app.state.revision_cache
        if cache["at"] == 0.0 or time.monotonic() - cache["at"] > 60.0:
            try:
                value = await app.state.opa.read(resolved.policy_revision_query)
            except OpaError:
                value = None
            cache["value"] = value if isinstance(value, str) else None
            cache["at"] = time.monotonic()
        return cache["value"]

    def _clock(payload_clock: Any) -> dict[str, int]:
        if payload_clock is not None:
            return {"milliseconds": int(payload_clock.milliseconds)}
        # The policy reads its clock from input so a stored decision can be
        # replayed; the service stamps it here and records it with the verdict.
        return {"milliseconds": int(time.time() * 1000)}

    def _check_tenant_header(body_tenant_id: str, header_tenant_id: str | None) -> None:
        if header_tenant_id and header_tenant_id != body_tenant_id:
            raise HTTPException(
                status_code=403,
                detail="X-Tenant-Id does not match the tenant in the request body",
            )

    async def _evaluate(query: str, input_doc: dict[str, Any], *, tenant_id: str, endpoint: str,
                        normalisation: list[dict] | None = None) -> dict[str, Any]:
        try:
            answer = await app.state.opa.eval(query, input_doc)
        except PolicyUndefined as exc:
            raise HTTPException(status_code=500, detail=f"policy produced no verdict: {exc}") from exc
        except OpaUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except OpaError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        result = answer.value
        revision = answer.revision or await served_revision()
        decision_id = input_doc.get("request_id") or new_decision_id()
        payload = {
            "decision_id": decision_id,
            "endpoint": endpoint,
            "tenant_id": tenant_id,
            "input": input_doc,
            "result": result,
            "policy_revision": revision,
            "normalisation": normalisation or [],
        }
        entry = app.state.ledger.append(payload)
        return {
            "decision_id": decision_id,
            "recorded_at": entry["recorded_at"],
            "ledger_seq": entry["seq"],
            "ledger_entry_hash": entry["entry_hash"],
            "policy_revision": revision,
            "fact_normalisation": normalisation or [],
            "requires_human_review": bool(result.get("escalation", {}).get("required")),
            "result": result,
        }

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "service": resolved.service_name, "time": utc_now_iso()}

    @app.get("/readyz")
    async def readyz() -> dict[str, Any]:
        ready = await app.state.opa.ready()
        if not ready:
            raise HTTPException(status_code=503, detail="OPA sidecar is not answering")
        return {"status": "ready", "opa": resolved.opa_base_url}

    @app.get("/v1/policies/version")
    async def policies_version() -> dict[str, Any]:
        tables = []
        for path in TABLE_AUTHORITIES:
            table_id = path.split("/")[1]
            try:
                authority = await app.state.opa.read(path)
            except OpaError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            if not isinstance(authority, dict):
                continue
            tables.append(
                {
                    "table_id": authority.get("table_id", table_id),
                    "table_version": authority.get("table_version"),
                    "modelled_authority": authority.get("modelled_authority"),
                    "status": authority.get("status"),
                    "effective_date": authority.get("effective_date"),
                    "review_cadence_days": authority.get("review_cadence_days"),
                }
            )
        return {
            "policy_engine": "opa",
            "served_policy_revision": await served_revision(),
            "tables": tables,
            "authority_unverified": [t["table_id"] for t in tables if str(t["status"]).startswith("ILLUSTRATIVE")],
        }

    @app.post("/v1/export-control/decisions")
    async def export_control_decision(
        body: ExportControlRequest,
        request: Request,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _check_tenant_header(body.tenant_id, x_tenant_id)
        meta = await parameter_meta()

        payload = body.model_dump(mode="json", exclude_none=True)
        params = payload["item"].pop("technical_parameters", {})
        normalised, notes = normalise_parameters(params, meta)
        payload["item"]["technical_parameters"] = normalised
        payload["clock"] = _clock(body.clock)
        payload.setdefault("request_id", request.headers.get("x-request-id") or new_decision_id())

        return await _evaluate(
            resolved.export_control_query,
            payload,
            tenant_id=body.tenant_id,
            endpoint="/v1/export-control/decisions",
            normalisation=[note.__dict__ for note in notes],
        )

    @app.post("/v1/data-transfer/gate")
    async def transfer_gate(
        body: TransferGateRequest,
        request: Request,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _check_tenant_header(body.tenant_id, x_tenant_id)

        payload = body.model_dump(mode="json", exclude_none=True)
        payload["clock"] = _clock(body.clock)
        payload.setdefault("request_id", request.headers.get("x-request-id") or new_decision_id())

        return await _evaluate(
            resolved.data_governance_query,
            payload,
            tenant_id=body.tenant_id,
            endpoint="/v1/data-transfer/gate",
        )

    @app.post("/v1/export-control/facts")
    async def extract_facts(
        body: dict[str, Any],
        source: str | None = Header(default=None, alias="X-Fact-Source"),
    ) -> dict[str, Any]:
        """Turn spec text into machine-sourced facts. Returns no verdict, ever.

        Feed the result into /v1/export-control/decisions; the policy decides how
        much weight an extracted fact can carry.
        """
        text = body.get("text")
        if not isinstance(text, str) or not text.strip():
            raise HTTPException(status_code=422, detail="body.text with the document text is required")
        facts = await app.state.extractor.extract(text)
        return {
            "extractor": app.state.extractor.name,
            "technical_parameters": facts,
            "authoritative": False,
            "note": (
                "Machine-extracted facts can raise risk but cannot retire it; "
                "a permissive classification needs an authoritative source."
            ),
        }

    @app.get("/v1/reviews")
    async def list_reviews() -> dict[str, Any]:
        return {"open": app.state.reviews.open_reviews()}

    @app.post("/v1/reviews/{decision_id}/close")
    async def close_review(decision_id: str, body: dict[str, Any]) -> dict[str, Any]:
        reviewer = str(body.get("reviewer") or "").strip()
        outcome = str(body.get("outcome") or "").strip()
        if not reviewer or "@" not in reviewer:
            raise HTTPException(status_code=422, detail="reviewer must be a identifiable address")
        if outcome not in {"APPROVED", "REJECTED", "NEEDS_MORE_INFORMATION"}:
            raise HTTPException(status_code=422, detail="outcome must be APPROVED, REJECTED or NEEDS_MORE_INFORMATION")
        try:
            entry = app.state.reviews.close(
                decision_id, reviewer=reviewer, outcome=outcome, note=str(body.get("note") or "")
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="no recorded decision with that id") from None
        return {"closed": decision_id, "outcome": outcome, "ledger_entry_hash": entry["entry_hash"]}

    @app.get("/v1/decisions/{decision_id}")
    async def get_decision(decision_id: str) -> dict[str, Any]:
        entry = app.state.ledger.find(decision_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="no recorded decision with that id")
        return entry

    @app.get("/v1/ledger/verify")
    async def verify_ledger() -> dict[str, Any]:
        return {
            "decisions": app.state.ledger.verify_chain(),
            "review_closures": app.state.reviews.verify_chain(),
        }

    return app


app = create_app()
