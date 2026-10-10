"""OPA sidecar client.

The service holds no policy logic: it hands the normalised input to the sidecar
and reads the verdict back. An undefined result is treated as a fault rather than
an outcome, because a Rego rule that silently fails to produce a value would
otherwise look like "the policy had nothing to say".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class OpaError(RuntimeError):
    pass


class OpaUnavailable(OpaError):
    pass


class PolicyUndefined(OpaError):
    """The sidecar answered but the queried rule produced no value."""


@dataclass(frozen=True)
class OpaAnswer:
    value: Any
    revision: str | None
    decision_id: str | None = None


class OpaClient:
    def __init__(self, base_url: str, timeout: float = 5.0, transport: httpx.AsyncBaseTransport | None = None):
        self._base = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def eval(self, path: str, input_doc: dict[str, Any]) -> OpaAnswer:
        url = f"{self._base}/v1/data/{path}"
        try:
            response = await self._client.post(url, json={"input": input_doc})
        except httpx.HTTPError as exc:  # connection refused, timeout, ...
            raise OpaUnavailable(f"OPA sidecar at {self._base} is not reachable: {exc}") from exc

        if response.status_code >= 400:
            raise OpaError(f"OPA returned {response.status_code}: {response.text[:400]}")

        body = response.json()
        if "result" not in body or body["result"] is None:
            raise PolicyUndefined(f"rule {path} produced no result for this input")
        return OpaAnswer(value=body["result"], revision=body.get("revision"))

    async def read(self, path: str) -> Any:
        url = f"{self._base}/v1/data/{path}"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as exc:
            raise OpaUnavailable(f"OPA sidecar at {self._base} is not reachable: {exc}") from exc
        if response.status_code >= 400:
            raise OpaError(f"OPA returned {response.status_code}: {response.text[:400]}")
        return response.json().get("result")

    async def ready(self) -> bool:
        try:
            response = await self._client.get(f"{self._base}/health")
        except httpx.HTTPError:
            return False
        return response.status_code < 400
