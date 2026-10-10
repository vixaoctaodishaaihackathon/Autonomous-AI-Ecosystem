"""Shared fixtures: a real OPA sidecar on a free port, and the API in front of it.

The tests deliberately talk to a live policy engine rather than a mock. A
compliance contract that is only proven against a fake sidecar proves nothing
about the rules that actually ship.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from compliance_engine.app import create_app
from compliance_engine.config import Settings

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _opa_binary() -> str:
    for candidate in (ROOT / ".tools" / "opa.exe", ROOT / ".tools" / "opa"):
        if candidate.exists():
            return str(candidate)
    return "opa"


@pytest.fixture(scope="session")
def opa_url() -> str:
    # Point OPA_BASE_URL at an already-running sidecar (e.g. bundle mode, started
    # with `sh scripts/opa_serve.sh --bundle`) to prove the verdicts served by the
    # shipped artefact are the same ones the tests were written against.
    external = os.environ.get("OPA_BASE_URL")
    if external:
        if httpx.get(f"{external.rstrip('/')}/health", timeout=2.0).status_code != 200:
            pytest.exit(f"{external} is not a healthy OPA sidecar")
        yield external
        return

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [_opa_binary(), "run", "--server", "--addr", f"127.0.0.1:{port}",
         str(ROOT / "policies"), str(ROOT / "data")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.exit("OPA sidecar died during startup")
            try:
                if httpx.get(f"{base}/health", timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            pytest.exit("OPA sidecar did not become healthy in time")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture()
def settings(opa_url: str, tmp_path: Path) -> Settings:
    return Settings(
        opa_base_url=opa_url,
        ledger_path=tmp_path / "decisions.jsonl",
        review_closures_path=tmp_path / "review_closures.jsonl",
        gemini_api_key=None,
    )


@pytest.fixture()
def client(settings: Settings):
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client
