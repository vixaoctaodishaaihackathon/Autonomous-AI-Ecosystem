from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def load_dotenv(path: Path | None = None) -> None:
    """Populate os.environ from a .env file without overriding what is set."""
    root = _repo_root()
    env_file = path or root / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass(frozen=True)
class Settings:
    """Everything the service knows about its environment.

    The policy itself is never read from here: rules and rule tables come from
    the OPA sidecar, so a decision cannot depend on service configuration.
    """

    opa_base_url: str = "http://127.0.0.1:8181"
    opa_timeout_seconds: float = 5.0
    export_control_query: str = "policy/export_control/result"
    data_governance_query: str = "policy/data_governance/result"
    control_params_query: str = "tables/dual_use_controls/params"
    # Written into the artefact by scripts/policy_build.sh: which bundle the
    # sidecar is actually serving right now.
    policy_revision_query: str = "policy_build/revision"
    ledger_path: Path = _repo_root() / "var" / "decisions.jsonl"
    review_closures_path: Path = _repo_root() / "var" / "review_closures.jsonl"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"
    service_name: str = "compliance-engine"
    # Transport-level gate for the HTTP boundary only. Which tenant may do what is
    # a policy question and stays in Rego; this only decides who may talk to us.
    api_key: str | None = None
    rate_limit_per_minute: int = 60

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        root = _repo_root()
        return cls(
            opa_base_url=_env("OPA_BASE_URL", "http://127.0.0.1:8181").rstrip("/"),
            opa_timeout_seconds=float(_env("OPA_TIMEOUT_SECONDS", "5")),
            ledger_path=Path(_env("LEDGER_PATH", str(root / "var" / "decisions.jsonl"))),
            review_closures_path=Path(
                _env("REVIEW_CLOSURES_PATH", str(root / "var" / "review_closures.jsonl"))
            ),
            gemini_api_key=os.environ.get("GEMINI_API_KEY") or None,
            gemini_model=_env("GEMINI_MODEL", "gemini-2.5-flash"),
            api_key=os.environ.get("ENGINE_API_KEY") or None,
            rate_limit_per_minute=int(_env("ENGINE_RATE_LIMIT_PER_MINUTE", "60")),
        )

    @property
    def root(self) -> Path:
        return _repo_root()


def load_settings() -> Settings:
    return Settings.from_env()
