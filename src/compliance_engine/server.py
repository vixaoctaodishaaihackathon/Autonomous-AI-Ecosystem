"""Uvicorn entrypoint."""

from __future__ import annotations

import os


def main() -> None:
    import uvicorn

    host = os.environ.get("ENGINE_HOST", "127.0.0.1")
    port = int(os.environ.get("ENGINE_PORT", "8080"))
    uvicorn.run("compliance_engine.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
