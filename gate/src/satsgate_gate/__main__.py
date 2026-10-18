"""Run the gate: ``python -m satsgate_gate``."""

from __future__ import annotations

import logging

import uvicorn

from satsgate_gate import __version__
from satsgate_gate.app import create_app
from satsgate_gate.config import ConfigError, load_settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    try:
        settings = load_settings()
    except ConfigError as exc:
        raise SystemExit(f"satsgate-gate: {exc}") from exc
    log = logging.getLogger("satsgate_gate")
    log.info("satsgate-gate %s core %s cache %ss", __version__, settings.core_base_url, settings.cache_seconds)
    uvicorn.run(create_app(settings), host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
