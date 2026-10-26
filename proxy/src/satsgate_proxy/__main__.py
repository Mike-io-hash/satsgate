"""Run the proxy: ``python -m satsgate_proxy --config satsgate-proxy.yaml``."""

from __future__ import annotations

import argparse
import logging
import os
import sys

import uvicorn

from satsgate_proxy import __version__
from satsgate_proxy.app import build_app
from satsgate_proxy.config import ConfigError, key_fingerprint, load_settings


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="satsgate-proxy")
    parser.add_argument(
        "--config",
        default=os.environ.get("SATSGATE_PROXY_CONFIG", "satsgate-proxy.yaml"),
        help="Path to the YAML config. Defaults to SATSGATE_PROXY_CONFIG or ./satsgate-proxy.yaml.",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"satsgate-proxy: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    log = logging.getLogger("satsgate_proxy")
    names = ", ".join(name for name, _value in settings.inject_headers)
    log.info(
        "satsgate-proxy %s listen %s:%s core %s key fp %s upstream %s routes %s inject [%s]",
        __version__,
        settings.host,
        settings.port,
        settings.core_base_url,
        key_fingerprint(settings.api_key),
        settings.upstream_base_url,
        len(settings.routes),
        names,
    )
    uvicorn.run(build_app(settings), host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
