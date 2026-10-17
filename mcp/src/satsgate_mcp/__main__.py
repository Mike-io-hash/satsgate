"""stdio entrypoint: python -m satsgate_mcp"""

from __future__ import annotations

import logging
import sys


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(name)s %(message)s")
    from satsgate_mcp.redact import install

    install()
    from satsgate_mcp.server import build_server

    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
