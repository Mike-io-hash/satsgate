#!/usr/bin/env python3
# Retired: credit packs are gone. USDC top-up is POST /v1/topup/usdc. This file is not a current example.
"""Retired pack example. It does not call the network."""

from __future__ import annotations

import sys


def main() -> int:
    print("Retired. Credit packs are gone. Top up with POST /v1/topup/usdc.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
