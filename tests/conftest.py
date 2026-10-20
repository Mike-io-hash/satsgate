"""Keep unit tests off the public BTC/USD endpoints."""

from __future__ import annotations

import os

os.environ["SATSGATE_RATES_ENABLED"] = "0"
