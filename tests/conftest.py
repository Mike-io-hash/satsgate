"""Keep unit tests off the public BTC/USD endpoints and off Base mainnet."""

from __future__ import annotations

import os

import pytest

os.environ["SATSGATE_RATES_ENABLED"] = "0"
os.environ.setdefault("SATSGATE_X402_CDP", "0")
os.environ.setdefault("SATSGATE_X402_CDP_KEY_ID", "")
os.environ.setdefault("SATSGATE_X402_CDP_KEY_SECRET", "")


@pytest.fixture(autouse=True)
def _x402_cdp_off():
    """A reloaded app copies os.environ. Reset the CDP switch around every test."""
    os.environ["SATSGATE_X402_CDP"] = "0"
    os.environ["SATSGATE_X402_CDP_KEY_ID"] = ""
    os.environ["SATSGATE_X402_CDP_KEY_SECRET"] = ""
    yield
    os.environ["SATSGATE_X402_CDP"] = "0"
    os.environ["SATSGATE_X402_CDP_KEY_ID"] = ""
    os.environ["SATSGATE_X402_CDP_KEY_SECRET"] = ""
