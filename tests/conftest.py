"""Keep unit tests off the public BTC/USD endpoints and off Base mainnet."""

from __future__ import annotations

import os

import pytest

os.environ["SATSGATE_RATES_ENABLED"] = "0"
# Existing debit tests prove a prepaid charge. The production default is 500
# free unlocks; those tests opt into "pay from the first unlock" here.
# Pricing tests that need the real quota set SATSGATE_FREE_QUOTA themselves
# and reload, or monkeypatch config.FREE_QUOTA.
os.environ.setdefault("SATSGATE_FREE_QUOTA", "0")
# The production caps are 3 per IP and 100 per day. Suites mint more than
# three accounts from one test client, so they opt out unless a test sets
# the real caps back.
os.environ.setdefault("SATSGATE_SIGNUP_MAX_PER_IP_PER_DAY", "100000")
os.environ.setdefault("SATSGATE_SIGNUP_MAX_GLOBAL_PER_DAY", "100000")
os.environ.setdefault("SATSGATE_X402_CDP", "0")
os.environ.setdefault("SATSGATE_X402_CDP_KEY_ID", "")
os.environ.setdefault("SATSGATE_X402_CDP_KEY_SECRET", "")


@pytest.fixture(autouse=True)
def _reset_pr11_env(monkeypatch):
    """Drop host-gate env a previous test may have written onto the process."""
    for name in (
        "SATSGATE_TERMS_VERSION",
        "SATSGATE_TERMS_URL",
        "SATSGATE_GEOBLOCK_COUNTRIES",
        "SATSGATE_ABUSE_CONTACT",
        "SATSGATE_SITES_AUTO_APPROVE",
    ):
        monkeypatch.delenv(name, raising=False)


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
