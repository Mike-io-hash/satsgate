"""satsgate-sdk

Python client SDK for the satsgate API.

Concepts:
- *Credits* are bought upfront (plans) and spent on successful verification.
- The real payment happens on Lightning. A payer can return the preimage, or (when the
  wallet advertised LUD-21) the backend can poll until satsgate sees the invoice settle.
- The customer backend submits `Authorization: L402 ...` and satsgate verifies it.
- The account key (``sg_``) manages the account. ``create_api_key`` mints a restricted
  key (``sgr_``) for a proxy or MCP server that should only run the paywall.
- ``max_uses`` / ``access_seconds`` on a challenge, with ``consume=True``, say what one payment buys.
"""

from .client import SatsgateClient, SatsgateError

__version__ = "0.5.0"

__all__ = ["SatsgateClient", "SatsgateError"]
