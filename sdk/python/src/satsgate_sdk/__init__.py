"""satsgate-sdk

Python client SDK for the satsgate API.

Concepts:
- *Credits* are bought upfront (plans) and spent on successful verification.
- The real payment happens on Lightning. A payer can return the preimage, or (when the
  wallet advertised LUD-21) the backend can poll until satsgate sees the invoice settle.
- The customer backend submits `Authorization: L402 ...` and satsgate verifies it.
"""

from .client import SatsgateClient, SatsgateError

__all__ = ["SatsgateClient", "SatsgateError"]
