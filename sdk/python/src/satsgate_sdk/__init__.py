"""satsgate-sdk

Python client for the satsgate API under model B.

- ``create_account`` opens an account. No API key is sent. The ``sg_`` key is returned once.
- Top up a free amount with ``topup_lightning`` or ``topup_usdc``. The prepaid balance
  is millisatoshis (``balance_msat``). It is not redeemable for sats, USDC, or fiat.
- A restricted ``sgr_`` key can read the balance. It cannot open an account or top up.
- The buyer payment still happens on Lightning or USDC. This SDK does not sign and
  does not ask for a seed or a private key.
- ``SatsgateClient.create_connect_link`` mints a one-time browser link. The URL is not logged.
- The customer backend submits ``Authorization: L402 ...`` and satsgate verifies it.
- ``max_uses`` / ``access_seconds`` on a challenge, with ``consume=True``, say what one payment buys.
- ``paywall_challenge(..., buyer_ip=)`` sends the end buyer's address. The server
  uses it only when the TCP peer is a trusted proxy.
"""

from .client import SatsgateClient, SatsgateError, create_account

__version__ = "0.10.1"

__all__ = ["SatsgateClient", "SatsgateError", "create_account"]
