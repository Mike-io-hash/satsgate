import os

from dotenv import load_dotenv

# Load env vars from .env if present
load_dotenv()

# L402 token signing
MACAROON_SECRET = os.environ.get("SATSGATE_MACAROON_SECRET", "dev-change-me")

# Demo endpoint pricing (/v1/tickets)
PRICE_SATS = int(os.environ.get("SATSGATE_PRICE_SATS", "10"))

# Token TTL (seconds)
TOKEN_TTL_SECONDS = int(os.environ.get("SATSGATE_TOKEN_TTL_SECONDS", "600"))

# Wallet backend
# - mock: simulated wallet (local testing)
# - lnaddr: generate invoices via Lightning Address (LNURL-pay)
WALLET_MODE = os.environ.get("SATSGATE_WALLET_MODE", "mock").strip().lower()
LIGHTNING_ADDRESS = os.environ.get("SATSGATE_LIGHTNING_ADDRESS", "").strip()

# Database
DB_PATH = os.environ.get(
    "SATSGATE_DB_PATH",
    os.path.join(os.path.dirname(__file__), "..", "satsgate.sqlite3"),
)

# Rate limit (simple in-memory MVP)
RL_ENABLED = os.environ.get("SATSGATE_RL_ENABLED", "1") == "1"
RL_WINDOW_SECONDS = int(os.environ.get("SATSGATE_RL_WINDOW_SECONDS", "60"))
RL_MAX_ANON = int(os.environ.get("SATSGATE_RL_MAX_ANON", "60"))
RL_MAX_AUTH = int(os.environ.get("SATSGATE_RL_MAX_AUTH", "600"))

# Operator/admin token.
# When set, enables /v1/admin/* endpoints (protected via X-Admin-Token header).
ADMIN_TOKEN = os.environ.get("SATSGATE_ADMIN_TOKEN", "").strip()

# Dev mode enables /dev/* endpoints
DEV_MODE = os.environ.get("SATSGATE_DEV_MODE", "1") == "1"
