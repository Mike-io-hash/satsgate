import json
import os

from dotenv import load_dotenv

# Load env vars from .env if present. Existing process env wins.
load_dotenv()

APP_VERSION = "0.4.0"

# production is the safe default. Local mock/dev only runs when this is explicit.
SATSGATE_ENV = os.environ.get("SATSGATE_ENV", "production").strip().lower() or "production"
LOCAL_ENVS = frozenset({"development", "dev", "local", "test"})

# L402 token signing. No insecure default in production (see validate_startup).
MACAROON_KEY_ID = os.environ.get("SATSGATE_MACAROON_KEY_ID", "1").strip() or "1"
MACAROON_SECRET = os.environ.get("SATSGATE_MACAROON_SECRET", "")
_PREVIOUS_KEYS_RAW = os.environ.get("SATSGATE_MACAROON_PREVIOUS_KEYS", "").strip()

# Demo endpoint pricing (/v1/tickets, dev-only)
PRICE_SATS = int(os.environ.get("SATSGATE_PRICE_SATS", "10"))

# Token TTL (seconds)
TOKEN_TTL_SECONDS = int(os.environ.get("SATSGATE_TOKEN_TTL_SECONDS", "600"))

# Wallet backend
# - mock: simulated wallet (local testing only)
# - lnaddr: generate invoices via Lightning Address (LNURL-pay)
WALLET_MODE = os.environ.get("SATSGATE_WALLET_MODE", "mock").strip().lower()
LIGHTNING_ADDRESS = os.environ.get("SATSGATE_LIGHTNING_ADDRESS", "").strip()

# BOLT11 network expected from LNURL-pay providers. mainnet unless a self-hoster opts out.
LN_NETWORK = os.environ.get("SATSGATE_LN_NETWORK", "mainnet").strip().lower() or "mainnet"

# LUD-12 comment on the LNURL-pay callback. Off by default: some providers (Alby)
# put the comment in the BOLT11 description and drop description_hash = SHA256(metadata).
LNURL_SEND_COMMENT = os.environ.get("SATSGATE_LNURL_SEND_COMMENT", "0").strip() == "1"

# Database
DB_PATH = os.environ.get(
    "SATSGATE_DB_PATH",
    os.path.join(os.path.dirname(__file__), "..", "satsgate.sqlite3"),
)

# Rate limit (in-memory, bounded)
RL_ENABLED = os.environ.get("SATSGATE_RL_ENABLED", "1") == "1"
RL_WINDOW_SECONDS = int(os.environ.get("SATSGATE_RL_WINDOW_SECONDS", "60"))
RL_MAX_ANON = int(os.environ.get("SATSGATE_RL_MAX_ANON", "60"))
RL_MAX_AUTH = int(os.environ.get("SATSGATE_RL_MAX_AUTH", "600"))
RL_MAX_CHALLENGE = int(os.environ.get("SATSGATE_RL_MAX_CHALLENGE", "30"))
RL_MAX_TOPUP = int(os.environ.get("SATSGATE_RL_MAX_TOPUP", "10"))
RL_MAX_KEYS = int(os.environ.get("SATSGATE_RL_MAX_KEYS", "10000"))

# Abuse caps for rows created before payment settles.
MAX_PENDING_TOPUPS_PER_IP = int(os.environ.get("SATSGATE_MAX_PENDING_TOPUPS_PER_IP", "20"))
MAX_OPEN_CHALLENGES_PER_CLIENT = int(os.environ.get("SATSGATE_MAX_OPEN_CHALLENGES_PER_CLIENT", "100"))

# Operator/admin token.
# When set, enables /v1/admin/* endpoints (protected via X-Admin-Token header).
ADMIN_TOKEN = os.environ.get("SATSGATE_ADMIN_TOKEN", "").strip()

# Dev mode enables /dev/* plus the demo /v1/tickets and /v1/spend routes.
# Ignored unless SATSGATE_ENV is an explicit local environment.
DEV_MODE = os.environ.get("SATSGATE_DEV_MODE", "0") == "1"

# Proxy peers allowed to supply X-Forwarded-For (comma-separated IPs or CIDRs).
# Empty means ignore forwarded headers and key rate limits by the TCP peer.
TRUSTED_PROXIES = os.environ.get("SATSGATE_TRUSTED_PROXIES", "").strip()

_WEAK_SECRETS = frozenset(
    {
        "",
        "dev-change-me",
        "changeme",
        "change-me",
        "secret",
        "password",
        "test",
        "test-secret",
    }
)
_MIN_SECRET_BYTES = 32
_FORBIDDEN_PROXY_VALUES = frozenset({"*", "0.0.0.0/0", "::/0"})


def is_local_env() -> bool:
    return SATSGATE_ENV in LOCAL_ENVS


def dev_endpoints_enabled() -> bool:
    """Mock-pay and demo routes exist only in an explicit local environment."""
    return is_local_env() and DEV_MODE


def _parse_previous_keys(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("SATSGATE_MACAROON_PREVIOUS_KEYS must be a JSON object of kid to secret") from exc
    if not isinstance(data, dict) or not data:
        raise RuntimeError("SATSGATE_MACAROON_PREVIOUS_KEYS must be a JSON object of kid to secret")
    keys: dict[str, str] = {}
    for kid, secret in data.items():
        if not isinstance(kid, str) or not kid.strip() or not isinstance(secret, str) or not secret:
            raise RuntimeError("SATSGATE_MACAROON_PREVIOUS_KEYS entries must be non-empty strings")
        keys[kid.strip()] = secret
    return keys


def _secret_is_weak(secret: str) -> str | None:
    stripped = secret.strip()
    if stripped.lower() in _WEAK_SECRETS or stripped == "":
        return "unset or a known default"
    if len(secret.encode("utf-8")) < _MIN_SECRET_BYTES:
        return f"shorter than {_MIN_SECRET_BYTES} bytes"
    return None


def signing_keys() -> dict[str, str]:
    """kid -> secret. The current key is always MACAROON_KEY_ID."""
    keys = _parse_previous_keys(_PREVIOUS_KEYS_RAW)
    if not MACAROON_KEY_ID:
        raise RuntimeError("SATSGATE_MACAROON_KEY_ID is empty")
    keys[MACAROON_KEY_ID] = MACAROON_SECRET
    return keys


def validate_startup() -> None:
    """Refuse to boot a production process with a weak signer or dev/mock mode."""
    if any(part.strip() in _FORBIDDEN_PROXY_VALUES for part in TRUSTED_PROXIES.split(",") if part.strip()):
        raise RuntimeError(
            "SATSGATE_TRUSTED_PROXIES must list specific proxy IPs or CIDRs, not '*' or the whole internet"
        )

    keys = signing_keys()
    if is_local_env():
        if not MACAROON_SECRET:
            raise RuntimeError("SATSGATE_MACAROON_SECRET is empty")
        return

    problems: list[str] = []
    for kid, secret in keys.items():
        why = _secret_is_weak(secret)
        if why:
            problems.append(f"signing key {kid!r} is {why}")
    if problems:
        raise RuntimeError(
            "Refusing to start with SATSGATE_ENV=production: "
            + "; ".join(problems)
            + ". Generate one with: openssl rand -hex 32"
        )
    if DEV_MODE:
        raise RuntimeError(
            "Refusing to start with SATSGATE_DEV_MODE=1 when SATSGATE_ENV=production. "
            "Dev and mock-pay endpoints are local-only."
        )
    if WALLET_MODE == "mock":
        raise RuntimeError(
            "Refusing to start with SATSGATE_WALLET_MODE=mock when SATSGATE_ENV=production. "
            "Set SATSGATE_ENV=development for local mock mode."
        )
    if LN_NETWORK not in {"mainnet", "testnet", "signet", "regtest"}:
        raise RuntimeError("SATSGATE_LN_NETWORK must be mainnet, testnet, signet, or regtest")


MACAROON_KEYS = signing_keys()
validate_startup()
