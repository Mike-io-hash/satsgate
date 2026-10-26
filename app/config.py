import json
import logging
import os
import re
from urllib.parse import urlsplit

from dotenv import load_dotenv

# Load env vars from .env if present. Existing process env wins.
load_dotenv()

APP_VERSION = "0.15.1"

# production is the safe default. Local mock/dev only runs when this is explicit.
SATSGATE_ENV = os.environ.get("SATSGATE_ENV", "production").strip().lower() or "production"
LOCAL_ENVS = frozenset({"development", "dev", "local", "test"})

# L402 token signing. No insecure default in production (see validate_startup).
MACAROON_KEY_ID = os.environ.get("SATSGATE_MACAROON_KEY_ID", "1").strip() or "1"
MACAROON_SECRET = os.environ.get("SATSGATE_MACAROON_SECRET", "")
_PREVIOUS_KEYS_RAW = os.environ.get("SATSGATE_MACAROON_PREVIOUS_KEYS", "").strip()

# Demo endpoint pricing (/v1/tickets, dev-only)
PRICE_SATS = int(os.environ.get("SATSGATE_PRICE_SATS", "10"))

# Minimum invoice lifetime for a paywall challenge, and the dev-ticket macaroon TTL.
# Paywall claim windows follow the invoice expiry (see the paywall settings below).
# Top-up macaroons follow the invoice expiry with their own grace and cap.
TOKEN_TTL_SECONDS = int(os.environ.get("SATSGATE_TOKEN_TTL_SECONDS", "600"))

# A top-up macaroon stays valid until the stored BOLT11 expiry, plus this grace
# so a buyer can finish polling after paying near the end of the invoice, and
# never longer than the cap. The cap is the lifetime of a bearer that can mint
# an API key. Both are optional; unset means these defaults.
_DEFAULT_TOPUP_TOKEN_TTL_CAP_SECONDS = 48 * 60 * 60
_DEFAULT_TOPUP_CLAIM_GRACE_SECONDS = 60 * 60
_MAX_TOPUP_TOKEN_TTL_CAP_SECONDS = 7 * 24 * 60 * 60
_MAX_TOPUP_CLAIM_GRACE_SECONDS = 24 * 60 * 60


def _optional_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


TOPUP_TOKEN_TTL_CAP_SECONDS = _optional_int(
    "SATSGATE_TOPUP_TOKEN_TTL_CAP_SECONDS",
    _DEFAULT_TOPUP_TOKEN_TTL_CAP_SECONDS,
    minimum=60,
    maximum=_MAX_TOPUP_TOKEN_TTL_CAP_SECONDS,
)
TOPUP_CLAIM_GRACE_SECONDS = _optional_int(
    "SATSGATE_TOPUP_CLAIM_GRACE_SECONDS",
    _DEFAULT_TOPUP_CLAIM_GRACE_SECONDS,
    minimum=0,
    maximum=_MAX_TOPUP_CLAIM_GRACE_SECONDS,
)
if TOPUP_CLAIM_GRACE_SECONDS > TOPUP_TOKEN_TTL_CAP_SECONDS:
    raise RuntimeError("SATSGATE_TOPUP_CLAIM_GRACE_SECONDS cannot exceed SATSGATE_TOPUP_TOKEN_TTL_CAP_SECONDS")

# Paywall macaroons stay valid until the stored invoice expiry, plus this grace
# so a buyer can finish polling after paying near the end of the invoice, and
# never longer than the cap. The cap bounds a bearer that can spend the
# merchant's credits once payment is proven. ttl_seconds on the challenge is
# only the minimum invoice lifetime, not this window.
PAYWALL_TOKEN_TTL_CAP_SECONDS = _optional_int(
    "SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS",
    _DEFAULT_TOPUP_TOKEN_TTL_CAP_SECONDS,
    minimum=60,
    maximum=_MAX_TOPUP_TOKEN_TTL_CAP_SECONDS,
)
PAYWALL_CLAIM_GRACE_SECONDS = _optional_int(
    "SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS",
    _DEFAULT_TOPUP_CLAIM_GRACE_SECONDS,
    minimum=0,
    maximum=_MAX_TOPUP_CLAIM_GRACE_SECONDS,
)
if PAYWALL_CLAIM_GRACE_SECONDS > PAYWALL_TOKEN_TTL_CAP_SECONDS:
    raise RuntimeError("SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS cannot exceed SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS")

# Longest access window a challenge may grant, measured from settlement.
# Also the longest a max_uses bundle is honored when access_seconds is omitted.
# Optional. Lower it to shorten passes. It cannot be raised past 7 days.
_DEFAULT_PAYWALL_ACCESS_CAP_SECONDS = 7 * 24 * 60 * 60
_MAX_PAYWALL_ACCESS_CAP_SECONDS = 7 * 24 * 60 * 60
PAYWALL_ACCESS_CAP_SECONDS = _optional_int(
    "SATSGATE_PAYWALL_ACCESS_CAP_SECONDS",
    _DEFAULT_PAYWALL_ACCESS_CAP_SECONDS,
    minimum=60,
    maximum=_MAX_PAYWALL_ACCESS_CAP_SECONDS,
)
MAX_PAYWALL_USES = 100_000

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

# Per-buyer challenge limits. They apply only when a trusted proxy passes
# X-Satsgate-Buyer-Ip. 0 disables that one limit. The rate uses RL_WINDOW_SECONDS.
# Scope "client" shares a buyer's budget across the account's keys. "key"
# gives each restricted key (and the account key) its own budget.
BUYER_CHALLENGE_MAX = _optional_int("SATSGATE_BUYER_CHALLENGE_MAX", 10, minimum=0, maximum=100_000)
BUYER_MAX_OPEN_CHALLENGES = _optional_int(
    "SATSGATE_BUYER_MAX_OPEN_CHALLENGES",
    5,
    minimum=0,
    maximum=100_000,
)
CHALLENGE_REUSE_SECONDS = _optional_int("SATSGATE_CHALLENGE_REUSE_SECONDS", 30, minimum=0, maximum=600)
_BUYER_LIMIT_SCOPES = frozenset({"client", "key"})
BUYER_LIMIT_SCOPE = os.environ.get("SATSGATE_BUYER_LIMIT_SCOPE", "client").strip().lower() or "client"
if BUYER_LIMIT_SCOPE not in _BUYER_LIMIT_SCOPES:
    raise RuntimeError("SATSGATE_BUYER_LIMIT_SCOPE must be 'client' or 'key'")

# Operator/admin token.
# When set, enables /v1/admin/* endpoints (protected via X-Admin-Token header).
ADMIN_TOKEN = os.environ.get("SATSGATE_ADMIN_TOKEN", "").strip()

# Hosted-proxy sites registry. Unset limits keep the closed-beta defaults.
# The secret key is optional at boot so a restart without it still serves
# current clients. Creating or rotating a site secret requires it.
SITES_MAX_PER_ACCOUNT = _optional_int("SATSGATE_SITES_MAX_PER_ACCOUNT", 3, minimum=1, maximum=100)
SITES_MAX_ROUTES = _optional_int("SATSGATE_SITES_MAX_ROUTES", 20, minimum=1, maximum=200)
SITES_AUTO_APPROVE = os.environ.get("SATSGATE_SITES_AUTO_APPROVE", "0").strip().lower() in {"1", "true", "yes", "on"}
_SITE_SECRET_RAW = os.environ.get("SATSGATE_SITE_SECRET_KEY", "").strip()


def _gate_public_base() -> str:
    raw = os.environ.get("SATSGATE_GATE_PUBLIC_BASE", "https://gate.satsgate.org").strip().rstrip("/")
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RuntimeError(
            "SATSGATE_GATE_PUBLIC_BASE must be an https origin without userinfo, a path, a query, or a fragment"
        )
    return raw


GATE_PUBLIC_BASE = _gate_public_base()

# Shared secret for the hosted gate process. Unset means the internal routes
# answer 404, so a deploy that has not turned the gate on does not expose them.
# SATSGATE_GATE_PEERS, when set, also requires the TCP peer to be that address.
# Empty means the token alone is enough (tests, and a core that is not on the
# compose network). Compose pins this to the gate container.
GATE_TOKEN = os.environ.get("SATSGATE_GATE_TOKEN", "").strip()
GATE_PEERS = os.environ.get("SATSGATE_GATE_PEERS", "").strip()

# x402. Core calls a third-party facilitator. It does not hold a buyer or
# merchant key and it does not sign or submit transactions.
# SATSGATE_X402_NETWORK stays the public-facilitator network (Base Sepolia).
# Base mainnet is SATSGATE_X402_CDP, not this variable.
X402_TESTNET_NETWORK = "eip155:84532"
X402_MAINNET_NETWORK = "eip155:8453"
X402_USDC_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
X402_USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
# Hardcoded so an operator cannot point mainnet USDC at an arbitrary host.
X402_CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"
X402_MAX_USD_ATOMIC = 100_000_000
X402_PAYEE_CHALLENGE_SECONDS = 600
X402_SIGNATURE_MAX_BYTES = 8192
X402_FACILITATOR_TIMEOUT_SECONDS = 10.0
X402_OFFER_SECONDS = _optional_int("SATSGATE_X402_OFFER_SECONDS", 60, minimum=15, maximum=300)


def _x402_network() -> str:
    raw = os.environ.get("SATSGATE_X402_NETWORK", X402_TESTNET_NETWORK).strip()
    if raw != X402_TESTNET_NETWORK:
        raise RuntimeError(
            "SATSGATE_X402_NETWORK must be eip155:84532. "
            "Base mainnet is SATSGATE_X402_CDP, not this variable. "
            "Satsgate does not run a facilitator."
        )
    return raw


def _x402_facilitator_url() -> str:
    raw = os.environ.get("SATSGATE_X402_FACILITATOR_URL", "https://x402.org/facilitator").strip()
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "SATSGATE_X402_FACILITATOR_URL must be an https URL without userinfo, a query, or a fragment"
        )
    return raw.rstrip("/")


X402_NETWORK = _x402_network()
X402_FACILITATOR_URL = _x402_facilitator_url()
X402_USDC = X402_USDC_SEPOLIA


def _cdp_requested() -> bool:
    return os.environ.get("SATSGATE_X402_CDP", "").strip() == "1"


def _cdp_key_id_ok() -> bool:
    raw = os.environ.get("SATSGATE_X402_CDP_KEY_ID", "")
    if raw != raw.strip() or not raw or any(ch.isspace() for ch in raw) or len(raw) > 256:
        return False
    return True


def _mainnet_enabled() -> bool:
    """True only when the switch is on and both CDP credentials are usable.

    A bad or missing credential does not refuse boot. Sepolia and Lightning
    still start. The secret is not logged.
    """
    if not _cdp_requested():
        return False
    secret = os.environ.get("SATSGATE_X402_CDP_KEY_SECRET", "").strip()
    from .cdp_auth import secret_is_usable

    if not _cdp_key_id_ok() or not secret_is_usable(secret):
        logging.getLogger("satsgate.x402").warning(
            "USDC mainnet disabled: SATSGATE_X402_CDP is set and a credential is missing or not a CDP Ed25519 secret"
        )
        return False
    return True


X402_CDP_REQUESTED = _cdp_requested()
X402_MAINNET_ENABLED = _mainnet_enabled()

from .cdp_auth import install_redactor  # noqa: E402

install_redactor()

# Satsgate's own USDC address for credit packs only. Unset or invalid disables
# that rail. Buyer payments for a merchant route still go to the merchant.
_TREASURY_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _treasury_address() -> str | None:
    raw = os.environ.get("SATSGATE_TREASURY_EVM_ADDRESS", "").strip()
    if not raw or not _TREASURY_ADDR.fullmatch(raw):
        return None
    try:
        from eth_utils import to_checksum_address

        checksum = to_checksum_address(raw)
    except Exception:  # noqa: BLE001
        return None
    if int(checksum, 16) == 0:
        return None
    return checksum


TREASURY_EVM_ADDRESS = _treasury_address()
if os.environ.get("SATSGATE_TREASURY_EVM_ADDRESS", "").strip() and TREASURY_EVM_ADDRESS is None:
    logging.getLogger("satsgate.x402").warning(
        "USDC top-up disabled: SATSGATE_TREASURY_EVM_ADDRESS is not a valid address"
    )

# BTC/USD quotes. The median is not a conversion. Defaults are safe to leave unset.
# SATSGATE_RATES_ENABLED=0 skips the background refresh (tests). The last good
# median is stale after 3 minutes and is then not used to price a challenge.
RATES_ENABLED = os.environ.get("SATSGATE_RATES_ENABLED", "1") == "1"
RATES_REFRESH_SECONDS = _optional_int("SATSGATE_RATES_REFRESH_SECONDS", 60, minimum=15, maximum=600)
RATES_STALE_SECONDS = _optional_int("SATSGATE_RATES_STALE_SECONDS", 180, minimum=60, maximum=900)
RATES_OUTLIER_BPS = _optional_int("SATSGATE_RATES_OUTLIER_BPS", 200, minimum=50, maximum=1000)


def _rates_timeout() -> float:
    raw = os.environ.get("SATSGATE_RATES_SOURCE_TIMEOUT_SECONDS", "2").strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError("SATSGATE_RATES_SOURCE_TIMEOUT_SECONDS must be a number") from exc
    if value < 0.5 or value > 5:
        raise RuntimeError("SATSGATE_RATES_SOURCE_TIMEOUT_SECONDS must be between 0.5 and 5")
    return value


RATES_SOURCE_TIMEOUT_SECONDS = _rates_timeout()


def site_secret_key() -> bytes | None:
    """32-byte key for origin-secret ciphertext. None when the env var is unset."""
    if not _SITE_SECRET_RAW:
        return None
    if len(_SITE_SECRET_RAW) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in _SITE_SECRET_RAW):
        raise RuntimeError("SATSGATE_SITE_SECRET_KEY must be 64 hex characters (openssl rand -hex 32)")
    return bytes.fromhex(_SITE_SECRET_RAW)

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
    if any(part.strip() in _FORBIDDEN_PROXY_VALUES for part in GATE_PEERS.split(",") if part.strip()):
        raise RuntimeError("SATSGATE_GATE_PEERS must list specific proxy IPs or CIDRs, not '*' or the whole internet")
    # A malformed key fails boot. An unset key does not: current clients keep working.
    site_secret_key()
    if GATE_TOKEN and not is_local_env():
        why = _secret_is_weak(GATE_TOKEN)
        if why:
            raise RuntimeError(
                f"Refusing to start: SATSGATE_GATE_TOKEN is {why}. Generate one with: openssl rand -hex 32"
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
