# Self-hosting

Run the Satsgate core yourself. A seller using the hosted API at `https://api.satsgate.org` can skip this and start with `uvx satsgate init`.

USDC payments: [USDC payments: Base network only](../README.md#usdc-payments-base-network-only).

## Quickstart (local)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# .env.example is production-shaped and will refuse to boot until you set a
# real secret. For local mock mode:
export SATSGATE_ENV=development
export SATSGATE_DEV_MODE=1
export SATSGATE_WALLET_MODE=mock
export SATSGATE_MACAROON_SECRET=local-dev-only

uvicorn app.main:app --reload --port 8000
```

`/dev/mock/pay/{payment_hash}` is available only in that local configuration.

## Docker (recommended for deployment)

This repo includes a minimal Docker setup with **Caddy** (TLS) and a persistent SQLite volume.

1) Copy env file:

```bash
cp .env.example .env
```

2) Edit `.env` and set at least:

- `SATSGATE_HOSTNAME=api.yourdomain.com`
- `SATSGATE_ENV=production`
- `SATSGATE_MACAROON_SECRET=$(openssl rand -hex 32)`
- `SATSGATE_WALLET_MODE=lnaddr`
- `SATSGATE_LIGHTNING_ADDRESS=user@domain`
- `SATSGATE_DEV_MODE=0`

The stack pins Caddy at `172.28.0.2` and the app at `172.28.0.3`, and only trusts forwarded headers from Caddy. Do not set `SATSGATE_TRUSTED_PROXIES=*` or uvicorn `--forwarded-allow-ips *`.

3) Start:

```bash
docker compose up -d --build
```

Notes:
- Your DNS must point `SATSGATE_HOSTNAME` to your server IP.
- Ports **80** and **443** must be open for Caddy/Let’s Encrypt.

## Operator notes

Live mode is on by default on api.satsgate.org. A self-hosted core needs `SATSGATE_X402_CDP=1` and both CDP credentials. Leave `SATSGATE_X402_NETWORK` at `eip155:84532`. That variable is the public facilitator network. Setting it to `eip155:8453` still refuses to boot. Mainnet USDC is the CDP switch.

```bash
SATSGATE_X402_CDP=1
SATSGATE_X402_CDP_KEY_ID=organizations/.../apiKeys/...
SATSGATE_X402_CDP_KEY_SECRET=...   # CDP Secret API key, the base64 value shown once
```

A missing or unusable credential logs that mainnet USDC is disabled and does not print the value. Base Sepolia and Lightning still start.

Rollback on a self-hosted core: set `SATSGATE_X402_CDP=0` and restart core. Live sites stop offering USDC. Test mode and Lightning keep working.

## From a checkout

```bash
pip install -e sdk/python -e proxy -e cli
pip install -r mcp/requirements.txt
PYTHONPATH=mcp/src python -m satsgate_mcp.manual https://your-proxy.example/blog/post
docker compose -f proxy/docker-compose.yml up --build
```

## Backups

Copy `satsgate.sqlite3` before you restart the core. Deploy notes for the current core line are `docs/deploy-core-0.20.1.md`, `docs/deploy-core-0.20.2-terms-sdk.md`, `docs/deploy-core-0.20.3.md`, `docs/deploy-core-0.20.4.md`, `docs/deploy-terms-2026-11-27.md`, and `docs/deploy-core-0.20.5.md`.

## Environment variables

The tables below are the same settings the API reference describes.

| Network | Network id | Circle USDC contract | Status |
| --- | --- | --- | --- |
| Base Sepolia (testnet) | `eip155:84532` | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | Testing. A site in test mode offers only this USDC, through `https://x402.org/facilitator`. It is not a network for real buyers. |
| Base | `eip155:8453` | [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) | Live mode (on by default on api.satsgate.org; a self-hosted core needs `SATSGATE_X402_CDP=1` and CDP credentials). A site in live mode offers only this USDC, through the Coinbase CDP facilitator. |

| Limit | Default | Env |
| --- | --- | --- |
| New challenges per buyer per `SATSGATE_RL_WINDOW_SECONDS` | 10 | `SATSGATE_BUYER_CHALLENGE_MAX` (`0` disables) |
| Unpaid challenges still inside the offer window, per rail | 5 | `SATSGATE_BUYER_MAX_OPEN_CHALLENGES` (`0` disables) |
| Bucket | the whole client | `SATSGATE_BUYER_LIMIT_SCOPE=client`, or `key` for a separate budget per restricted key |
| Reuse an identical pending challenge | 30 seconds | `SATSGATE_CHALLENGE_REUSE_SECONDS` (`0` disables) |

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_SITE_SECRET_KEY` | unset | 64 hex characters. Required to create or rotate a site secret. Unset does not stop the process. |
| `SATSGATE_SITES_AUTO_APPROVE` | off | `1` approves a new site only after a successful origin check, acceptance of the current `SATSGATE_TERMS_VERSION`, and an account that is not suspended. Empty terms with this switch on refuses to boot. The default is off. |
| `SATSGATE_RECEIPT_SECONDS` | 86400 | Receipt lifetime when the route sets no `access_seconds`. Clamped to 60–86400 and to the paywall access cap. |
| `SATSGATE_TERMS_VERSION` | empty | Effective date of the terms you serve. |
| `SATSGATE_TERMS_URL` | empty | https page linked from the API and the gate 402 when set. Empty means the key is present and null. |
| `SATSGATE_ABUSE_CONTACT` | empty | Bare email. Shown on `GET /` of the gate when set. |
| `SATSGATE_GEOBLOCK_COUNTRIES` | empty | ISO codes refused on signups and quotes. Empty skips the lookup. |
| `SATSGATE_GEOIP_DB` | `/data/geoip/dbip-country-lite.mmdb` | DB-IP Country Lite. Required only when the country list is set. |
| `SATSGATE_OFAC_EVM_FILE` | `/data/ofac/ofac_evm.txt` | Local EVM addresses from the OFAC SDN list. Missing file fails open. |
| `SATSGATE_SITES_MAX_PER_ACCOUNT` | 3 | Sites per account, including disabled ones. |
| `SATSGATE_SITES_MAX_ROUTES` | 20 | Routes per site. |
| `SATSGATE_GATE_PUBLIC_BASE` | `https://gate.satsgate.org` | https origin used in public `url` values. No path. |
| `SATSGATE_GATE_TOKEN` | unset | Shared with the gate container. Unset means `/internal/gate/*` is 404. |
| `SATSGATE_GATE_PEERS` | empty (Compose sets `172.28.0.4`) | When set, only that TCP peer may present the gate token. |

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_X402_FACILITATOR_URL` | `https://x402.org/facilitator` | https facilitator base. No userinfo, query, or fragment. Core calls `POST /verify` and `POST /settle`. |
| `SATSGATE_X402_NETWORK` | `eip155:84532` | Base Sepolia only. Any other value, including Base mainnet `eip155:8453`, refuses to boot. |
| `SATSGATE_X402_OFFER_SECONDS` | 60 | Offer lifetime. Config accepts 15 to 300. Gate routes and USDC top-up clamp it to 60–300. A Lightning invoice uses its own expiry. |
| `SATSGATE_X402_PAYEE_CHALLENGE_SECONDS` | 1800 | Payee signature window. Values outside 300–3600 are clamped. |
| `SATSGATE_PAYEE_CONNECT_SECONDS` | 3600 | Connect-link lifetime. Values outside 600–86400 are clamped. |
| `SATSGATE_CONNECT_PUBLIC_BASE` | `https://satsgate.org/connect` | https URL with the page path. The token is appended as a fragment. |

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_RATES_ENABLED` | on | `0` skips the background refresh. |
| `SATSGATE_RATES_REFRESH_SECONDS` | 60 | How often the quote is refreshed (15 to 600). |
| `SATSGATE_RATES_STALE_SECONDS` | 180 | After this, the internal backup is not used to price a challenge. The primary read stays fresh for 3,600 seconds. |
| `SATSGATE_RATES_SOURCE_TIMEOUT_SECONDS` | 2 | Timeout for one source (0.5 to 5). |
| `SATSGATE_RATES_OUTLIER_BPS` | 200 | Drop a backup sample this far from the others. 200 is 2%. |
| `SATSGATE_BASE_RPC_URL` | `https://mainnet.base.org` | Primary Base RPC for the on-chain quote and for smart-wallet checks. |
| `SATSGATE_BASE_RPC_FALLBACK_URL` | empty | Optional second Base RPC. Same https rules. Used only when the primary does not answer. |
| `SATSGATE_ACCOUNTING_RATE_CACHE_S` | 60 | How long a quote is reused. |
| `SATSGATE_ACCOUNTING_RATE_STALE_S` | 3600 | How old the primary read may be. |
| `SATSGATE_ACCOUNTING_RATE_TIMEOUT_S` | 3 | Timeout for one primary read. |

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_TREASURY_EVM_ADDRESS` | unset | Satsgate's own Base payTo for USDC top-ups. Unset or invalid turns this rail off. Not used for merchant route payments. |
