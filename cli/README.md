# satsgate

Charge AI agents in Lightning and USDC on the same 402. 500 free unlocks per UTC month. Cobrale a agentes de IA en Lightning y USDC, en el mismo 402.

`satsgate init` takes a merchant from nothing to a self-hosted paywall config. It opens a free account, saves the account key in `.satsgate/account.env`, asks for a Lightning Address, mints a restricted proxy key, writes `.env` and `satsgate-proxy.yaml`, and checks the paywall with a real 402. That check does not pay, verify, or settle.

It does not ask for a seed, a private key, or a recovery phrase. It does not hold sats or USDC. The account key is not copied into the project `.env`. The project `.env` holds `SATSGATE_API_KEY` (`sgr_`) and `SATSGATE_ORIGIN_SECRET`.

```bash
uvx satsgate init
pip install satsgate
```

From a checkout: `pip install -e sdk/python -e proxy -e cli`.

## Human and agent

Human mode prompts when stdin is a terminal and `--json` is not set. Agent mode (`--json`, or stdin that is not a terminal) never prompts. It prints one JSON object on stdout and notes on stderr. A missing Lightning Address is exit 2 and names `--lightning-address`.

```bash
satsgate init --json --lightning-address merchant@pay.example
satsgate init --json --lightning-address merchant@pay.example --want-usdc
satsgate init --docker --framework fastapi
```

JSON (`schema_version` 1) includes `ok`, `status`, `exit_code`, `api_url`, `account` (`client_id`, `key_preview`, `fingerprint`, `reused`), `payee_lightning_address`, `usdc`, `files`, `route`, `test_402`, `start_command`, `next_steps`, `warnings`, and `error`. A key is shown as `sg_…` or `sgr_…` plus the last four characters, and as a fingerprint. The connect link is not a JSON field.

Exit codes: 0 done, 1 the API or the network failed, 2 usage, 3 a human has to decide, 4 rate-limited. A 429 includes `retry_after_seconds` and is not retried.

## Files

| Path | Mode | Contents |
| --- | --- | --- |
| `.satsgate/` | 0700 | directory |
| `.satsgate/account.env` | 0600 | `SATSGATE_ACCOUNT_KEY` |
| `.satsgate/.gitignore` | | `*` |
| `.env` | 0600 when created here | `SATSGATE_API_KEY`, `SATSGATE_ORIGIN_SECRET` |
| `satsgate-proxy.yaml` | | proxy config, no secrets |
| `.satsgate/connect-link.txt` | 0600 | wallet link in agent mode |

A second run reuses the account and the keys. An existing YAML or snippet is not overwritten (agent exit 3 `file_exists`). A different `SATSGATE_*` value is exit 3 `env_conflict`. A symlink is refused. On Windows the run finishes and warns `permissions_not_restricted`; WSL is the supported way to get owner-only files.

## USDC payments: Base network only

USDC payments use Base only. Ethereum mainnet, Polygon, Solana, Arbitrum, and any other chain are not accepted.

`--want-usdc` mints a one-time connect link when the EVM payee is not verified yet. A terminal prints the link once and can open it. Otherwise it is written to `.satsgate/connect-link.txt` and is not printed. After the payee is verified, a later run sets `x402: true` and `x402_mode: test`. The unpaid 402 then includes a Base Sepolia offer. Paying that offer is a later step for a buyer agent (`satsgate-mcp-pay`), with the key on the buyer's machine. Test mode is free.

To turn USDC test mode off, edit the YAML (`x402: false` on the route, or delete the route's x402 keys) and run `init` again, or delete the YAML and re-run (it is regenerated; keys are reused).

Lightning has no test network. A paid Lightning request moves real sats to the merchant's own address.

## Start

```bash
uvx --env-file .env satsgate-proxy --config satsgate-proxy.yaml
```

`satsgate` 0.1.1. `--docker` writes `docker-compose.satsgate.yml` and prints `docker compose -f docker-compose.satsgate.yml up`. The compose file uses the public image `ghcr.io/mike-io-hash/satsgate-proxy:0.14.1`. To build that image yourself, use `proxy/Dockerfile` from the repo. The generated service listens on `0.0.0.0`; the YAML written for `uvx` stays on `127.0.0.1`. From a checkout: `pip install -e sdk/python -e proxy -e cli`.

`--framework fastapi`, `express`, or `nginx` copies the existing origin check. A client that can reach the origin directly must fail closed. The Caddy file in the package is a note, not an HMAC check.
