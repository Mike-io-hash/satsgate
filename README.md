# Satsgate

[![CI](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml/badge.svg)](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml)

**Charge AI agents in Lightning and USDC on the same 402. Payments go straight to your wallet. 500 free unlocks a month.**

Satsgate is a paywall for an HTTP API or a remote MCP server. The buyer pays the seller's wallet directly, in Lightning or in USDC on Base, on the same 402. Satsgate keeps a prepaid service balance for the seller and debits a fee after the free quota.

Fastest path: `satsgate init`

```bash
uvx satsgate init
```

## Who it is for

- You run an API or a remote MCP server and want agents to pay per request.
- You are an agent setting this up for your owner. Use `satsgate init --json`. It does not prompt.
- You are a buyer agent. Use `satsgate-mcp` to read a 402, pay, and fetch.

## Why Satsgate

- No node to run. Payouts go to a Lightning Address. LUD-21 lets the buyer pay from any wallet.
- No custody. The buyer pays the seller's wallet. Satsgate does not hold, receive, forward, or refund that payment.
- Lightning and USDC on the same 402, with L402 and x402 v2. Works with Lightning Labs `lnget` and Alby `fetch402`. The client table is in [docs/api.md](docs/api.md).
- Plug in the proxy, or call the API. The core, the proxy, the SDK, and the buyer MCP are open source.
- No KYC. Payments are not private: Lightning and USDC payments are visible on the networks that move them.

## Quickstart

Published packages only. `pip install satsgate` is an alternative to `uvx`, not a second step.

```bash
uvx satsgate init
```

```bash
pip install satsgate
satsgate init
```

An agent passes `--json` and `--lightning-address merchant@pay.example`.

Start the proxy:

```bash
uvx --env-file .env satsgate-proxy --config satsgate-proxy.yaml
```

Docker, after `init` writes the compose file:

```bash
satsgate init --docker
docker compose -f docker-compose.satsgate.yml up
```

The image is `ghcr.io/mike-io-hash/satsgate-proxy:0.14.x`. The compose file pins the proxy version you installed.

Copy an origin HMAC check with `--framework fastapi`, `express`, or `nginx`. A client that can reach the origin directly must fail closed.

Try an unpaid request. The proxy answers 402. Paying that invoice sends real sats to the Lightning Address you set.

Optional USDC test mode: `satsgate init --want-usdc`, then open the connect link (`https://satsgate.org/connect`). Test mode offers USDC on Base Sepolia.

`init` writes `satsgate-proxy.yaml` (secrets stay in `.env`):

```yaml
core:
  base_url: "https://api.satsgate.org"
  api_key_env: SATSGATE_API_KEY
upstream:
  base_url: "http://127.0.0.1:3000"
origin:
  secret_env: SATSGATE_ORIGIN_SECRET
server:
  host: 127.0.0.1
  port: 8080
routes:
  - name: first
    methods: [GET]
    path: "/paid/**"
    price_sats: 10
    access: per_request
    scope: route
```

## How it works

```
buyer
  |  402  (L402, and x402 when USDC is on)
  v
self-hosted proxy    hosted gate    your own call to the API
  |
  v
seller Lightning Address, or the seller's address on Base
```

Satsgate debits the seller's prepaid service balance after the free quota: with the proxy, only after the origin returns 2xx; on the hosted gate, when the receipt is issued.

Three ways to integrate:

1. Self-hosted proxy in front of an HTTP API you already run.
2. The Python SDK, if you mint challenges in your own code.
3. The hosted gate, which sells a signed receipt for an approved site.

### Hosted gate (x402)

The hosted gate at `https://gate.satsgate.org` is in closed beta. Sites are approved manually. The buyer pays the seller's wallet, then repeats the request at the seller with `Satsgate-Receipt`. See [docs/api.md](docs/api.md).

## Pricing

The buyer pays the seller's wallet directly. The seller loads a prepaid service balance (Lightning, or USDC on Base converted at the BTC/USD rate at load time) kept in millisatoshis. Each paid unlock debits the model B service fee. The balance is not money, not transferable, not redeemable, and it does not expire.

- Test mode is free.
- The first 500 paid unlocks per UTC month are free, shared by accounts that pay out to the same address.
- After that, 2 sats per unlock, capped at 10% of the item price.
- USDC items have a floor of US$0.001. That floor covers the facilitator's per-transaction cost only.
- Top up from 1,000 sats or US$1.
- Loading the balance adds 10% from 100,000 sats, and 20% from 1,000,000 sats.
- If the free quota and the balance are both empty, buyers get `502 paywall_unavailable`.

## USDC payments: Base network only

USDC payments use Base only. Ethereum mainnet, Polygon, Solana, Arbitrum, and any other chain are not accepted.

| Network | Network id | Circle USDC contract | Status |
| --- | --- | --- | --- |
| Base Sepolia (testnet) | `eip155:84532` | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | Testing. Not a network for real buyers. |
| Base | `eip155:8453` | [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) | Live mode (on by default on api.satsgate.org; a self-hosted core needs `SATSGATE_X402_CDP=1` and CDP credentials, see [self-hosting](docs/self-hosting.md)). |

`payTo` must be an address you control on Base. The USDC moves from the buyer to that address. Satsgate does not hold a buyer wallet and does not run its own facilitator.

## Buyer side: `satsgate-mcp`

```bash
pip install satsgate-mcp
```

or `pip install "satsgate[mcp]"`.

```json
{
  "mcpServers": {
    "satsgate": {
      "command": "satsgate-mcp",
      "env": {
        "SATSGATE_MCP_MAX_PAYMENT_SATS": "100",
        "SATSGATE_MCP_DAILY_MAX_SATS": "500"
      }
    }
  }
}
```

Paying also needs `SATSGATE_MCP_NWC_URI` or the USD caps in that env block. Wallet setup is in [mcp/README.md](mcp/README.md).

`satsgate-mcp --help` lists the environment variables it reads and exits. `--version` prints the package version. With no arguments it speaks MCP on stdio.

## Packages

| Package | Where |
| --- | --- |
| `satsgate` | [PyPI](https://pypi.org/project/satsgate/) 0.1.x |
| `satsgate-sdk` | [PyPI](https://pypi.org/project/satsgate-sdk/) 0.10.x |
| `satsgate-proxy` | [PyPI](https://pypi.org/project/satsgate-proxy/) 0.14.x and [GHCR](https://github.com/Mike-io-hash/satsgate/pkgs/container/satsgate-proxy) |
| `satsgate-mcp` | [PyPI](https://pypi.org/project/satsgate-mcp/) 0.13.x |

OpenAPI: [https://api.satsgate.org/openapi.json](https://api.satsgate.org/openapi.json). Works with core 0.20.3 or later.

## Status

Beta. Tested end-to-end on mainnet with small amounts.

Open to everyone: accounts, the self-hosted proxy, the SDK, and the buyer MCP.

The hosted gate is closed beta. Sites are approved manually.

Not built yet:

- Per-tool pricing for remote MCP servers. Today a price applies to a route and method, so every tool call on `/mcp` costs the same.
- A TypeScript SDK.

## Security and trust

The account key (`sg_`) is shown once. Rotate it yourself. A restricted key (`sgr_`) cannot change the payout address. An alert email and a signed webhook report payout changes. The proxy debits the unlock fee only after the origin returns 2xx.

Customer quickstart, including key rotation: [CUSTOMER_QUICKSTART.md](CUSTOMER_QUICKSTART.md#rotate-the-account-key).

Report a security issue as described in [SECURITY.md](SECURITY.md).

## Documentation

- [docs/api.md](docs/api.md)
- [docs/self-hosting.md](docs/self-hosting.md)
- [docs/x402-design.md](docs/x402-design.md)
- [CUSTOMER_QUICKSTART.md](CUSTOMER_QUICKSTART.md)
- [cli/README.md](cli/README.md)
- [sdk/python/README.md](sdk/python/README.md)
- [proxy/README.md](proxy/README.md)
- [mcp/README.md](mcp/README.md)
- [Terms](https://satsgate.org/terms)
- [CHANGELOG.md](CHANGELOG.md)
- [BETA.md](BETA.md)
- [STATUS.md](STATUS.md)
- Health: https://api.satsgate.org/health
- Manifest: https://api.satsgate.org/.well-known/satsgate.json

## Contributing and support

Support: [SUPPORT.md](SUPPORT.md). Development setup: [CONTRIBUTING.md](CONTRIBUTING.md). Source: [https://github.com/Mike-io-hash/satsgate](https://github.com/Mike-io-hash/satsgate).

## License

Apache-2.0. See [LICENSE](LICENSE).

