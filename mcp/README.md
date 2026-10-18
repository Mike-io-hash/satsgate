# satsgate-mcp

A buyer-side MCP server. An agent (Claude Desktop, Cursor, or any stdio MCP client) can see the price of a Satsgate-paywalled URL, pay it, and read the response.

This package is version **0.9.1**. It talks to whatever URL returned the 402. It does not change satsgate core. Core stays **0.7.0**. The proxy stays **0.8.0**.

A hosted directory of sites is not part of this release. `list_sites` reads a JSON file or URL only when you set `SATSGATE_MCP_REGISTRY`.

## Run it

```bash
pip install -r mcp/requirements.txt
export SATSGATE_MCP_DATA_DIR="$HOME/.local/share/satsgate-mcp"
export SATSGATE_MCP_MAX_PAYMENT_SATS=100
export SATSGATE_MCP_DAILY_MAX_SATS=500
PYTHONPATH=mcp/src python -m satsgate_mcp
```

`python -m satsgate_mcp` speaks MCP over stdio. Logs go to stderr. After `pip install -e mcp` the console script is `satsgate-mcp`.

Claude Desktop or Cursor config:

```json
{
  "mcpServers": {
    "satsgate": {
      "command": "python",
      "args": ["-m", "satsgate_mcp"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/satsgate/mcp/src",
        "SATSGATE_MCP_DATA_DIR": "/absolute/path/to/satsgate-mcp-data",
        "SATSGATE_MCP_MAX_PAYMENT_SATS": "100",
        "SATSGATE_MCP_DAILY_MAX_SATS": "500"
      }
    }
  }
}
```

Put `SATSGATE_MCP_NWC_URI` in that env block when you want the agent to pay. Do not paste the URI into the chat. The tools have no argument for it, and it is not logged.

## Tools

| Tool | What it does |
| --- | --- |
| `discover` | GET (or POST) the URL with no payment. Reads `WWW-Authenticate: L402 macaroon="...", invoice="..."` and the JSON body: `amount_sats`, `max_uses`, `access_seconds`, `invoice_expires_at`. |
| `quote` | Same request, plus a short sentence. |
| `pay_and_fetch` | `mode=human` (default) returns the invoice, a text QR, and a PNG. `mode=nwc` pays from the environment wallet if the caps allow it, then fetches. |
| `check_payment` | One poll of a human payment. `payment_pending` means call it again after `retry_after_seconds`. On settlement it fetches the URL with `Authorization: L402 <macaroon>` and no preimage. |
| `credits_balance` | `GET /v1/balance` with the optional restricted key. Core answers 403 `insufficient_scope` for an `sgr_` key. Nothing is written. |
| `challenge_status` | `GET /v1/paywall/status/{payment_hash}?consume=false`. The macaroon is the one stored locally. It is not a tool argument. |
| `list_sites` | Reads `SATSGATE_MCP_REGISTRY` when set. |

A token that still has uses, or whose pass has not ended, is sent again and is not paid again. The macaroon stays in the local sqlite file. It is not returned to the model.

If the server answers a stored token with a fresh 402 `token_used_up` or `token_expired`, the tool returns the new quote and does not pay. Call `pay_and_fetch` again to pay that invoice. Set `SATSGATE_MCP_AUTO_PAY=1` to pay that replacement inside the same call, and only when it is inside both caps.

`discover` followed within 60 seconds by `pay_and_fetch` for the same URL reuses that invoice instead of minting another one.

## Human pay, no preimage

1. `pay_and_fetch` with `mode=human`.
2. Pay the BOLT11 invoice in any wallet. You do not need the preimage.
3. `check_payment` with the `payment_hash`.

When `SATSGATE_MCP_API_KEY` is set and the challenge names a resource, `check_payment` first calls core `GET /v1/paywall/status/{payment_hash}` with the macaroon and `consume=false`. That is the LUD-21 poll. Unpaid is `status=pending`. Settled, it retries the original URL with the macaroon. The proxy then consumes one use and forwards.

Without a key, `check_payment` retries the URL directly. The proxy does the core poll. Pending is HTTP 402 `payment_pending` and does not mint a second invoice.

If the payee wallet does not advertise LUD-21 (Wallet of Satoshi), core returns `preimage_required`. Human poll cannot finish. Use `mode=nwc`, or a wallet that shows the preimage.

## NWC

`SATSGATE_MCP_NWC_URI` is `nostr+walletconnect://...?relay=...&secret=...`. Both caps must be set or every NWC payment is refused. `0` refuses every positive amount. The spend ledger is `satsgate-mcp.sqlite` in the data dir (mode 0600). A payment is recorded when the wallet returns a preimage, including when the origin then fails. Sats are not refunded.

## Environment

| Variable | Meaning |
| --- | --- |
| `SATSGATE_MCP_NWC_URI` | Wallet connection. Never a tool argument. Unset means NWC is off. |
| `SATSGATE_MCP_MAX_PAYMENT_SATS` | Most sats one invoice may cost. Required for NWC. |
| `SATSGATE_MCP_DAILY_MAX_SATS` | Most sats in any rolling 24 hours. Required for NWC. |
| `SATSGATE_MCP_AUTO_PAY` | `1` pays a `token_used_up` / `token_expired` replacement inside the same call, if the caps allow it. Default off. |
| `SATSGATE_MCP_DATA_DIR` | sqlite directory. Default `~/.local/share/satsgate-mcp`. |
| `SATSGATE_MCP_CORE_URL` | Core base URL. Default `https://api.satsgate.org`. |
| `SATSGATE_MCP_API_KEY` | Optional `sgr_` key for the two read-only tools. An account `sg_` key is ignored. |
| `SATSGATE_MCP_URL_ALLOWLIST` | Comma-separated hosts. `*.example.com` allows subdomains. Empty allows any http(s) host. |
| `SATSGATE_MCP_HTTP_TIMEOUT` | Seconds, default 20. |
| `SATSGATE_MCP_MAX_BODY_BYTES` | Response cap, default 1000000. |
| `SATSGATE_MCP_REGISTRY` | JSON file or http(s) URL. See `registry.example.json`. |

Only `http` and `https` URLs are requested. Userinfo is rejected. Redirects are not followed. Requests time out.

## Registry file

```json
{
  "sites": [
    {"name": "example", "url": "https://shop.example/blog/post", "description": "One article"}
  ]
}
```

This is a stand-in. There is no hosted Satsgate registry yet.

## Mainnet check from your machine

Use a route priced at 1 to 21 sats. Pay from a wallet that is not the payee.

### Human QR

```bash
pip install -r mcp/requirements.txt
export SATSGATE_MCP_DATA_DIR="$HOME/.local/share/satsgate-mcp"
PYTHONPATH=mcp/src python -m satsgate_mcp.manual 'https://YOUR-PROXY/blog/post'
```

The process prints the amount, the invoice, a text QR, and the path of a PNG under the data dir. Pay that invoice. It keeps polling until the invoice expires. The wait starts at 2 seconds and grows toward 15 seconds. `--polls N` and `--timeout SECONDS` are optional caps. Status lines start with a UTC timestamp. No NWC URI is required. The macaroon is not printed.

If it stops before the origin body is printed, it prints a command you can paste. That command resumes the same `payment_hash` from the data dir and does not mint a new invoice:

```bash
SATSGATE_MCP_DATA_DIR="$HOME/.local/share/satsgate-mcp" python -m satsgate_mcp.manual --resume PAYMENT_HASH
```

If it stays on `payment_pending` until expiry, the invoice was unpaid or the payee has no LUD-21 `verify` URL. Wallet of Satoshi needs the NWC path below.

### NWC, optional

```bash
export SATSGATE_MCP_NWC_URI='nostr+walletconnect://...'
export SATSGATE_MCP_MAX_PAYMENT_SATS=50
export SATSGATE_MCP_DAILY_MAX_SATS=200
PYTHONPATH=mcp/src python -m satsgate_mcp.manual --nwc 'https://YOUR-PROXY/blog/post'
```

### lnget and fetch402 against the proxy

These clients pay the 402 header themselves. They are not the MCP server. CI checks the header shape and does not pay. On your machine:

```bash
PYTHONPATH=mcp/src python mcp/scripts/mainnet_l402_clients.py 'https://YOUR-PROXY/blog/post'
```

That request does not pay. It prints whether the lnget and fetch402 parsers accept the header. Then, to spend sats:

```bash
lnget 'https://YOUR-PROXY/blog/post'
npm install @getalby/lightning-tools
export NWC_CONNECTION_STRING='nostr+walletconnect://...'
node mcp/scripts/fetch402.mjs 'https://YOUR-PROXY/blog/post'
```

lnget and fetch402 retry with `Authorization: L402 <macaroon>:<preimage>`. A phone wallet that does not return a preimage pays the same invoice and retries with `Authorization: L402 <macaroon>` only. Pending must stay on that invoice (`402 payment_pending`), not a second one.

Confirm the origin saw the request and `X-Satsgate-Signature` verifies. A tampered path or a stale `t=` is rejected by the origin snippet.
