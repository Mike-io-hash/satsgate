# satsgate-mcp

Charge AI agents in Lightning and USDC on the same 402. Payments go straight to your wallet. 500 free unlocks a month.

A buyer-side MCP server. An agent (Claude Desktop, Cursor, or any stdio MCP client) can see the price of a Satsgate-paywalled URL, pay it, and read the response.

This package is version **0.13.1**. It talks to whatever URL returned the 402. Works with core 0.20.3 or later. The self-hosted proxy is **0.14.2**. Works with gate 0.15.2 or later. On a gate host (`SATSGATE_MCP_GATE_HOSTS`, default `gate.satsgate.org`) `pay_and_fetch` pays the gate, keeps the receipt, and repeats the request at `redeem_url` when that host is on the allowlist. The receipt is not logged. A stored receipt is returned by `challenge_status`. The body sent to a gate host is not forwarded. A 402 may offer Lightning, x402 (USDC on Base), or both. One 402 lists one USDC network. `list_sites` includes a public route priced only in USD, with `price_currency` and `price_usd_atomic`. This process cannot load a seller's prepaid service balance, and it does not hold a buyer private key. An account tops up on the core with `POST /v1/topup/lightning` or `POST /v1/topup/usdc`. On api.satsgate.org a USDC top-up is Base mainnet USDC (a self-hosted core needs `SATSGATE_X402_CDP=1`; see [self-hosting](https://github.com/Mike-io-hash/satsgate/blob/main/docs/self-hosting.md)). The USDC path is not an MCP tool.

## Install

```bash
pip install satsgate-mcp
```

or `pip install "satsgate[mcp]"`.

The console script is `satsgate-mcp`. `satsgate-mcp --help` prints the environment variables it reads and exits. `satsgate-mcp --version` prints `satsgate-mcp` and the version. With no arguments it speaks MCP on stdio.

## USDC payments: Base network only

USDC payments use Base only. Ethereum mainnet, Polygon, Solana, Arbitrum, and any other chain are not accepted.

| Network | Network id | Circle USDC contract | Status |
| --- | --- | --- | --- |
| Base Sepolia (testnet) | `eip155:84532` | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | Testing. A site in test mode offers only this USDC. It is not a network for real buyers. |
| Base | `eip155:8453` | [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) | Live mode (on by default on api.satsgate.org; a self-hosted core needs `SATSGATE_X402_CDP=1` and CDP credentials, [self-hosting](https://github.com/Mike-io-hash/satsgate/blob/main/docs/self-hosting.md)). A site in live mode offers only this USDC. |

Merchants: `payTo` must be an address you control on Base. The USDC is paid to that address on the one network that site is in. Try on Base Sepolia with your agent first, then switch the site to live. Buyers: USDC sent on another network will not be accepted. A balance on Ethereum, Polygon, Solana, or Arbitrum does not pay a Satsgate 402.

Satsgate never custodies, receives, forwards, or refunds buyer funds. The USDC moves from the buyer to the merchant's `payTo`. Satsgate does not hold a buyer wallet and does not run its own facilitator.

This MCP server does not send that USDC and does not hold a key. It shows the network and the amount printed on the 402. An accept on any other network is reported and is not payable. A test-mode 402 is Base Sepolia and is labeled testing. A live-mode 402 is Base. This server can describe either. It still does not sign. A wallet that signs uses the `extra` on that 402. Base Sepolia is name `USDC`. Base is name `USD Coin`. This server does not substitute a name.

`list_sites` reads `GET /v1/sites` on `SATSGATE_MCP_CORE_URL` (default `https://api.satsgate.org`). That is the public directory: approved sites that opted in. Set `SATSGATE_MCP_REGISTRY` only to replace it with a JSON file or another URL.

## Run it

```bash
pip install satsgate-mcp
export SATSGATE_MCP_DATA_DIR="$HOME/.local/share/satsgate-mcp"
export SATSGATE_MCP_MAX_PAYMENT_SATS=100
export SATSGATE_MCP_DAILY_MAX_SATS=500
satsgate-mcp
```

`satsgate-mcp` speaks MCP over stdio. Logs go to stderr.

Claude Desktop or Cursor config:

```json
{
  "mcpServers": {
    "satsgate": {
      "command": "satsgate-mcp",
      "env": {
        "SATSGATE_MCP_DATA_DIR": "/absolute/path/to/satsgate-mcp-data",
        "SATSGATE_MCP_MAX_PAYMENT_SATS": "100",
        "SATSGATE_MCP_DAILY_MAX_SATS": "500",
        "SATSGATE_MCP_MAX_PAYMENT_USD": "1",
        "SATSGATE_MCP_DAILY_MAX_USD": "5"
      }
    }
  }
}
```

Put `SATSGATE_MCP_NWC_URI` in that env block when you want the agent to pay. Do not paste the URI into the chat. The tools have no argument for it, and it is not logged.

## Tools

| Tool | What it does |
| --- | --- |
| `discover` | GET (or POST) the URL with no payment. Reads `WWW-Authenticate: L402 macaroon="...", invoice="..."` and the JSON body: `amount_sats`, `max_uses`, `access_seconds`, `invoice_expires_at`. When the 402 offers x402, also reads `PAYMENT-REQUIRED` and the JSON `x402` mirror. |
| `quote` | Same request, plus a short sentence. |
| `pay_and_fetch` | `mode=human` (default) returns the Lightning invoice, a text QR, and a PNG when that rail is offered. `mode=nwc` pays Lightning from the environment wallet if the sats caps allow it, then fetches. An optional `payment_signature` forwards a `PAYMENT-SIGNATURE` the caller already has. This process does not sign. |
| `remote_list_tools` | Lists the tools of a remote MCP server. Free: it never calls a tool and never pays. |
| `remote_call_tool` | Calls one tool on a remote MCP server. Reads the price from an HTTP 402 or from the in-band price notice, then pays with the same modes and caps as `pay_and_fetch`. See [Remote MCP servers](#remote-mcp-servers). |
| `check_payment` | One poll of a human payment. `payment_pending` means call it again after `retry_after_seconds`. On settlement it fetches the URL with `Authorization: L402 <macaroon>` and no preimage. |
| `credits_balance` | `GET /v1/balance` with the optional restricted key. An `sgr_` key can read the balance. It cannot top up. Nothing is written. |
| `challenge_status` | `GET /v1/paywall/status/{payment_hash}?consume=false`. The macaroon is the one stored locally. It is not a tool argument. |
| `list_sites` | Approved, listed sites from `GET /v1/sites`. Routes keep `price_sats` when that is an integer, and `price_currency` plus `price_usd_atomic` when the route is priced in USD. A file or other URL in `SATSGATE_MCP_REGISTRY` replaces the directory. |

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

## x402 (USDC on Base)

A site may enable only Lightning, only x402, or both. x402 is off until the merchant turns it on. If core has no fresh BTC/USD median, a sats-priced route's 402 offers only its primary currency. This client shows the 402 as it arrived. It does not invent a USDC price, and it does not round the amount again. The server already locked the quote and rounded it up (minimum 0.001 USDC, or 1 sat on Lightning).

`PAYMENT-REQUIRED` is base64 of an x402 v2 document. Each accept is returned with `scheme`, `network`, `asset`, `amount_atomic`, `amount_display` (`10000` is `0.01 USDC`), `pay_to`, `resource_url`, and `expires_at` when the body states one. The header is canonical. If the JSON mirror disagrees, the header values are the ones shown. A missing header with only the mirror present is shown with `canonical: false` and is not payable. Expiry is not computed from `maxTimeoutSeconds`.

Supported accepts are Circle USDC on Base Sepolia (`eip155:84532`, the network tests and the current gate use) and Circle USDC on Base (`eip155:8453`). Any other network or asset is listed with `supported: false`. The tool does not raise. A `PAYMENT-SIGNATURE` is forwarded only when every accept is one of those two and inside both USD caps, because the signature may select any accept.

This server holds no buyer private key. It does not sign, submit, custody, forward, or refund USDC, and it does not run a facilitator. Satsgate does not either. When `payable` is true, the `payment` object is what an external wallet has to pay. Call `pay_and_fetch` again with `payment_signature` set to that `PAYMENT-SIGNATURE`: one line, no spaces, at most 8192 bytes. Do not send an L402 `Authorization` on the same request. An empty `payment_signature` stays on the Lightning path.

The gate or proxy runs verify, then the origin, then settle. A 2xx returns the body and, when the server sent one, `payment_response` with `success`, `transaction`, `tx`, `network`, and `payer`. The raw header is not returned. If the origin fails, nothing is settled and the seller's prepaid service balance is not debited. The tool says so, sets `retry_same_payment_signature` true, and the same header can be sent again while the offer is valid. `bad_signature` and `expired` need a new signature. `x402_replay` was already settled, so sending it again does not fetch the resource. `x402_rejected` is either a failed verify (new signature) or a failed settle of a header you already sent (retry that same header). Local USD spend is recorded only after a 2xx, and the signature is not written to sqlite and is not logged.

Both `SATSGATE_MCP_MAX_PAYMENT_USD` and `SATSGATE_MCP_DAILY_MAX_USD` must be set or the tool will not proceed. `0` refuses every positive amount. Unset or over the cap, `discover` still returns the parsed requirements with `payable: false`. `pay_and_fetch` then refuses and does not send the header. The sats caps do not apply to USDC. An over-cap USDC amount does not block paying the Lightning invoice on the same 402.

`mode=human` still returns the invoice and QR when Lightning is offered, so a person can pay from any phone wallet and the agent continues with `check_payment`. A dual 402 returns that invoice and the x402 block together. An x402-only URL has no invoice. NWC is not required for it. An `sgr_` key is still only for `challenge_status` and `credits_balance`. The x402 tools do not call a route that needs an account key.

## Remote MCP servers

`remote_call_tool` calls one tool on a remote MCP server, such as a route of `satsgate-proxy` priced per tool. It is not in a published release yet.

Each call opens its own connection. The client first tries the 2026-07-28 `server/discover`. If the server does not answer it, the client uses `initialize` and the session the server assigns, and ends that session after the call. Then it lists the tools. The handshake and the list are never paid. A tool the server does not list is not called.

An unpaid call to a priced tool gets the price either as an HTTP 402 or as an in-band price notice: a tool result with `isError: true` and the offer in `structuredContent`. Both are read the same way.

- `mode=human` returns the invoice and the QR. Pay it, then call `remote_call_tool` again with the same `url` and `tool`. The same invoice is used until it expires. Do not call `check_payment` for a remote tool.
- `mode=nwc` pays from the environment wallet if the sats caps allow it, then repeats the same call with `Authorization: L402 <macaroon>:<preimage>`.
- `payment_signature` sends a `PAYMENT-SIGNATURE` from an external wallet inside the call, in `params._meta["x402/payment"]`. The USD caps apply. This process does not sign.

A call pays at most once. The token is stored per server URL and tool name, not per argument set, and is reused while it has uses or time. A failed tool call takes no use, so the token is kept and the next call retries with it. Parallel calls to the same tool wait for one another, so a token that covers several calls is paid once. This holds inside one `satsgate-mcp` process. Two processes that share a data directory are not coordinated.

Not supported: requests from the server to the client (sampling, elicitation), a tool that asks for more input, tasks, resources, and prompts. A paid call that times out is not repeated automatically. Call `remote_call_tool` again to retry with the stored token.

Example: a human offer (placeholders for values that change).

```json
{
  "ok": true,
  "payment_required": true,
  "url": "http://shop.example/mcp",
  "method": "POST",
  "resource": "<resource>",
  "max_uses": 1,
  "access_seconds": null,
  "reason": null,
  "rails": [
    "lightning"
  ],
  "summary": "Tool quote: POST http://shop.example/mcp costs 21 sats. One payment covers one request. The invoice expires at unix 0.",
  "amount_sats": 21,
  "payment_hash": "<payment_hash>",
  "invoice": "<invoice>",
  "invoice_expires_at": 0,
  "tool": "quote",
  "protocol_version": "2026-07-28",
  "mode": "human",
  "action": "pay_invoice",
  "qr_text": "<qr_text>",
  "detail": "Pay this invoice from any Lightning wallet, then call remote_call_tool again with the same url and tool. Do not send a preimage. The same invoice is used until it expires. Do not call check_payment for a remote tool."
}
```

Example: the result after paying.

```json
{
  "ok": true,
  "url": "http://shop.example/mcp",
  "tool": "quote",
  "protocol_version": "2026-07-28",
  "is_error": false,
  "content": [
    {
      "text": "acme",
      "type": "text"
    }
  ],
  "structured_content": {
    "result": "acme"
  },
  "paid": true,
  "paid_with": "lightning",
  "paid_sats": 21,
  "reused_token": false,
  "payment_hash": "<payment_hash>",
  "uses_remaining": 0,
  "access_until": null,
  "detail": "The tool returned a result after one Lightning payment. The token is stored for later calls to this tool while it has uses or time."
}
```

## NWC

`SATSGATE_MCP_NWC_URI` is `nostr+walletconnect://...?relay=...&secret=...`. Both caps must be set or every NWC payment is refused. `0` refuses every positive amount. The spend ledger is `satsgate-mcp.sqlite` in the data dir (mode 0600). A payment is recorded when the wallet returns a preimage, including when the origin then fails. Sats are not refunded.

## Environment

| Variable | Meaning |
| --- | --- |
| `SATSGATE_MCP_NWC_URI` | Wallet connection. Never a tool argument. Unset means NWC is off. |
| `SATSGATE_MCP_MAX_PAYMENT_SATS` | Most sats one invoice may cost. Required for NWC. |
| `SATSGATE_MCP_DAILY_MAX_SATS` | Most sats in any rolling 24 hours. Required for NWC. |
| `SATSGATE_MCP_MAX_PAYMENT_USD` | Most USDC one accept may cost, as a decimal with at most 6 places (`0.01` is 10000 atomic). Required before a `PAYMENT-SIGNATURE` is forwarded. Independent of the sats cap. |
| `SATSGATE_MCP_DAILY_MAX_USD` | Most USDC in any rolling 24 hours, same decimal form. Required together with the per-payment cap. |
| `SATSGATE_MCP_AUTO_PAY` | `1` pays a `token_used_up` / `token_expired` replacement inside the same call, if the caps allow it. Default off. |
| `SATSGATE_MCP_DATA_DIR` | sqlite directory. Default `~/.local/share/satsgate-mcp`. |
| `SATSGATE_MCP_CORE_URL` | Core base URL. Default `https://api.satsgate.org`. |
| `SATSGATE_MCP_API_KEY` | Optional `sgr_` key for the two read-only tools. An account `sg_` key is ignored. |
| `SATSGATE_MCP_URL_ALLOWLIST` | Comma-separated hosts. `*.example.com` allows subdomains. Empty allows any http(s) host. |
| `SATSGATE_MCP_HTTP_TIMEOUT` | Seconds, default 20. |
| `SATSGATE_MCP_MAX_BODY_BYTES` | Response cap, default 1000000. |
| `SATSGATE_MCP_REGISTRY` | Optional. A JSON file or http(s) URL that replaces the public directory. Unset uses `{SATSGATE_MCP_CORE_URL}/v1/sites`. |

Only `http` and `https` URLs are requested. Userinfo is rejected. Redirects are not followed. Requests time out.

## Registry file

```json
{
  "sites": [
    {"name": "example", "url": "https://shop.example/blog/post", "description": "One article"}
  ]
}
```

Leave `SATSGATE_MCP_REGISTRY` unset to use the public directory. The response uses `hosted_registry: true`, `slug`, `url` (the gate URL, `https://gate.satsgate.org/<slug>/` when that is the configured public base), `description`, and `routes` with `price_sats` when that price is an integer, plus `price_currency` and `price_usd_atomic` when the route is priced in USD. A USD-only route is kept. `list_sites` follows up to five pages. Each request waits at most 5 seconds, and never longer than `SATSGATE_MCP_HTTP_TIMEOUT`. A timeout, a connection failure, or a non-200 body returns `ok: false` and an empty `sites` list. It does not raise.

A row that includes `status` other than `approved`, or `listed` other than true, is skipped. The public endpoint does not return those rows. A local file that omits both fields is your own list.

If `SATSGATE_MCP_URL_ALLOWLIST` is set, the directory host has to be on it. The default host is the host of `SATSGATE_MCP_CORE_URL`.

## Mainnet check from your machine

Use a route priced at 1 to 21 sats. Pay from a wallet that is not the payee.

### Human QR

```bash
pip install satsgate-mcp
export SATSGATE_MCP_DATA_DIR="$HOME/.local/share/satsgate-mcp"
satsgate-mcp-pay 'https://YOUR-PROXY/blog/post'
```

The process prints the amount, the invoice, a text QR, and the path of a PNG under the data dir. Pay that invoice. It keeps polling until the invoice expires. The wait starts at 2 seconds and grows toward 15 seconds. `--polls N` and `--timeout SECONDS` are optional caps. Status lines start with a UTC timestamp. No NWC URI is required. The macaroon is not printed.

If it stops before the origin body is printed, it prints a command you can paste. That command resumes the same `payment_hash` from the data dir and does not mint a new invoice:

```bash
SATSGATE_MCP_DATA_DIR="$HOME/.local/share/satsgate-mcp" satsgate-mcp-pay --resume PAYMENT_HASH
```

If it stays on `payment_pending` until expiry, the invoice was unpaid or the payee has no LUD-21 `verify` URL. Wallet of Satoshi needs the NWC path below.

### NWC, optional

```bash
export SATSGATE_MCP_NWC_URI='nostr+walletconnect://...'
export SATSGATE_MCP_MAX_PAYMENT_SATS=50
export SATSGATE_MCP_DAILY_MAX_SATS=200
satsgate-mcp-pay --nwc 'https://YOUR-PROXY/blog/post'
```

### lnget and fetch402 against the proxy

These clients pay the 402 header themselves. They are not the MCP server.

A header-shape check that does not pay is in the contributors' section below. To spend sats:

```bash
lnget 'https://YOUR-PROXY/blog/post'
npm install @getalby/lightning-tools
export NWC_CONNECTION_STRING='nostr+walletconnect://...'
node mcp/scripts/fetch402.mjs 'https://YOUR-PROXY/blog/post'
```

lnget and fetch402 retry with `Authorization: L402 <macaroon>:<preimage>`. A phone wallet that does not return a preimage pays the same invoice and retries with `Authorization: L402 <macaroon>` only. Pending must stay on that invoice (`402 payment_pending`), not a second one.

Confirm the origin saw the request and `X-Satsgate-Signature` verifies. A tampered path or a stale `t=` is rejected by the origin snippet.

## For contributors

From a checkout: `PYTHONPATH=mcp/src python -m satsgate_mcp`.

```bash
PYTHONPATH=mcp/src python mcp/scripts/mainnet_l402_clients.py 'https://YOUR-PROXY/blog/post'
```
