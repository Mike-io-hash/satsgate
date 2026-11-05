# satsgate-gate

The hosted gate. One process serves many approved sites at `https://gate.satsgate.org/<slug>/<path>`.

Version **0.15.0**. Core is **0.18.0**. This process sells a signed receipt and nothing else. It does not call the origin, relay the buyer, or serve seller content. A site can offer Lightning, x402 (USDC on one Base network), or both. x402 is off until the merchant turns it on. A new site stores no mode. Turning x402 on without a mode stores test (Base Sepolia). Live (Base) is a separate choice and only works when the operator has enabled CDP. Test mode issues a receipt and does not debit a credit. Live mode and Lightning debit one credit when the receipt is issued. The self-hosted proxy is **0.14.0** and is a different program. In `mode: paywall` it still forwards and still charges after a successful origin. In `mode: receipt` it checks `Satsgate-Receipt` and does not call core. This process has no origin secret and does not call the facilitator. A debit from this gate still has a null `api_key_id`, because the gate authenticates with `GATE_TOKEN` rather than an `sgr_` key.

## USDC payments: Base network only

USDC payments use Base only. Ethereum mainnet, Polygon, Solana, Arbitrum, and any other chain are not accepted.

| Network | Network id | Circle USDC contract | Status |
| --- | --- | --- | --- |
| Base Sepolia (testnet) | `eip155:84532` | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | Testing. A site in test mode offers only this USDC. It is not a network for real buyers. |
| Base | `eip155:8453` | [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) | Live mode. Available only when the operator sets `SATSGATE_X402_CDP=1` and both CDP credentials. The 402 offers only this USDC. |

Merchants: `payTo` must be an address you control on Base. The USDC is paid to that address on the one network the site is in. The EIP-712 name in `extra` is `USDC` on Base Sepolia and `USD Coin` on Base. Try on Base Sepolia with your agent first, then switch the site to live. Buyers: USDC sent on another network will not be accepted. A balance on Ethereum, Polygon, Solana, or Arbitrum does not pay this gate.

Satsgate never custodies, receives, forwards, or refunds buyer funds. The USDC moves from the buyer to the merchant's `payTo`. This process does not hold a buyer wallet and does not run its own facilitator.

## Why an internal API

The gate and core run on the same host, on one docker network. The gate does not mount the sqlite file and does not receive `origin_secret`.

Core mints the receipt. The internal routes return one approved site (routes, origin URL, rails, `x402_mode`) and the challenge and receipt calls. The token is `SATSGATE_GATE_TOKEN`. It is not the admin token. The admin token can approve a site. This token cannot.

The routes are not in the public OpenAPI document. When the token is unset they answer 404. Compose also sets `SATSGATE_GATE_PEERS` to the gate container (`172.28.0.4`), so a request that arrives through Caddy is rejected even if the token leaks. The public Caddy host answers 404 for `/internal/*` before the request reaches core. The gate calls `http://satsgate:8000` on the docker network. `POST /internal/gate/charge`, `POST /internal/gate/x402/verify`, and `POST /internal/gate/x402/settle` are gone. Receipts are `POST /internal/gate/receipt` and `POST /internal/gate/x402/receipt`.

## What a request does

`GET /` is service JSON (`name`, `version`, `delivery`, `terms`, `abuse`). `GET /healthz` stays `{"ok": true, "component": "satsgate-gate", "version": "0.15.0"}`. The gate does not read the request body. `HEAD` returns the same headers and no body. Responses set `Cache-Control: no-store`.

1. `GET /internal/gate/sites/<slug>/status` on every request. This is not cached. Anything other than `approved` is HTTP 404, with no distinction between missing, pending, and disabled.
2. The site record (origin URL, routes, rails, `x402_mode`) is cached for `SATSGATE_GATE_CACHE_SECONDS` (default 5). A config that still contains `origin_secret` is rejected. A disable still takes effect on the next request because step 1 is uncached.
3. The path after the slug is an exact route. `/slug` and `/slug/` are the route `/`. The query string is not part of the match and is not copied onto `redeem_url`. Unknown paths are 404. There is no free path.
4. No payment header yet: core mints a challenge for resource `gate:<slug>:<path>`. The 402 adds `delivery: receipt`, `redeem_url` (origin plus path), `receipt_header: Satsgate-Receipt`, `seller_host`, and `terms_url` when `SATSGATE_TERMS_URL` is set. `Link` is `<redeem_url>; rel="satsgate-redeem"`. Lightning still sends `WWW-Authenticate: L402`. x402 still sends `PAYMENT-REQUIRED`. The resource description is `Satsgate receipt for {host}{path}`. Test mode prefixes the Base Sepolia test sentence. Credits are not spent yet.
5. `Authorization: L402 <macaroon>:<preimage>` asks core to confirm the invoice and issue the receipt. The credit is taken in that same step, except test mode, which does not apply to Lightning. Pending, when the payee has LUD-21 and the invoice is not paid yet, is HTTP 402 `payment_pending` with `Retry-After`. A mock wallet with no LUD-21 and no preimage is HTTP 401 `preimage_required`. An expired grant is HTTP 401 `token_expired`. The owner being out of credits is HTTP 502 `paywall_unavailable`. The origin is not called.
6. `PAYMENT-SIGNATURE` is posted to `POST /internal/gate/x402/receipt`. Core verifies and settles with the facilitator. Live mode takes one credit when the receipt is stored. Test mode (`x402_mode: test`) stores the receipt with cost 0 and does not move credits. A replay of the same payment returns the same receipt. A flagged payee is HTTP 403 `payee_not_allowed`. The gate does not call the facilitator.
7. Both `Authorization: L402` and `PAYMENT-SIGNATURE` is HTTP 400 `one_rail_only`.
8. A paid response is HTTP 200. The body includes `receipt` (the compact JWT) and `redeem_url`. The header `Satsgate-Receipt` is the same token. The buyer repeats the request at the seller. This process does not follow that URL.

`X-Satsgate-Buyer-Ip` is set by the gate from `X-Forwarded-For`, and only when the TCP peer is in `SATSGATE_GATE_TRUSTED_PROXIES` (Caddy, `172.28.0.2`). Core accepts that header only from the gate. Caddy deletes the header on public hosts, so a buyer cannot pick a bucket. Rate limits run after the site is loaded, so an unknown slug is not counted. Test mode uses `SATSGATE_GATE_RL_TEST_PER_BUYER` (default 10) and `SATSGATE_GATE_RL_TEST_PER_SITE` (default 60) instead of 60 and 600.

The resource `gate:<slug>:<path>` must be at most 200 characters. A longer route is stored by core and is not served. Caddy caps the gate request body at 64KB. The gate does not read it.

## Run it

Compose builds this directory and does not publish a port. Caddy is the only public listener. The `gate.satsgate.org` site block is active and caps the body at 64KB. See the repository `docker-compose.yml` and `Caddyfile`. Old upstream timeout and size variables are ignored so a previous env file still starts. They are not in Compose.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_GATE_CORE_URL` | `http://satsgate:8000` | Core on the docker network. Not the public API URL. |
| `SATSGATE_GATE_TOKEN` | unset | Same value as on core. |
| `SATSGATE_GATE_TRUSTED_PROXIES` | empty (Compose sets `172.28.0.2`) | Peer allowed to supply `X-Forwarded-For`. |
| `SATSGATE_GATE_CACHE_SECONDS` | 5 | Site record cache. Status is never cached. |
| `SATSGATE_GATE_CORE_TIMEOUT` | 10 | Seconds for the core call. |
| `SATSGATE_GATE_RL_PER_SITE` | 600 | Requests per window. `0` disables. Test mode uses the test limit instead. |
| `SATSGATE_GATE_RL_PER_BUYER` | 60 | Requests per buyer IP per window. |
| `SATSGATE_GATE_RL_TEST_PER_SITE` | 60 | Test-mode requests per site per window. |
| `SATSGATE_GATE_RL_TEST_PER_BUYER` | 10 | Test-mode requests per buyer IP per window. |
| `SATSGATE_ABUSE_CONTACT` | empty | Bare email included on `GET /`. |
| `SATSGATE_TERMS_URL` | empty | https URL included on the 402 when set. |

`GET /healthz` returns `{"ok": true, "component": "satsgate-gate", "version": "0.15.0"}`.

## Turn on x402

Use the account key. A restricted `sgr_` key cannot set a payee, a rail, or `x402_mode`. `payTo` must be an address you control on Base. USDC sent on another network will not be accepted. See [USDC payments: Base network only](#usdc-payments-base-network-only).

Try on Base Sepolia with your agent first, then switch the site to live.

1. `POST /v1/client/payee/evm/challenge` with `{"address":"0x..."}`. Sign the returned text with `personal_sign` (EIP-191). Nothing happens on chain. Or create a one-time connect link with `POST /v1/client/payee/evm/connect` and open it in a browser.
2. `POST /v1/client/payee/evm` with `{"address","signature"}`. `GET /v1/client` then shows `payee_evm_verified: true`. It does not return the signature.
3. `PATCH /v1/sites/{slug}` with `{"rail_x402": true}`. That stores `x402_mode: "test"` when the mode was unset. The 402 offers only Base Sepolia (`eip155:84532`, contract [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e)) and the JSON says `testing: true`. Set `rail_lightning` false for x402 only. Both false is `400 rails_required`.
4. After the operator has set `SATSGATE_X402_CDP=1`, `PATCH` `{"x402_mode":"live"}`. The 402 then offers only Base (`eip155:8453`, contract [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)). While the switch is off, that PATCH is `400 x402_mainnet_disabled`. A new site does not start in live mode, so a merchant cannot take real USDC by accident.
5. Add a route. `{"path":"/blog/post","price_sats":21}` keeps sats as the main price. `{"path":"/blog/post","price_currency":"usd","price_usd_atomic":10000}` is $0.01 USDC (6 decimals). Sending both is `400 price_conflict`. A sats price is quoted as USDC only while `GET /v1/rates` is `ok` and the quote is at least $0.001.

The site must be `approved`. `listed: false` keeps it off `GET /v1/sites`. The gate still serves an approved unlisted site. The public directory may show `x402_mode` and `x402_testing`. It does not show `payTo`.

Test-mode rate limits and the abuse contact are the gate variables added for receipts. The CDP key stays on core. Core already has `SATSGATE_X402_FACILITATOR_URL` (default `https://x402.org/facilitator`) for test mode, `SATSGATE_X402_NETWORK` (`eip155:84532` only; mainnet is `SATSGATE_X402_CDP`, not this variable), and `SATSGATE_X402_OFFER_SECONDS`. Do not point those at a Satsgate process. This service does not custody, receive, forward, or refund buyer funds.

## Private Sepolia check

After the gate image is deployed, use an unlisted approved site and a buyer wallet funded with faucet USDC on Base Sepolia. The merchant test `payTo` for that check is `0x4A9E2CA774BB87110ffF3CB8a250e935cFE52Ce3`. It is a public test address. It is not a default and it is not compiled into the gate. Confirm the settlement transaction's `to` is that address. Confirm the origin request has `X-Satsgate-Paid-Usd-Atomic` and no `PAYMENT-SIGNATURE`. Then make the origin fail and confirm the credit balance does not move. Retry the same `PAYMENT-SIGNATURE` and confirm it still serves, then settles once.
