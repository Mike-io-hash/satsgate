# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core 0.15.0 accepts USDC on Base (`eip155:8453`) through the Coinbase CDP facilitator when `SATSGATE_X402_CDP=1` and both `SATSGATE_X402_CDP_KEY_ID` and `SATSGATE_X402_CDP_KEY_SECRET` are set. The default is off. A missing or unusable credential does not refuse boot. Sepolia and Lightning still start. The secret is a CDP Ed25519 API key. It is not logged, not on `/health`, not in the manifest, and not given to the gate. `SATSGATE_X402_NETWORK` must stay `eip155:84532`. Mainnet is the CDP switch, not that variable.
- A site has one x402 mode. `test` offers only Base Sepolia through `https://x402.org/facilitator`. `live` offers only Base through CDP, and only while the switch is on. One 402 never lists both. A new site leaves the rail off and the mode unset. Turning the rail on without a mode stores `test`, so a merchant does not take real USDC until they ask for live. Test responses set `testing: true` and describe the payment as Base Sepolia, not Base mainnet. Try on Base Sepolia with your agent first, then switch the site to live.
- `sites.x402_mode` (`TEXT NOT NULL DEFAULT ''`). Existing rows stay lightning-only with an empty mode. No other new table.
- Credit packs are mainnet USDC only while the switch is on, and Base Sepolia only while it is off. Credits are not sold for faucet USDC once mainnet is on. A merchant route can stay in test mode while packs are on mainnet.
- `GET /v1/admin/x402` (admin token) reports whether mainnet is enabled and whether a cached CDP `GET /supported` advertised `exact` on `eip155:8453`. The JSON has no secret and no key id. Call it at most once a minute.
- Hosted gate 0.14.0 accepts exactly one USDC accept, on Sepolia or on Base, and keeps `testing` and `x402_mode` on the 402 body.
- `satsgate-proxy` 0.13.0 sends `x402_mode` (`test` or `live`). `x402: true` without a mode is test. A mode without `x402: true` refuses to start.

### Changed
- The draft terms in `docs/hosted-gate-terms.md` now say that a facilitator can reject a USDC payment, including after the origin ran; that illegal or sanctioned content can be taken down; that credits are not money and are not redeemable; and that the service is not anonymous. The draft is still pending legal review.

Core health is 0.15.0. The hosted gate is 0.14.0. The self-hosted proxy is 0.13.0. satsgate-mcp stays 0.11.0. Copy `satsgate.sqlite3` before restart. Rebuild the core image, the gate image, and the proxy image. Rollback is `SATSGATE_X402_CDP=0` and a core restart. Live sites stop offering USDC. Test mode and Lightning keep working. The column stays.

### Added
- `satsgate-mcp` 0.11.0 reads an x402 offer on a 402. `discover`, `quote`, and `pay_and_fetch` parse `PAYMENT-REQUIRED` (x402 v2, scheme `exact`) and show each accept: network, asset, the raw atomic amount, human USDC (6 decimals, so `10000` is `0.01 USDC`), `payTo`, resource URL, scheme, and expiry when the body states one. The header wins when the JSON `x402` mirror disagrees. Amounts are the locked figures on that 402. This process does not recompute them from sats or from a BTC/USD rate. A Lightning-only 402, an x402-only 402, and a 402 that offers both are all returned. A malformed x402 header does not drop a valid Lightning invoice. An unknown network or asset is reported and is not payable. Only USDC on Base Sepolia (`eip155:84532`) and USDC on Base (`eip155:8453`) count as supported. This client does not pay either network.
- A separate USD budget: `SATSGATE_MCP_MAX_PAYMENT_USD` and `SATSGATE_MCP_DAILY_MAX_USD`. Both must be set before the tool describes an external payment or forwards a `PAYMENT-SIGNATURE`. `0` refuses every positive amount. The sats caps are not used for USDC. Over the cap, or with a cap unset, the requirements are still shown and the signature is not sent.
- `pay_and_fetch` takes an optional `payment_signature`. The server holds no buyer key and does not sign. It forwards that header only when every accept is supported USDC on Base and inside both USD caps, and it does not send `Authorization` on the same request. A 2xx returns the body and the public `PAYMENT-RESPONSE` fields (`success`, `transaction`, `tx`, `network`, `payer`). An origin error says nothing was settled and no merchant credit was taken, and that the same header can be retried. `x402_rejected` covers a failed verify (send a new signature) and a failed settle (retry the same header). The signature is not logged, stored, or returned. The local sqlite file gains `quotes.x402_json` and a `spend_usd` table. Existing rows stay. Spend is recorded only after a 2xx.
- `list_sites` keeps a USD-only public route (`price_currency` `usd` and `price_usd_atomic` at least 1) and passes `price_currency` and `price_usd_atomic` through. A sats route still requires an integer `price_sats`.

### Changed
- Core 0.14.3 stores `api_key_id` on a new x402 ledger debit when the settle caller authenticated with a restricted `sgr_` key. That is the proxy's public `POST /v1/paywall/x402/settle`. The hosted gate authenticates with `GATE_TOKEN` and still leaves the column null, as does an account key. Existing rows are not rewritten. No new column and no new table. `payment_offers.api_key_id` stays null. That column is the buyer-limit scope, not this debit.
- `satsgate-proxy` 0.12.1 logs `key fp` and the first 12 hex characters of SHA-256 of the API key at startup. It does not log any part of the key. `proxy/docker-compose.yml` tags the image `satsgate-proxy:0.12.1`.
- Docs state the USDC network in plain language: Base only, with `eip155:84532` (Base Sepolia, live) and `eip155:8453` (Base, not live in this version). The Circle contract addresses link to BaseScan. `payTo` has to be an address the merchant controls on Base. USDC sent on another chain is not accepted. No behaviour change.

Those notes describe satsgate-mcp 0.11.0, proxy 0.12.1, gate 0.13.0, and core 0.14.3. Current versions are at the top of Unreleased. That release added no core migration. Copy `satsgate.sqlite3` before restart if you want a rollback point. Rebuild the proxy image and the core image. The gate image stayed 0.13.0. An agent that pays USDC sets both USD caps and brings a `PAYMENT-SIGNATURE` from its own wallet. That release left the facilitator at `https://x402.org/facilitator`.

### Added
- `satsgate-mcp` 0.10.0. `list_sites` reads `GET /v1/sites` on `SATSGATE_MCP_CORE_URL` (default `https://api.satsgate.org`) without any extra setting. Each row is an approved, listed site: name, slug, description, gate URL, and routes (`price_sats`, `max_uses`, `access_seconds`). A row that still carries `status` other than `approved`, or `listed` other than true, is dropped. A route without an integer `price_sats` is dropped, so a USD-priced route does not appear until a later MCP release. `SATSGATE_MCP_REGISTRY` is an optional file or URL that replaces the public directory. A directory that times out (5 seconds, and never longer than `SATSGATE_MCP_HTTP_TIMEOUT`), fails to connect, or returns a non-200 or unreadable body comes back as `registry_unavailable` or `invalid_registry` with an empty `sites` list.
- `docs/hosted-gate-terms.md`, a draft terms of use for the closed-beta hosted gate. It is not in effect until legal review.

The notes below describe 0.10.0 and gate 0.12.0. Current versions are in the paragraphs above.

### Added
- `satsgate-gate` 0.12.0. One HTTP 402 offers the rails that site has turned on. Lightning still returns the same JSON and `WWW-Authenticate` as 0.11.0, with no `PAYMENT-REQUIRED`. x402, off until the merchant enables it, adds `PAYMENT-REQUIRED` (scheme `exact`, network `eip155:84532`, Base Sepolia USDC, `payTo` the account's verified address, amount from the route's main price or the locked `/v1/rates` quote). A site can be Lightning only, x402 only, or both. The 402 lists only the enabled rails.
- A request with `PAYMENT-SIGNATURE` is verified by core, which calls the public facilitator. The gate does not. The origin is called only after verify succeeds. The body is returned, with `PAYMENT-RESPONSE`, only after the origin is 2xx and settle succeeds. One merchant credit is taken at that point. An origin HTTP error does not settle and does not take a credit. A failed settle is 402 `x402_rejected` and the origin body is not returned. The credit stays. Sending both `Authorization: L402` and `PAYMENT-SIGNATURE` is 400 `one_rail_only`. A `PAYMENT-SIGNATURE` over 8 KB is rejected before core is called.
- Toward the origin, USDC sends `X-Satsgate-Paid-Usd-Atomic` and `X-Satsgate-Payment-Hash` set to the EIP-3009 nonce (64 hex characters, no `0x`). It does not send `X-Satsgate-Paid-Sats`. `PAYMENT-SIGNATURE` is stripped. Lightning sends `X-Satsgate-Paid-Sats`. As of gate 0.13.0 the credit is taken only after the origin returns 2xx (see 0.14.1).

`GET /healthz` reports `0.13.0`. `GET /health` on core is `0.14.1`. No new table and no new column. No new environment variable. Copy `satsgate.sqlite3` before restart anyway. Rebuild the `gate` image and the core image together and start the gate with core, or start the gate first. The core site config now includes USD routes and `rail_lightning` / `rail_x402`. An older gate treats a USD route as a bad site config and answers 502 for that whole site until it is upgraded. Lightning-only sites keep working on the old gate. Leave `SATSGATE_X402_FACILITATOR_URL` at `https://x402.org/facilitator` and `SATSGATE_X402_NETWORK` at `eip155:84532`. Do not add a facilitator key or a Satsgate wallet. Buyer USDC goes to the merchant `payTo` through the facilitator.

To turn x402 on, with the account key: `POST /v1/client/payee/evm/challenge` with the merchant's `0x` address, sign that EIP-191 text (`personal_sign`), then `POST /v1/client/payee/evm` with the address and signature. Core 0.13.1 also accepts the signature when the wallet drops the trailing newline. `PATCH /v1/sites/{slug}` with `{"rail_x402": true}` requires that verified address. Lightning can stay on or be set false. A route is `{"path":"/blog/post","price_sats":21}` or `{"path":"/blog/post","price_currency":"usd","price_usd_atomic":10000}` (6 decimals). Do not send both amounts. A sats price is offered as USDC only while the BTC/USD median is fresh and the quote is at least $0.001. A private unlisted site is `listed: false`. Approve it before the gate will serve it. The private Sepolia check is in `gate/README.md`.

## [0.14.2] - 2026-10-23

### Changed
- `satsgate-proxy` 0.12.0 matches the hosted gate's charge timing and offers both rails. An unpaid request is still HTTP 402. Lightning keeps `WWW-Authenticate`. When a route sets `x402: true` and the account has a verified EVM payee, the same 402 also carries `PAYMENT-REQUIRED` (x402 v2, scheme `exact`, Base Sepolia USDC, `payTo` that address, amount derived from the sats price). The proxy confirms a Lightning payment, or asks core to verify a `PAYMENT-SIGNATURE`, then calls the origin. One credit is taken only after that response is 2xx: `POST /v1/paywall/charge` for Lightning, and `POST /v1/paywall/x402/settle` for USDC. A 4xx or 5xx from the origin is returned as that status and body. Nothing is debited and nothing is settled. The same macaroon, or the same `PAYMENT-SIGNATURE`, can be retried. A redirect, timeout, or oversized body is 502 or 504 with `use_spent: false`. `PAYMENT-RESPONSE` is `success`, `transaction`, `network`, and `payer`, with `tx` repeating the hash. The proxy does not call the facilitator. Buyer USDC goes to the merchant `payTo`.
- `POST /v1/paywall/verify` and `GET /v1/paywall/status` still debit when `charge` is omitted or true, so proxy 0.8.0 keeps its old behaviour on this core. The new proxy sends `charge=false` and charges afterwards.
- An unpaid Lightning quote occupies the per-buyer cap, and the account cap, only for `SATSGATE_X402_OFFER_SECONDS` clamped to 60–300. The BOLT11 invoice and the macaroon claim window are unchanged, so a buyer can still pay, and a LUD-21 status check still runs, after the quote has left the cap. `Retry-After` is the soonest of those short slots. Asking for the price five times no longer blocks that IP for the life of a 24 hour invoice.
- An x402 route debit (`paywall_verify`) now stores `network` and `amount_usd_atomic` on the ledger row. The columns already exist. Lightning debits leave them empty.

`GET /health` reports `0.14.2`. `GET /healthz` on the proxy reports `0.12.0`. The gate stays `0.13.0`. No migration and no new environment variable. `server.public_base` in the proxy YAML is required only when a route sets `x402: true`. Copy `satsgate.sqlite3` before restart if you want a rollback point. Rebuild the proxy image and the core image. An old proxy image keeps debiting before it forwards. Leave the facilitator at `https://x402.org/facilitator`.

## [0.14.1] - 2026-10-22

### Changed
- Hosted gate 0.13.0 charges a Lightning credit only after the origin returns 2xx. Core confirms the preimage or LUD-21 proof first (`settled_at` is set, the credit stays), the gate calls the origin, and `POST /internal/gate/charge` then takes one use and, on the first success, one credit. A 4xx or 5xx from the origin is returned as that status and does not debit. A redirect, timeout, rebind, or oversized body is 502 or 504 with `use_spent: false`. The same macaroon retries inside its validity. `max_uses` still allows one successful delivery. Two concurrent retries debit once. The merchant pays a Satsgate credit only for a successful delivery. Buyer sats already went to the merchant's own node. Satsgate does not custody them and does not refund them.
- The self-hosted proxy is unchanged at 0.8.0. `POST /v1/paywall/verify` still debits on the first settled call, which is what the proxy uses before it forwards. An old gate that still sends `consume=true` keeps that earlier debit. Rebuild the gate image and the core image together.
- A gate-route x402 offer uses `SATSGATE_X402_OFFER_SECONDS` clamped to 60–300 (default 60), the same window as a USDC credit pack. That clock is not the Lightning invoice expiry. A reused invoice whose x402 quote has expired gets a new short quote. The BOLT11 invoice and the macaroon claim window stay as they were.
- The per-buyer open-challenge cap counts only unexpired, unused challenges. Lightning and x402 are counted separately, each against `SATSGATE_BUYER_MAX_OPEN_CHALLENGES` (default 5). An expired offer does not count. A settled Lightning invoice does not count. An x402 offer that already charged a credit does not count. `Retry-After` is the soonest expiry of the rows that still count, not the expiry plus the claim grace and not the 48 hour claim cap. The per-minute rate still counts recent creates on both rails together. The account-wide cap uses the same unexpired, unused rule and the same soonest-expiry `Retry-After`.
- `PAYMENT-RESPONSE` follows the x402 v2 settlement response: `success`, `transaction`, `network`, and `payer`. `transaction` is the spec name ([coinbase/x402 `specs/x402-specification-v2.md`](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md), section 5.3). `tx` repeats the same hash for this release. The gate copies the header. Core top-up uses the same document.

`GET /health` reports `0.14.1`. `GET /healthz` on the gate reports `0.13.0`. No migration and no new environment variable. `SATSGATE_X402_OFFER_SECONDS` is the existing setting. Copy `satsgate.sqlite3` before restart if you want a rollback point. Restart core and the gate together. The proxy image does not need a rebuild. Leave the facilitator at `https://x402.org/facilitator`.

## [0.14.0] - 2026-10-22

### Added
- `GET /v1/topup/{plan_id}/x402` sells the same credit pack for USDC on Base Sepolia. The account key is required. A restricted key cannot buy credits. With no `PAYMENT-SIGNATURE`, the response is 402 and `PAYMENT-REQUIRED` (x402 v2, scheme `exact`, asset Base Sepolia USDC, `payTo` `SATSGATE_TREASURY_EVM_ADDRESS`, amount the pack's sats price converted with the live BTC/USD median). `maxTimeoutSeconds` follows `SATSGATE_X402_OFFER_SECONDS`, clamped to 60–300. With `PAYMENT-SIGNATURE`, core checks the payload against that locked offer, asks the existing facilitator to verify and then settle, and grants the pack only after settle succeeds. The buyer response carries `PAYMENT-RESPONSE`.
- The quote rounds up to the next USDC atomic unit (6 decimals), the same way a route quote rounds. Below $0.001 is not offered. Above $1,000,000 is not offered. The $100 route cap does not apply, because a pack price is not merchant input. The integer is locked on the offer. A later median does not change it. A missing or stale median is 503 `rate_unavailable` on this path only. Lightning top-up is unchanged.
- One EIP-3009 nonce (network, asset, payer, nonce on `x402_authorizations`) can grant credits once. A second submit is 409 `x402_replay`. A duplicate still in flight is 409 `x402_in_progress`. The ledger reason is `topup_x402`, with the tx hash, network, and atomic amount. Credits stay closed-loop and are not redeemable for USDC. There is no withdrawal. Satsgate does not run a facilitator and does not forward anyone else's funds. This payment is the client buying Satsgate credits, so the USDC is paid to Satsgate's own treasury.

`GET /health` reports `0.14.0`. Startup adds `resource_url` and `grant_credits` on `payment_offers`, `rail`, `tx_hash`, `amount_usd_atomic`, and `network` on `topups`, and `network` and `amount_usd_atomic` on `ledger`. No new table. Copy `satsgate.sqlite3` before restart if you want a rollback point. Leave `SATSGATE_TREASURY_EVM_ADDRESS` unset and the USDC pack route answers `x402_topup_disabled`. Lightning top-up keeps working. An invalid address does the same, and does not stop the process. The gate image does not need a rebuild for this release. Restart the core image. Keep `SATSGATE_X402_FACILITATOR_URL` at `https://x402.org/facilitator` and `SATSGATE_X402_NETWORK` at `eip155:84532`.

## [0.13.1] - 2026-10-22

### Fixed
- `POST /v1/client/payee/evm` accepts an EIP-191 signature over the server challenge, or over that same text with only trailing whitespace removed. Wallet UIs such as Etherscan and BaseScan trim the trailing newline before MetaMask signs. CRLF line endings verify as the same message. The nonce, expiry, address, client, and domain otherwise have to match the stored challenge. The nonce is single-use. An expired challenge is rejected. A bad signature still leaves the stored address as it was. Satsgate still does not custody funds and does not run a facilitator.

`GET /health` reports `0.13.1`. No migration and no new environment variable. The gate is unchanged. Copy `satsgate.sqlite3` before restart if you want a rollback point. Restart the core image.

## [0.13.0] - 2026-10-20

### Added
- `GET /v1/rates`, a public BTC/USD median. Core refreshes Coinbase, Kraken, and Bitstamp about once a minute (2 second timeout each, no API key). It keeps the median of the sources that agree. One source is not enough. A price more than 2% from the median is dropped. The last good median goes stale after 3 minutes. `status` is `ok`, `stale`, or `unavailable`.
- A route still has one main price, sats or USD. When the other rail is enabled and the median is fresh, the challenge locks the derived amount on `payment_offers` (`rate_num`, `rate_den`, `rate_fetched_at`, both amounts, expiry). A later verify uses that row, not a new fetch. If the median is missing or stale, the challenge offers only the main currency. It does not fail because the quote is down.
- Derived sats round up to the next sat (minimum 1). Derived USDC rounds up to the next atomic unit (6 decimals). A derived USDC amount below $0.001 is not offered. The merchant's own price is unchanged.
- `GET /v1/sites/mine` adds `derived` on each route: the live quote, or `unavailable` / `stale` / `below_minimum`. `GET /v1/sites` still shows the main price and `price_currency` only. It does not show `payTo` or the moving quote.

`GET /health` reports `0.13.0`. No new table and no new column. Copy `satsgate.sqlite3` before restart anyway. Lightning challenges are unchanged when x402 is off or the median cannot be used. The hosted gate stays 0.11.0 and still ignores extra fields on a Lightning challenge. Satsgate does not convert, hold, or forward the payment. The buyer pays the locked amount on that rail to the merchant.

New env vars, all optional: `SATSGATE_RATES_ENABLED` (default on), `SATSGATE_RATES_REFRESH_SECONDS` (60), `SATSGATE_RATES_STALE_SECONDS` (180), `SATSGATE_RATES_SOURCE_TIMEOUT_SECONDS` (2), `SATSGATE_RATES_OUTLIER_BPS` (200).

## [0.12.0] - 2026-10-19

### Added
- Core x402 v2 on Base Sepolia (`eip155:84532`), USDC, scheme `exact` (EIP-3009). The facilitator is `https://x402.org/facilitator` unless `SATSGATE_X402_FACILITATOR_URL` is set. Satsgate does not sign, broadcast, or hold a key. Base mainnet is refused at startup. There is no CDP path.
- A merchant sets an EVM `payTo` with the account key. `POST /v1/client/payee/evm/challenge` returns an EIP-191 message (10 minutes, nothing on chain). `POST /v1/client/payee/evm` checks the signature and stores the address. A bad signature leaves the stored address as it was. Changing the address turns x402 off on that account's sites. `GET /v1/client` adds `payee_evm_address` and `payee_evm_verified`. It does not return the signature.
- `PATCH /v1/sites/{slug}` accepts `rail_lightning` and `rail_x402` from the account key only. Lightning stays on. x402 stays off until the merchant turns it on, and that requires a verified address. Both off is `400 rails_required`. A restricted key still cannot change rails.
- A route has one price: `price_currency` `sats` with `price_sats`, or `usd` with `price_usd_atomic` (USDC atomic units, 6 decimals, 1 to 100000000). Mixing the two is `400 price_conflict`. This release offers x402 only for a USD price on an x402-enabled site. A sats price stays Lightning. There is no conversion yet.
- The internal gate API, still omitted from OpenAPI and still requiring `SATSGATE_GATE_TOKEN`, can `POST /internal/gate/x402/verify` and `POST /internal/gate/x402/settle`. Verify checks the `PAYMENT-SIGNATURE` locally (amount, asset, network, payTo, validity), then asks the facilitator `/verify`, and returns `serve: true` without debiting a credit. Settle runs only after the caller reports a successful origin response: facilitator `/settle`, then one credit, then `PAYMENT-RESPONSE`. A failed settle does not debit. A used nonce is rejected. The hosted gate 0.11.0 does not call these routes yet.
- `GET /v1/sites` adds `price_currency` on each route. A USD route includes `price_usd_atomic` and omits `price_sats`. The directory still does not include `payTo`, the owner, or the origin.

`GET /health` reports `0.12.0`. Lightning challenges, invoices, and the debit-before-forward path are unchanged. The hosted gate stays 0.11.0. The self-hosted proxy stays 0.8.0. satsgate-mcp stays 0.10.0.

Copy `satsgate.sqlite3` before restart. Startup adds `payee_evm_*` on `clients` (existing rows stay NULL), `rail_lightning` (default on) and `rail_x402` (default off) on `sites`, rebuilds `site_routes` so `price_sats` may be null (existing rows stay `sats` with the same amount), and creates `payment_offers` and `x402_authorizations`. New env vars have safe defaults: leave `SATSGATE_X402_NETWORK` unset or set `eip155:84532` (anything else refuses to boot), `SATSGATE_X402_FACILITATOR_URL` defaults to `https://x402.org/facilitator`, and `SATSGATE_X402_OFFER_SECONDS` defaults to 60 (15 to 300). No new secret. A USD route is stored but the current gate does not serve it.

## [0.11.0] - 2026-10-18

### Added
- `satsgate-gate` 0.11.0, a separate container that serves `https://gate.satsgate.org/<slug>/<path>` for an approved site. It reads that site from core over an internal HTTP API (`SATSGATE_GATE_TOKEN`), not by opening the sqlite file. The response for one approved site includes that site's decrypted origin secret. Pending, disabled, and unknown slugs are the same HTTP 404. The gate caches the site for a few seconds (`SATSGATE_GATE_CACHE_SECONDS`, default 5) and checks status on every request, so a disable takes effect on the next request.
- Charging uses the existing challenge, status, and verify functions on the site owner's account. Credits come from the owner. The invoice is paid to the owner's Lightning Address. The route's price and usage policy are copied onto the challenge. The resource is `gate:<slug>:<path>`. The buyer sees the same L402 402 as the self-hosted proxy, including the no-preimage poll and a fresh 402 when the grant is used up. `X-Satsgate-Buyer-Ip` is sent by the gate. Core honors it only from the gate container.
- Forwarding signs `X-Satsgate-Signature` with the same HMAC scheme as satsgate-proxy 0.8.0. L402 `Authorization`, hop-by-hop headers, and client `X-Satsgate-*` headers are removed. The origin is https only. Redirects are not followed, including same-origin redirects. The body is read in chunks up to a cap and is not stored. Responses set `Cache-Control: no-store`. Each forward resolves DNS again and connects to that public IP, so a later private answer (DNS rebinding) is not used. Private, loopback, link-local, CGNAT, and metadata addresses are rejected.
- Docker Compose passes `SATSGATE_SITE_SECRET_KEY`, `SATSGATE_SITES_AUTO_APPROVE`, `SATSGATE_SITES_MAX_PER_ACCOUNT`, `SATSGATE_SITES_MAX_ROUTES`, and `SATSGATE_GATE_PUBLIC_BASE` into the core service. A local override file is no longer required for those five. The `gate` service has no published port. The Caddyfile rejects `/internal/*` on the API host and includes a commented site block for `gate.satsgate.org`. Both blocks strip `X-Satsgate-Buyer-Ip`.

`GET /health` reports `0.11.0`. `GET /healthz` on the gate reports `0.11.0`. The self-hosted proxy stays 0.8.0. satsgate-mcp stays 0.9.1. The public paywall, top-up, and site registry routes behave as in 0.10.0. Internal routes answer 404 until `SATSGATE_GATE_TOKEN` is set. The gate hostname is not served until its Caddy block is uncommented.

No database migration. Startup does not alter existing tables.

## [0.10.0] - 2026-10-18

### Added
- Sites registry for the hosted-proxy closed beta. A merchant registers a slug, an https origin, and routes (`price_sats`, optional `max_uses` and `access_seconds`, the same policy as 0.6.0). The account key can do this, and so can a restricted key with `sites:write` or `sites:read`. The default restricted scope stays `paywall`. New sites start `pending` unless `SATSGATE_SITES_AUTO_APPROVE=1`. An operator with `SATSGATE_ADMIN_TOKEN` approves or disables them. `GET /v1/sites` lists approved sites that opted in: gate URL, name, slug, description, and routes. No owner, origin, or secret.
- The origin HMAC secret is generated by the server, returned once on create and rotate, and stored as ciphertext under `SATSGATE_SITE_SECRET_KEY`. The proxy will need the raw secret to sign `X-Satsgate-Signature`, so it is not a one-way hash.
- Origin URLs are https only. Userinfo, private, loopback, link-local, CGNAT, and metadata addresses are rejected, including DNS answers in those ranges. That check is at registration. The proxy must repeat it on every forward (DNS rebinding).
- `satsgate-mcp` `list_sites` accepts `GET /v1/sites` (`hosted_registry`, `slug`, `routes`, `next_cursor`) and still accepts a local JSON file. The MCP package stays 0.9.1.

`GET /health` reports `0.10.0`. The self-hosted proxy stays 0.8.0. Paywall, top-up, and restricted paywall keys behave as before.

Startup creates empty `sites` and `site_routes` tables. It does not add columns to existing tables. Copy the SQLite file before restart if you want a rollback point. The process still boots when `SATSGATE_SITE_SECRET_KEY` is unset. Set it (`openssl rand -hex 32`) before the first site is created, and keep it. Defaults: 3 sites per account, 20 routes per site, no auto-approve, public base `https://gate.satsgate.org`. The gate is not serving traffic in this release.

## [0.9.1] - 2026-10-18

### Fixed
- `satsgate-mcp` 0.9.1 reads a BOLT11 amount from the human-readable part before the last `1`. That `1` is the bech32 separator. 0.9.0 split on the first `1`, so an amount whose digits contain `1` was wrong: `lnbc210n` (21 sats) was read as 2 BTC, and the budget check refused the invoice. The same misread hit 1, 10, 100, 1000, and 10000 sats. A `p`-suffix millisatoshi amount and an invoice with no amount are unchanged in meaning. The proxy does not decode BOLT11 amounts. Core still uses the `bolt11` library. `GET /health` stays `0.7.0`.
- `python -m satsgate_mcp.manual` polls until the invoice expires. The wait starts at 2 seconds and grows to 15. `--polls` and `--timeout` are optional caps. `--resume PAYMENT_HASH` continues a quote or token already stored in `SATSGATE_MCP_DATA_DIR`. If polling stops, the process prints that resume command. Status lines carry a UTC timestamp. 0.9.0 stopped after 40 polls (about four minutes), which was before a person scanning the QR had paid.

## [0.9.0] - 2026-10-17

### Added
- `satsgate-mcp` 0.9.0, a buyer-side MCP server in `mcp/`. An agent can `discover` or `quote` a URL, read the 402 L402 challenge (price, `max_uses`, `access_seconds`, expiry), and `pay_and_fetch`. Human pay returns the BOLT11 invoice and a QR, then `check_payment` polls the no-preimage path and retries with the macaroon. NWC pay reads `SATSGATE_MCP_NWC_URI` from the environment only. Per-payment and rolling 24-hour caps refuse anything above them. A local sqlite cache reuses a token that still has uses or time left. A fresh `token_used_up` is quoted again and is not paid unless `SATSGATE_MCP_AUTO_PAY` is on and the new invoice is inside the budget.
- Read-only merchant tools when `SATSGATE_MCP_API_KEY` is a restricted `sgr_` key: `challenge_status` (`consume=false`) and `credits_balance`. Core still refuses balance for a restricted key. There are no write tools. `list_sites` reads a JSON file or URL from `SATSGATE_MCP_REGISTRY`. A hosted registry is not part of this release.
- `mcp/scripts/mainnet_l402_clients.py` and `mcp/scripts/fetch402.mjs` for a manual check that a live proxy 402 matches lnget and Alby fetch402. CI checks the same parsers against the proxy's 402 header and does not pay.

### Changed
- The proxy 402 JSON now includes `max_uses` and `access_seconds` from the route (null when that side of the policy is unset). Payment behaviour is unchanged. The core API stays 0.7.0. `GET /health` on the core still reports `0.7.0`. The proxy `GET /healthz` still reports `0.8.0`.

No database migration. The MCP ledger and token cache are a new sqlite file on the buyer's machine.

## [0.8.0] - 2026-10-17

### Added
- `satsgate-proxy` 0.8.0, a self-hosted reverse proxy in `proxy/`. A merchant runs it beside an existing HTTP API. It calls this core with a restricted `sgr_` key (default `https://api.satsgate.org`). The merchant does not write paywall code. YAML sets the upstream, routes (`per_request`, `uses:N`, `pass:<seconds>`, scope `route` or `site`), free paths, limits, and secrets via the environment.
- Unpaid requests are HTTP 402 with `WWW-Authenticate: L402 macaroon="...", invoice="..."` (the same header lnget and Alby `fetch402` parse) plus a JSON body for the no-preimage poll. `Authorization: L402 <macaroon>:<preimage>` verifies with `consume=true`. `Authorization: L402 <macaroon>` polls status with `consume=true`. Pending is HTTP 402 `payment_pending` with `Retry-After` and does not mint another invoice. A used, expired, or wrong-route token is a fresh 402, not 401.
- The proxy sends `X-Satsgate-Buyer-Ip` when the buyer address is a real IP. Hosted core counts it only when the proxy's egress IP is in `SATSGATE_TRUSTED_PROXIES` and the edge does not delete the header. Otherwise the header is ignored and per-buyer limits do not apply.
- Paid requests are forwarded with `X-Satsgate-Signature` (HMAC-SHA256 of `{unix}|{METHOD}|{raw path and query}|{payment_hash}`) and `X-Satsgate-Payment-Hash`, `X-Satsgate-Resource`, `X-Satsgate-Paid-Sats`. Client `X-Satsgate-*` and L402 `Authorization` are stripped. Redirects are not followed. Origin checks ship for FastAPI, Express, and nginx, plus a Caddy note and a docker-compose example.
- Startup warns when a `per_request` price is below 10 times `pricing.sats_per_credit` (default 5, so 50 sats). Cheap calls should be a bundle or a pass.

### Security
- The proxy consumes a use before it calls the origin, so two requests cannot both be forwarded on one remaining use. If the origin then times out, redirects, or exceeds the size cap, that use is spent. Credits are not refunded: Lightning sats go to the merchant, and the credit is charged once per `payment_hash` on first settlement.
- Upstream credentials are read from the environment and are not logged. Origin responses drop `Server`, `Via`, `X-Powered-By`, and `Location`. A 3xx becomes HTTP 502 with no `Location`.

The core API stays 0.7.0. `GET /health` on the core still reports `0.7.0`. `GET /healthz` on the proxy reports `0.8.0`. No database migration.

## [0.7.0] - 2026-10-17

### Added
- `X-Satsgate-Buyer-Ip` on `POST /v1/paywall/challenge`. A trusted proxy (the TCP peer is in `SATSGATE_TRUSTED_PROXIES`, the same rule as `X-Forwarded-For`) can name the end buyer. Any other peer can send the header and it is ignored, so existing callers are unchanged. The response says `buyer_ip_accepted`.
- Per-buyer limits inside one client: `SATSGATE_BUYER_CHALLENGE_MAX` (default 10 per `SATSGATE_RL_WINDOW_SECONDS`) and `SATSGATE_BUYER_MAX_OPEN_CHALLENGES` (default 5 unpaid challenges still inside the claim window). `0` disables that limit. HTTP 429 `buyer_rate_limited` or `too_many_open_challenges_for_buyer`, with `Retry-After`. The account cap remains `too_many_open_challenges` and now also sends `Retry-After`.
- `SATSGATE_BUYER_LIMIT_SCOPE=client` (default) shares a buyer's budget across the account's keys. `key` gives each restricted key its own budget. The account key is its own bucket in that mode.
- `SATSGATE_CHALLENGE_REUSE_SECONDS` (default 30, `0` disables). An identical unpaid challenge for the same buyer, resource, amount, usage policy, payee, and key returns the same invoice (`reused: true`) instead of minting another one. The macaroon is signed again for that invoice. Retries do not call the LNURL provider.
- Python SDK `0.6.0`: `paywall_challenge(..., buyer_ip=)`.

### Security
- The buyer address is not stored. The challenge row keeps HMAC-SHA256 of the truncated address (IPv4 /24, IPv6 /64), keyed by the macaroon secret. The digest is removed with the row, on the existing challenge cleanup. A /24 or /64 shares one bucket.
- The header cannot move a buyer into a bucket unless the connection comes from a configured trusted proxy. The shipped Caddyfile deletes `X-Satsgate-Buyer-Ip` on public requests, because Caddy is that trusted peer. Forward the header only from the paywall proxy.

### Changed
- `GET /health` reports `0.7.0`.
- Caps are checked before the LNURL call, and again in the insert transaction, so a buyer at the limit does not ask the payee's provider for an invoice. Two concurrent inserts cannot both take the last unpaid slot.

### Migration
Restart the process to serve 0.7.0. Startup adds nullable `paywall_challenges.buyer_ip_hash` and an index on `(client_id, buyer_ip_hash, created_at)`. Existing rows stay unlimited. Copy the SQLite file first if you want a rollback point. No environment variable is required. Leave the new settings unset to keep the defaults above.

## [0.6.0] - 2026-10-17

### Added
- Per-challenge usage policy. `POST /v1/paywall/challenge` accepts optional `max_uses` (1 to 100000) and `access_seconds` (1 to the server cap). Omit both and the payment behaves as before: a settled token can be verified again without consuming a unit.
- `consume=true` on `POST /v1/paywall/verify` and `GET /v1/paywall/status/{payment_hash}` atomically takes one use and returns `uses_remaining`, `uses_consumed`, `access_until`, `settled_at`, and `consumed`. The check is one SQLite transaction, so two callers cannot both take the last use. Omit `consume` to read that state without changing it. Each `consume=true` is one use, including a retry after a lost response.
- `access_seconds` starts at the first settled unlock. A `max_uses` bundle that omits `access_seconds` still ends at the server cap (default 7 days) and that deadline is stored in `access_until`. Responses name it so a proxy can see when the grant dies.
- Exhausted and expired consumes return HTTP 401 `token_used_up` or `token_expired`, with `uses_remaining` and `access_until`, so the client can mint a new challenge. A non-consuming check of that same payment still returns HTTP 200.
- Python SDK `0.5.0`: `paywall_challenge(..., max_uses=, access_seconds=)`, `paywall_verify(..., consume=)`, `poll_paywall(..., consume=)`. A policy grant is not stored in the SDK cache.

### Changed
- Credits are still charged once per `payment_hash`, on the first settled unlock, including when that call also consumes a use. Later uses and the 401s above charge 0.
- `GET /health` reports `0.6.0`.
- Optional `SATSGATE_PAYWALL_ACCESS_CAP_SECONDS` (default `604800`, minimum `60`, maximum `604800`) shortens the longest pass. Leave it unset to keep 7 days.

### Security
- A settled macaroon is no longer an unlimited replay for the whole claim window when the merchant set a policy. The counter and `access_until` live in SQLite, shared by every replica that uses that database file. Writers wait up to 30 seconds for the lock.
- Restricted keys can create these challenges and consume uses. `resource_prefix` still applies. A restricted key still cannot change the payee or top up.

### Migration
Restart the process to serve 0.6.0. Startup adds nullable `paywall_challenges.max_uses`, `access_seconds`, `settled_at`, and `access_until`, plus `uses_consumed` (default 0). Existing rows stay unlimited. Copy the SQLite file first if you want a rollback point. No environment variable is required.

## [0.5.0] - 2026-10-17

### Added
- Restricted API keys. The account key (`sg_...`, from top-up) can `POST /v1/api-keys`, `GET /v1/api-keys`, and `POST /v1/api-keys/{key_id}/revoke`. A new key is returned once, stored as a SHA-256 hash, and starts with `sgr_` so it is distinguishable from the account key. Each key has a label, `created_at`, `last_used_at` (updated at most once a minute), and `revoked_at`.
- An optional `resource_prefix` limits that key to paywall resources that start with the prefix (case-sensitive). Omit it to allow every resource. Up to 50 active restricted keys per client.
- A restricted key can `POST /v1/paywall/challenge`, `GET /v1/paywall/status/{payment_hash}`, and `POST /v1/paywall/verify`. It cannot top up, set or change the payee (including on the first challenge), create or revoke keys, or read balance, client, ledger, or usage.
- Paywall debits record `api_key_id` and `resource`. `GET /v1/ledger` adds `api_key_id`, `api_key_label`, `api_key_prefix`, and `resource`. Null `api_key_id` means the account key. `GET /v1/usage/summary` adds `summary.by_api_key`.
- Python SDK `0.4.0`: `create_api_key`, `list_api_keys`, `revoke_api_key`.

### Security
- A leaked restricted key cannot redirect payouts or mint another key. Revocation is checked on every request (`api_key_revoked`). Forbidden account calls return HTTP 403 `insufficient_scope`. A resource outside the prefix returns HTTP 403 `resource_not_allowed`.
- The account key is unchanged. Existing `sg_` keys keep full access. Unknown account keys on top-up stay anonymous, as before. A presented `sgr_` key is never treated as anonymous.

### Migration
No new environment variables. Restart the process to serve 0.5.0. Startup adds the `api_keys` table and nullable `ledger.api_key_id`, `ledger.resource`, and `paywall_challenges.api_key_id` columns. Existing rows are left in place. Copy the SQLite file first if you want a rollback point. Nothing else has to be configured.

## [0.4.2] - 2026-10-17

### Fixed
- A paywall macaroon no longer expires at `SATSGATE_TOKEN_TTL_SECONDS` (default 10 minutes) while the payee's Lightning invoice is still payable. Paying an Alby invoice hours later, then `GET /v1/paywall/status/{payment_hash}` or `POST /v1/paywall/verify`, unlocks the challenge. The macaroon `exp` is the invoice expiry plus a grace window (default 1 hour), and never later than 48 hours after the challenge was created. This is the same claim window top-ups got in 0.4.1.
- A paywall token already issued with that 10-minute `exp` can still unlock while the invoice window is open. Rows written before 0.4.2 stored the token TTL in `expires_at`; the BOLT11 expiry is used when it is later. Signature, client, resource, amount, payee, and invoice bindings are unchanged. A first unlock still requires a preimage or a stored LUD-21 `verify` response that carries a matching preimage. After the window the route returns `invoice expired` and does not spend a credit, including when the macaroon `exp` has not passed and including when the provider would report the invoice settled.

### Added
- Challenge responses add `invoice_expires_at`, `claim_until`, `cache_until`, `payee_saved`, and `payee_note`. `valid_until` stays and, for a new token, equals `claim_until` (the macaroon expiry). `cache_until` is how long to cache a successful unlock. How long the buyer may use the product is the merchant's decision.
- Unlock responses add `claim_until`, `invoice_expires_at`, and `cache_until`. `valid_until` stays the macaroon `exp` caveat, which can be earlier than `claim_until` for a token minted before this release.
- The first challenge that includes `payee_lightning_address` still saves it. The response now says so (`payee_saved: true`, `payee_note`). A later different address returns `payee_mismatch` with the saved address and `POST /v1/client/payee` as the way to change it.
- `resource mismatch` includes `detail`, the caller's `expected_resource`, and, after the macaroon is verified for this API key, the issued `resource`. Another client's token still returns `client mismatch` without that resource.
- Pending unlocks name the charge: `charged_credits: 0` until settlement. Verify's HTTP 402 `payment_pending` body also includes `status: pending`. Status stays HTTP 200 `pending`. Both notes describe the other route. Settled responses keep `charged_credits` and state that verify and status share one debit per `payment_hash`.
- Python SDK `0.3.1` reads the new fields and caches until `cache_until`.

### Changed
- `ttl_seconds` on `POST /v1/paywall/challenge` is the minimum invoice lifetime. It no longer shortens the macaroon below the invoice claim window.
- `GET /health` reports `0.4.2`.
- Optional `SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS` (default `172800`, max `604800`) and `SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS` (default `3600`, max `86400`). The grace cannot exceed the cap. Neither is required. Dev-ticket macaroons still use `SATSGATE_TOKEN_TTL_SECONDS`.

### Security
- Credits are still not spent without a preimage or a stored LUD-21 `verify` response that carries a matching preimage. The claim cap and the grace window bound how long a macaroon can unlock a payment. A replay after the first debit spends 0.

## [0.4.1] - 2026-10-17

### Fixed
- A top-up macaroon no longer expires at `SATSGATE_TOKEN_TTL_SECONDS` (default 10 minutes) while the Lightning invoice is still payable. Paying an Alby invoice hours later, then `GET /v1/topup/status/{payment_hash}` or `GET /v1/topup/{plan_id}` with the preimage, credits the account. The macaroon `exp` is the invoice `expires_at` the service already stores, plus a grace window (default 1 hour) so a payment made near expiry can still be polled, and never later than 48 hours after the row was created.
- A top-up token already issued with that 10-minute `exp` (0.4.0 macaroon or in-flight 0.3.0 JSON) can still complete while the ledger row is pending and that server-side window is open. The macaroon signature, the invoice/amount/payee bindings, and proof of payment are unchanged.

### Security
- Credits are still not issued without a preimage or a stored LUD-21 `verify` response that carries a matching preimage. After `expires_at` plus the grace window, or after the cap, the claim returns `invoice expired` and does not credit, including when the macaroon's own `exp` has not passed and including when the provider would report the invoice settled.
- Paywall and dev-ticket macaroons keep `SATSGATE_TOKEN_TTL_SECONDS` (or the paywall request's `ttl_seconds`). An expired paywall token still returns `token expired`.

### Changed
- `GET /health` reports `0.4.1`.
- Optional `SATSGATE_TOPUP_TOKEN_TTL_CAP_SECONDS` (default `172800`, max `604800`) and `SATSGATE_TOPUP_CLAIM_GRACE_SECONDS` (default `3600`, max `86400`). The grace cannot exceed the cap. Neither is required.

## [0.4.0] - 2026-10-17

### Added
- Top-ups, paywall unlocks, and dev-only tickets can finish without a preimage when the LNURL-pay provider returned a LUD-21 `verify` URL (Alby does). Poll `GET /v1/topup/status/{payment_hash}` or `GET /v1/paywall/status/{payment_hash}` with `Authorization: L402 <macaroon>` and no preimage. The same macaroon-only header is accepted on `GET /v1/topup/{plan_id}`, `POST /v1/paywall/verify`, and `GET /v1/tickets`.
- The new account's API key is returned only by the request that creates it. A replay is idempotent: it does not credit again and does not show the key. The macaroon (not the payment hash) is the claim.
- Python SDK `0.3.0`: `poll_topup` and `poll_paywall` for that pay-from-any-wallet flow.
- New tokens are libmacaroons V2 macaroons, standard base64, with an L402 v0 identifier (so lnget can read the payment hash) and caveats for the existing v2 bindings. `Authorization` accepts `L402` and legacy `LSAT`.

### Changed
- In production, `/openapi.json` and `/docs` omit `/v1/admin/*`, `/v1/tickets`, `/v1/spend`, and `/dev/mock/pay`. Those routes still behave as before.
- `GET /health` reports `0.4.0`.

### Fixed
- `GET` and `HEAD` for `/health` and `/.well-known/satsgate.json` no longer share one OpenAPI operation id.
- LNURL-pay invoice requests no longer send a LUD-12 `comment` unless `SATSGATE_LNURL_SEND_COMMENT=1` and the provider advertises `commentAllowed`. Alby puts that comment in the BOLT11 description and omits `description_hash = SHA256(metadata)`, which challenge and top-up routes rejected (`invoice_rejected` / `description_hash_mismatch`). The description-hash check stays strict.
- Docker Compose assigns the app container `172.28.0.3` so it cannot take Caddy's pinned address `172.28.0.2` (`Address already in use`). The app service checks `GET /health`.

### Security
- Auto-confirm reads only the verify URL stored with the invoice, checks it again with the SSRF guard, and credits only when the provider returns a preimage that hashes to that invoice. A caller cannot pass a verify URL. `settled: true` without that preimage does not credit.
- In-flight v2 JSON tokens from 0.3.0 still verify until they expire. v1 tokens stay rejected. Client, resource, amount, payee, and invoice bindings are unchanged.

### Migration
No new environment variables. Restart the process to serve 0.4.0.

Buyers on a provider that advertises LUD-21 `verify` can pay the invoice from any wallet and poll. Wallet of Satoshi does not advertise `verify`; those payments still need `Authorization: L402 <macaroon>:<preimage>`.

HTTP clients that pass the macaroon through unchanged (the Node demos, lnget, Alby `fetch402`) keep working. Code that decodes the old JSON token locally, including satsgate-sdk `0.2.0`, should upgrade to satsgate-sdk `0.3.0`.

## [0.3.0] - 2026-10-16

### Security
- Paywall tokens are now **v2**. The signed payload is `{v, kid, purpose, cid, ph, res, amt, payee_h, inv_h, exp, nonce}`. `/v1/paywall/verify` rejects a token whose `cid` is not the calling client, whose resource does not match, or whose invoice/amount/payee binding does not match the challenge satsgate issued. v1 tokens are rejected.
- `expected_resource` is required on `/v1/paywall/verify` (HTTP 422 when it is omitted).
- BOLT11 invoices from LNURL-pay are checked before a challenge is returned: amount, mainnet (or `SATSGATE_LN_NETWORK`), `description_hash` = SHA256 of the LUD-06 metadata string, expiry covering the token TTL, and a 32-byte payment hash. The decoder also checks the invoice signature.
- LUD-21 `verify` is used as an extra settlement check only when the provider includes it. Wallet of Satoshi does not; those payees stay preimage-only.
- Outbound LNURL fetches are https-only, DNS-checked, and pinned to a public address. Private, loopback, link-local, and CGNAT targets are refused, redirects are not followed, and responses are capped at 5s and 64 KiB.
- The process refuses to start when `SATSGATE_ENV` is production (the default) and the signing secret is empty, `dev-change-me`, or shorter than 32 bytes, or when dev mode or the mock wallet is enabled. `/dev/mock/pay`, `/v1/tickets`, and `/v1/spend` exist only in an explicit local environment with `SATSGATE_DEV_MODE=1`.
- `/health` returns only `{ok, version}`.
- Rate limits use the TCP peer unless that peer is listed in `SATSGATE_TRUSTED_PROXIES`. Unknown API keys share the IP bucket. The in-memory limiter caps how many keys it tracks. Pending top-ups per IP and open challenges per client are capped.
- `bitstring` is pinned to 4.x so `bolt11` can import (`ConstBitStream` was removed in bitstring 5).

### Changed
- Verify responses add `amount_sats` and `payee_lightning_address`. Challenge responses add `token_version`.
- Signing keys can be rotated with `SATSGATE_MACAROON_KEY_ID` and `SATSGATE_MACAROON_PREVIOUS_KEYS` (JSON object of retired kid → secret, verify-only).
- Python SDK `0.2.0`: `paywall_verify` requires `expected_resource` and rejects tokens that are not v2.

### Migration
There are no production clients to migrate. Outstanding v1 tokens stop verifying immediately (they were unbound bearer credentials). Integrators must send `expected_resource` on every verify. Copying the old `.env` with `SATSGATE_MACAROON_SECRET=dev-change-me` or `SATSGATE_DEV_MODE=1` will not boot under the default `SATSGATE_ENV=production`. Local mock:

```bash
SATSGATE_ENV=development SATSGATE_DEV_MODE=1 SATSGATE_WALLET_MODE=mock \
  SATSGATE_MACAROON_SECRET=local-dev-only \
  uvicorn app.main:app --reload --port 8000
```

`cost_credits` is unchanged: the authenticated merchant still chooses how many of their own credits a verification spends (default 1). That value is not part of the cross-tenant bypass.

## [0.2.0] - 2026-03-06

### Added
- L402 paywall endpoints (challenge/verify) with prepaid credits (plans)
- Operator reporting: ledger, usage summary, daily series, forecast + recommended purchase + trigger
- `.well-known/satsgate.json` discovery manifest + OpenAPI
- Docker + Caddy deployment configuration
- Python SDK (`satsgate-sdk`) + FastAPI examples (minimal + reference)
- CI smoke tests (mock mode)
- Trust layer docs: `SECURITY.md`, `SUPPORT.md`, `STATUS.md`, `BETA.md`

### Changed
- Improved onboarding UX in SDK examples (handle missing payee without returning 500)

### Security
- SSH hardening and access guidance documented (operator runbook is private)
