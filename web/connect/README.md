# Connect wallet

This page is how a merchant proves an EVM address for USDC on Base. It connects a browser extension (EIP-6963 / injected) or a mobile wallet (WalletConnect QR on a computer, deep links on a phone) and asks for one `personal_sign`. It does not send a transaction, ask for a seed phrase, or see the account API key.

The link is created with the account key:

```bash
curl -s -X POST https://api.satsgate.org/v1/client/payee/evm/connect \
  -H 'X-Api-Key: sg_...'
```

The response `connect_url` has the token in the fragment (`#t=sgc_…`). The page reads it once, removes the fragment, and keeps it in memory. Refreshing the tab forgets the link.

## Build

From this directory, on a machine with Docker:

```bash
./build.sh
```

That runs `npm ci && npm run build` inside `node:22-alpine`. The output is `dist/`. Satsgate-prod does not need Node installed. Copy or mount `dist/` read-only at `/srv/connect` (Compose does this).

CI builds the same way with Node 22: `npm ci && npm test && npm run build`. There is no Playwright job. A headless browser check of the modal would add a heavy browser install and still could not prove WalletConnect without the real project ID.

## Local run

```bash
npm ci
npm test
npm run dev
```

Create `public/config.json` (gitignored) with a 32-character hex `projectId` if you want the button to enable. Do not put the real Reown project ID in the repo. The dev server proxies `/v1/connect` to `http://127.0.0.1:8000`.

Production does not use that file. Caddy responds to `/connect/config.json` from `SATSGATE_REOWN_PROJECT_ID`.

## Versions

Pinned in `package.json`:

- `@reown/appkit` 1.8.24
- `@reown/appkit-adapter-ethers` 1.8.24
- `ethers` 6.17.0 (the adapter accepts ethers 6)
- `vite` 7.3.7

`metadata.url` is `https://satsgate.org`. The icon is `/connect/icon.svg` on the same origin. Networks are Base only. The page does not ask the wallet to switch chain before `personal_sign`. Coinbase Wallet is set to `eoaOnly`. Email, social login, onramp, swaps, send, history, and analytics are off.

## CSP

The Caddyfile starts from Reown's published AppKit policy and keeps `script-src 'self'` (no `unsafe-eval`). `style-src` adds `'unsafe-inline'` because this AppKit version inserts `<style>` elements for its theme. `connect-src` adds `https://walletguide.walletconnect.network` (the wallet list), `https://mainnet.base.org` (the Base RPC in the pinned viem chain), and the Coinbase hosts the pinned wallet SDK calls. `img-src` includes `*` because that is what Reown publishes for wallet icons. `frame-ancestors` is `'none'`.
