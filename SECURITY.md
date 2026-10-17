# Security Policy

## What verify actually checks

A paywall token is a macaroon. Its caveats are the v2 bindings (`v`, `kid`, `purpose`, `cid`, `ph`, `res`, `amt`, `payee_h`, `inv_h`, `exp`), and the identifier is the L402 v0 payment-hash form. In-flight 0.3.0 tokens, which were an HMAC over that same JSON payload, still verify until they expire. Verification requires all of the following:

- The signature matches the current signing key, or a retired key listed in `SATSGATE_MACAROON_PREVIOUS_KEYS` under its `kid`.
- `cid` is the client id of the API key calling `/v1/paywall/verify`. A token issued for one merchant does not verify for another, so a 1-sat invoice paid to the attacker's own Lightning Address cannot unlock someone else's resource or spend their credits.
- `expected_resource` is present and equals the resource in the token.
- The token's amount, payee hash, and invoice hash match the challenge row satsgate stored when it fetched the invoice.
- Either the caller presents a preimage that hashes to the payment hash, or (only when the stored LUD-21 `verify` URL exists) that URL returns a preimage that hashes to it. The URL is the one saved at invoice time. Callers cannot substitute their own. A response of `settled: true` without that preimage does not credit. If the provider omitted `verify`, the preimage is the only settlement proof. That is expected for Wallet of Satoshi.
- The macaroon is what authorizes a claim. Knowing the payment hash is not enough, a second claim does not credit again, and the new API key is returned only once.

The invoice itself is checked at challenge time (amount, network, description hash, expiry, payment hash). LNURL callbacks are fetched with an SSRF guard: https only, public addresses only, no redirects, 5 second timeout, 64 KiB cap.

Production startup refuses the default signing secret, secrets shorter than 32 bytes, `SATSGATE_DEV_MODE=1`, and `SATSGATE_WALLET_MODE=mock`. `/health` does not return the database path, the Lightning Address, or the wallet mode.

These checks do not make a malicious Lightning Address provider honest. The provider still chooses the invoice destination. They stop a provider (or a misconfigured payee) from returning an invoice for a different amount, network, or description, and they stop one satsgate client from redeeming another client's token.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub Security Advisories:

- Go to: https://github.com/Mike-io-hash/satsgate/security/advisories
- Click **"Report a vulnerability"**

If you are unable to use GitHub Security Advisories, you may open a minimal issue that says
"I have a security report" and we will follow up privately.

## Supported Versions

This project is currently in **beta**. Only the latest `main` branch is supported.

## Disclosure

We aim to acknowledge reports within **72 hours**.
