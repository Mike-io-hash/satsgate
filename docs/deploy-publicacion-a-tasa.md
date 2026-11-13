# Deploy Publicación A (core 0.20.1)

This note is for a later deploy. It is not an authorization to deploy. The coding change does not SSH, set production environment, restart anything, or publish packages.

When the operator later has a separate OK:

1. **Backup.** Snapshot the production database and its WAL to a dated copy that the next nightly backup will not overwrite. Record size, sha256, and row counts for `clients`, `ledger`, `topups`, and `payment_offers`, and re-read Client 1 `balance_msat` at cut-over (1,152,000 msat was the figure on 13/11 14:18 ART). This release has no schema migration. The backup is still required. Do not restart Alby Hub. Do not restore that snapshot after new buyer payments have landed.

2. **Tag the running image** before replacing it: `satsgate-satsgate:pre-0.20.1`, pointing at the current 0.20.0 image. Leave `satsgate-satsgate:pre-0.20.0` (0.19.1) in place. Do not rebuild the gate if it is still 0.15.2. Record the running commit.

3. **Build and deploy only the core.** The old accounting vendor key stays absent. `SATSGATE_BASE_RPC_URL` already defaults to `https://mainnet.base.org`. `SATSGATE_BASE_RPC_FALLBACK_URL` stays empty unless a second URL was chosen. Auto-approve stays off. `SATSGATE_TERMS_URL` stays empty. Balances are already in msat. There is no conversion step.

4. **Health.** `GET /health` reports core 0.20.1 and the gate still 0.15.2. Logs for the new quote say `primary` or `fallback` and an as-of integer. They do not name a vendor or a backup venue, and they do not print the RPC URL. Alby Hub's start time stays the 17/10 04:15Z baseline.

5. **Smoke, with no payment.**
   - `GET /v1/rates` is 200, with a numeric `value` (or `unavailable` if both reads are actually down, which stops the smoke). There is no `sources` field and no venue name. `source` is `oracle` or `fallback`.
   - `POST /v1/topup/usdc` on a disposable account, not Client 1, for US$1, unpaid: 402 with a locked `msat_credit` and a rate object that does not name a venue, or 503 `rate_unavailable` if the quote is genuinely down. Do not retry with a guessed amount.
   - Off the public record, compare the primary value with the internal backup. A large unexplained gap stops the deploy. Do not publish that comparison.
   - Generate a Lightning invoice and do not pay it. A live Lightning-priced challenge still issues when the seller has quota or balance.
   - Retired pack URLs stay 410. `/v1/plans` stays model B. Repeat the geoblock and sanctions smoke from the 0.20.0 deploy. Client 1's balance is unchanged.

6. **Rollback.** Code: `satsgate-satsgate:pre-0.20.1` (0.20.0). There is no reverse balance conversion. If the database was not migrated, the previous image is enough. If an unexpected write happened, restore the snapshot from step 1 only when no new buyer payment landed after it. 0.20.0 will use the previous accounting vendor again. That is the known rollback trade-off for a short window.

7. **After smoke.** Report the `/v1/rates` body, the unpaid USDC quote, Client 1's unchanged msat balance, and whether the quote was `oracle` or `fallback`.
