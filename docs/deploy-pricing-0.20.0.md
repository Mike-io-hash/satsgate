# Deploy notes for core 0.20.0

This file is for a later deploy. The coding change does not run it. Do not SSH, do not set production env, do not publish packages, do not restart Alby Hub, and do not write to Client 1's live database from the agent that opened the pull request.

When a separate OK exists:

1. Announce a short window if needed. Prefer to keep verify and receipt honouring up.
2. Back up the production database file and any WAL. Record size, sha256, and row counts (`clients`, `ledger`, `topups`, `SUM(credits)`). Tag the running commit. Do not restore that backup after new buyer payments have landed.
3. Copy the backup. Run `python -m app.migrate_credits_to_msat --db COPY --dry-run` then `--apply` on the copy. Check every `balance_msat = old_credits * 2000`, the ledger invariant, and Client 1's live credit count re-read at cut-over (it was 576 on 12/11, which would be 1,152,000 msat).
4. Deploy core 0.20.0. The gate stays 0.15.2. Set the new env vars at their defaults. Set `SATSGATE_TERMS_VERSION` to the effective date chosen at deploy. Leave `SATSGATE_SITES_AUTO_APPROVE` off. Check `/health` and a test-mode unlock.
5. Apply the conversion on production only after the copy was clean, and only with an explicit OK for this step. If it fails, stop. Restore the backup only if no new payments were accepted.
6. Smoke: signup or a staging equivalent, a Lightning top-up on a test account, a live challenge refused at zero, a test-mode challenge at zero, `410` on `/v1/topup/trial`, and the `/v1/plans` shape.
7. Rollback: code reverts to 0.19.1. Data `--reverse` only if every milisat value is still a multiple of 2,000. Otherwise restore the snapshot from step 2, and only if that does not erase buyer payments accepted after the snapshot.
8. The public headline and the terms go live with this deploy, once. Package publication is a later OK.
