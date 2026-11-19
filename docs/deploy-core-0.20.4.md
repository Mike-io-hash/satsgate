# Deploy core 0.20.4

This note is for a later deploy. It is not an authorization to deploy. Do not run it from this pull request. The maintainer runs it only after the release approver's separate deploy approval. Nothing is published. Auto-approve stays off. Do not change `SATSGATE_TERMS_VERSION`. The Lightning node is not restarted. The reference account is read-only; its balance must not change.

## Preconditions

- `main` includes this pull request and CI is green.
- A separate deploy approval has been given.
- `SATSGATE_TERMS_VERSION` stays `2026-11-13`.
- `SATSGATE_SITES_AUTO_APPROVE` stays off.
- The Lightning node is not restarted, and the reference account stays read-only.
- Nothing is published.

## Steps

1. **Backup.** Copy the sqlite file, the Caddyfile, and the compose file to `/opt/satsgate/backups` as `pre-0.20.4_<UTC stamp>`. Tag the running core image `satsgate-satsgate:pre-0.20.4`. Keep `pre-0.20.3`.

2. **Checkout.** Fast-forward the server checkout to the merged main. Confirm with `git diff --stat <old> <new> -- Caddyfile docker-compose.yml Dockerfile requirements.txt` that none of them changed. If one did, stop: this note does not cover it. Run `scripts/build_terms.py --check`.

3. **Core.** Rebuild and replace only the core container (`docker compose build satsgate`, then `docker compose up -d --no-deps satsgate`). Expect a few seconds of cut on the API host. The gate and `demo-seller` are not rebuilt or recreated.

   The Caddy container is not rebuilt or recreated.

4. **Smoke, no real money.**
   - Health reports core 0.20.4 and gate 0.15.2.
   - `/openapi.json` has `info.version` 0.20.4, and both descriptions contain "millisatoshis".
   - `/docs` is 200.
   - `/terms` is 200 with `Cache-Control: no-store`.
   - `/terms/2026-11-13` is 200 with a one-year cache.
   - `/connect` is 200.
   - A random path is 301 to GitHub.
   - `GET /v1/rates` has `source=oracle` or `source=fallback` and names no rate source.
   - The reference account balance is unchanged.
   - Watchdogs are ok.

5. **Rollback.** Retag `pre-0.20.4` as the running image and run `docker compose up -d --no-deps satsgate`. There is no migration to reverse. Restore the database only if no payment entered after the backup.
