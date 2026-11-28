# Deploy core 0.20.5 and gate 0.15.3

This note is for a later deploy. It is not an authorization to deploy. Do not run it from this pull request. The maintainer runs it only after the release approver's separate deploy approval. Nothing is published. Do not change `SATSGATE_SITES_AUTO_APPROVE` or `SATSGATE_TERMS_VERSION`. The Lightning node is not restarted. The reference account is read-only; its balance must not change.

## Preconditions

- `main` includes this pull request and CI is green.
- A separate deploy approval has been given.
- The server env file is not edited.
- The Lightning node is not restarted, and the reference account stays read-only.
- Nothing is published.

## Steps

1. **Backup.** Copy the sqlite file, the Caddyfile, and the compose file to `/opt/satsgate/backups` as `pre-0.20.5_<UTC stamp>`. Tag the running core image `satsgate-satsgate:pre-0.20.5` and the running gate image `satsgate-gate:pre-0.15.3`. Keep the older tags.

2. **Checkout.** Fast-forward the server checkout to the merged main. Confirm with `git diff --stat <old> <new> -- Caddyfile docker-compose.yml Dockerfile requirements.txt gate/Dockerfile gate/requirements.txt` that none of them changed. If one did, stop: this note does not cover it. Run `scripts/build_terms.py --check`.

3. **Core.** Rebuild and replace only the core container (`docker compose build satsgate`, then `docker compose up -d --no-deps satsgate`). Expect a few seconds of cut on the API host. Gate 0.15.2 reads the new status answer as a missing site, so buyers see the same 404 as before until step 4.

4. **Gate.** Rebuild and replace only the gate container (`docker compose build gate`, then `docker compose up -d --no-deps gate`). `demo-seller` is not rebuilt or recreated.

   The Caddy container is not rebuilt or recreated.

5. **Smoke, no real money.**
   - Health reports core 0.20.5 and gate 0.15.3.
   - `/.well-known/satsgate.json` has the new `description`, `terms_version` equal to the effective terms date, and the same `terms_url` and `abuse_contact`.
   - `/openapi.json` has `info.version` 0.20.5. `/docs` is 200.
   - On the gate, an unknown slug is 404 `not_found`, and a disabled test site is 404 `site_not_active` with a `hint`.
   - An approved test site still answers its 402 with no payment.
   - `/terms` is 200 with `Cache-Control: no-store`. `/connect` is 200. A random path is 301 to GitHub.
   - The reference account balance is unchanged. Watchdogs are ok.

6. **Rollback.** Retag `pre-0.15.3` and `pre-0.20.5` as the running images and run `docker compose up -d --no-deps gate`, then `docker compose up -d --no-deps satsgate`. There is no migration to reverse. Restore the database only if no payment entered after the backup.
