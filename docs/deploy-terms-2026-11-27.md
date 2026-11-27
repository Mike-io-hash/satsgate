# Deploy hosted-gate terms 2026-11-27

This note is for a later deploy. It is not an authorization to deploy. Do not run it from this pull request. The maintainer runs it only after a separate deploy approval. Nothing is published. Auto-approve stays off. The Lightning node is not restarted. The reference account is read-only; its balance must not change.

Core stays 0.20.4. Do not rebuild the core image unless the diff in step 2 shows a change in `Caddyfile`, `docker-compose.yml`, `Dockerfile`, or `requirements.txt`. Those files should not change for this deploy. If one did, stop.

## Preconditions

- `main` includes this pull request and CI is green.
- A separate deploy approval has been given.
- `SATSGATE_SITES_AUTO_APPROVE` stays `0`.
- `SATSGATE_TERMS_URL` stays `https://satsgate.org/terms`.
- The Lightning node is not restarted, and the reference account stays read-only.
- Nothing is published. Core stays 0.20.4 and the hosted gate stays 0.15.2.

## Steps

1. **Backup.** Copy the sqlite file, the Caddyfile, the compose file, and the env file to `/opt/satsgate/backups` as `pre-terms-2026-11-27_<UTC stamp>`. If `web/terms/dist` exists, copy it under the same name. Do not print secrets.

2. **Checkout.** Fast-forward the server checkout to the merged main. Confirm with `git diff --stat <old> <new> -- Caddyfile docker-compose.yml Dockerfile requirements.txt` that none of them changed. If one did, stop: this note does not cover it. Run `python3 scripts/build_terms.py` so `web/terms/dist/` exists, then `python3 scripts/build_terms.py --check`.

3. **Caddy first.** Recreate Caddy with `docker compose up -d --no-deps --force-recreate caddy`. A reload is not enough: the bind-mounted dist and the Caddyfile are new inodes. Confirm:
   - `/terms` is 200, `Cache-Control: no-store`, the effective date is `2026-11-27`, the contact is present, and there is no draft banner.
   - `/terms/2026-11-27` is 200 with a one-year cache and the same current text.
   - `/terms/2026-11-13` is 200 with a one-year cache and the previous text.
   - `/connect` is 200.
   - A random path is 301 to `https://github.com/Mike-io-hash/satsgate`.

4. **Env and core.** Set only `SATSGATE_TERMS_VERSION=2026-11-27` in the server env file. Leave `SATSGATE_SITES_AUTO_APPROVE` at `0`. Leave `SATSGATE_TERMS_URL` as `https://satsgate.org/terms`. Recreate only the core container with `docker compose up -d --no-deps satsgate` so it reads the env. Use the same 0.20.4 image. Do not rebuild it. Do not recreate the gate. Do not restart the Lightning node.

5. **Smoke, no real money.**
   - `GET /health` reports core 0.20.4.
   - Gate health reports 0.15.2.
   - The well-known `terms_url` is still `https://satsgate.org/terms`.
   - `SATSGATE_TERMS_VERSION` inside the core container is `2026-11-27`.
   - Auto-approve is still `0`.
   - The reference account balance is unchanged.
   - Watchdogs are ok.

6. **Rollback.** Restore the previous terms dist. Force-recreate Caddy with `docker compose up -d --no-deps --force-recreate caddy`. Set `SATSGATE_TERMS_VERSION` back to `2026-11-13` and recreate only core with `docker compose up -d --no-deps satsgate`. There is no database migration to reverse.
