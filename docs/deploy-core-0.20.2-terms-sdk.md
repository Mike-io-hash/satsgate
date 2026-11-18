# Deploy core 0.20.2 (terms page and SDK)

This note is for a later deploy. It is not an authorization to deploy. Do not run it from this pull request. The maintainer runs it only after a separate deploy OK from the release approver, and only after the terms page text has been reviewed. Auto-approve stays off. Do not change `SATSGATE_TERMS_VERSION`. The Lightning node is not restarted. The reference account is read-only; its balance must not change. Do not publish packages.

## Preconditions

- `main` includes this pull request and CI is green.
- The terms HTML and markdown have been reviewed, including the vendor-content sentences.
- A separate deploy OK has been given.
- `SATSGATE_TERMS_VERSION` is already `2026-11-13`. Leave it.
- `SATSGATE_SITES_AUTO_APPROVE` stays off.

## Steps

1. **Backup.** Copy the sqlite file and the current Caddyfile and compose, with the same discipline as the 0.20.1 deploy. Name the copies `pre-0.20.2_…`. Tag the running core image `satsgate-satsgate:pre-0.20.2` and keep `pre-0.20.1`. The gate image stays 0.15.2. Tag it only if a restart will replace that container.

2. **Checkout.** Fast-forward the server checkout to the merged main. Run `python3 scripts/build_terms.py` so `web/terms/dist/` exists. Terms do not need Node. Do not rebuild the connect page unless `web/connect/dist` is missing. Do not refresh it without a reason.

3. **Caddy first.** Superseded: do not `caddy reload`. Later deploys use `docker compose up -d --no-deps --force-recreate caddy` (see `docs/deploy-core-0.20.3.md`). Compose already mounts `/srv/terms` and the Caddyfile already has the terms handles. The historical step reloaded Caddy inside the caddy container, not a restart of the other services, so `/terms` was live before `SATSGATE_TERMS_URL` was set. Confirm `/terms` and `/terms/2026-11-13` are 200, `/connect` is 200, and a random path still 301s to `https://github.com/Mike-io-hash/satsgate`.

4. **Env and core.** Set `SATSGATE_TERMS_URL=https://satsgate.org/terms` on core and on the gate, in the server env file. Do not print the rest of the env. Rebuild and replace only the core container to 0.20.2, with the same short window as 0.20.1. Restart the gate container only so it reads the env. It stays image 0.15.2. Do not rebuild the proxy, demo-seller, or connect unless one of them is required. The Lightning node is not restarted.

5. **Smoke, no real money.**
   - `GET https://satsgate.org/terms` and `/terms/2026-11-13` are 200, show `2026-11-13`, and have no draft banner.
   - `/connect` is 200.
   - `/.well-known/satsgate.json` has `terms_url` equal to `https://satsgate.org/terms`.
   - `GET /v1/plans` has the same `terms_url`. Signup of a throwaway account (not the reference account) returns it on the 201, and `GET /v1/client` returns it for that account.
   - `GET /v1/rates` still has `source` of `oracle` or `fallback` and no `sources` list.
   - The reference account is read-only. Its balance must not change.
   - Health reports core 0.20.2 and gate 0.15.2. Watchdogs are ok.
   - Do not pay leftover Lightning invoices. A live receipt verify and `balance.low` wait for the first real use.

6. **Rollback.** Restore the previous Caddyfile, set `SATSGATE_TERMS_URL` back to empty, and return to the previous core image. The terms dist can stay on disk. There is no database migration to reverse.
