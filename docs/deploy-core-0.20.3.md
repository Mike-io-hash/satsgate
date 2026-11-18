# Deploy core 0.20.3 and the terms cache

Standing rules for every later deploy: a Caddy change is `docker compose up -d --no-deps --force-recreate caddy`. Do not reload Caddy in place. Never restart Alby Hub. Client 1 is read-only. Take a backup and tag the running image before replacing a container.

This note is for a later deploy. It is not an authorization to deploy. Do not run it from this pull request. The maintainer runs it only after the release approver's separate deploy OK. Auto-approve stays off. Do not change `SATSGATE_TERMS_VERSION`. Do not restart Alby Hub. Do not touch Client 1 except to read the balance in the smoke below. Do not publish packages. There is no proxy on the server to redeploy: proxy 0.14.1 and SDK 0.10.0 reach merchants only through the release workflows.

## Preconditions

- `main` includes this pull request and CI is green.
- A separate deploy OK has been given. The live `satsgate init` run in step 7 needs its own OK, separate from the deploy OK.
- `SATSGATE_TERMS_VERSION` stays `2026-11-13`.
- `SATSGATE_SITES_AUTO_APPROVE` stays off.
- Alby Hub and Client 1 stay untouched.
- Nothing is published. The packages stay in the repo.

## Steps

1. **Backup.** Copy the sqlite file and the current Caddyfile and compose to `/opt/satsgate/backups` as `pre-0.20.3_<UTC stamp>`. Tag the running core image `satsgate-satsgate:pre-0.20.3` (that image is 0.20.2). Keep `pre-0.20.2`. Do not rebuild the gate image.

2. **Checkout.** Fast-forward the server checkout to the merged main. Do not rebuild `web/connect` or `web/terms` unless one is missing. Run `scripts/build_terms.py --check` and build the terms page only if that check reports the output is stale.

3. **Core.** Rebuild and replace only the core container, to 0.20.3, with the same short window as 0.20.2. Do not rebuild `demo-seller` (it builds from `sdk/python`; SDK 0.10.0 changes nothing it uses). Do not rebuild the gate. It stays 0.15.2.

4. **Caddy.** The Caddyfile changed. Recreate the container with `docker compose up -d --no-deps --force-recreate caddy`. An unchanged compose file does not recreate the container, and a bind-mounted Caddyfile replaced by git has a new inode. Do not reload Caddy in place. Expect a few seconds where the API, the gate, and the apex are cut. Certificates live in named volumes and are not reissued.

5. **Smoke, no real money.**
   - Health reports core 0.20.3 and gate 0.15.2.
   - `/terms` is 200 with `Cache-Control: no-store`.
   - `/terms/2026-11-13` is 200 with `max-age=31536000`.
   - `/terms/2099-01-01` is 404 and does not send `max-age=31536000`.
   - `/connect` is 200.
   - A random path still 301s to GitHub.
   - `GET /v1/rates` has `source=oracle` or `source=fallback` and does not name a rate source.
   - Client 1's balance, read only, is still 1,152,000 msat.
   - Watchdogs are ok.
   - Do not pay leftover invoices of throwaway clients.

6. **Rollback.** Return to the previous core image (`pre-0.20.3`) and the previous Caddyfile, and recreate Caddy with `docker compose up -d --no-deps --force-recreate caddy` (do not reload Caddy in place). An unchanged compose file does not recreate the container. There is no migration to reverse. Restore the database only if no payment entered after the backup.

## 7. A live `init` check with its own approval

This step needs its own approval, separate from the deploy OK. The release approver picks the Lightning Address beforehand. The maintainer runs it. It is not part of CI.

From the operator's box, not from the server, in a fresh scratch directory:

```bash
cd /path/to/the/merged/checkout
python3 -m venv /tmp/satsgate-init-c
# Install this checkout into that venv the way CONTRIBUTING.md describes.
/tmp/satsgate-init-c/bin/satsgate init --json --lightning-address merchant@pay.example
```

The install is from the merged checkout. The command talks to `https://api.satsgate.org`. It creates one throwaway account and uses 1 of the 3 signups allowed for that IP that day. It must not use Client 1.

Check:

- exit 0
- JSON `test_402.ok` is true and `test_402.debited` is false
- files and modes match the init spec
- the output contains no secret
- a second run reuses the account and opens zero accounts

Do not pay the invoice. Do not pass `--want-usdc`. Afterward delete the scratch directory from the box. The account stays, the same way clients 4–6 stayed. Record the client id, not the key.
