# Publishing satsgate (clean repo)

This folder is an export from `projects/satsgate/`.

## Quickstart (local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# .env.example will not boot as-is (production defaults, empty secret).
# Local mock:
#   SATSGATE_ENV=development SATSGATE_DEV_MODE=1 SATSGATE_WALLET_MODE=mock \
#   SATSGATE_MACAROON_SECRET=local-dev-only uvicorn app.main:app --reload --port 8000
```

## Docker (recommended for servers)

```bash
cp .env.example .env
# edit .env and set SATSGATE_HOSTNAME, SATSGATE_ENV=production,
# SATSGATE_MACAROON_SECRET=$(openssl rand -hex 32), SATSGATE_LIGHTNING_ADDRESS,
# SATSGATE_DEV_MODE=0, SATSGATE_WALLET_MODE=lnaddr

docker compose up -d --build
```

## Discovery

- `GET /.well-known/satsgate.json`
- `GET /openapi.json`

## Publish to GitHub

```bash
git init
git add .
git commit -m "Initial public release"

# create a repo on GitHub, then:
# git remote add origin git@github.com:YOUR_USER/satsgate.git
# git push -u origin main
```
