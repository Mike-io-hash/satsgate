# Contributing

Thanks for considering contributing to satsgate.

## Quickstart (development)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

pytest -q
```

## Running locally

```bash
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

`.env.example` will not boot as-is (production defaults, empty secret). A local mock is:

```bash
SATSGATE_ENV=development SATSGATE_DEV_MODE=1 SATSGATE_WALLET_MODE=mock \
  SATSGATE_MACAROON_SECRET=local-dev-only uvicorn app.main:app --reload --port 8000
```

Discovery routes for a running core are `GET /.well-known/satsgate.json` and `GET /openapi.json`.
The release runbook is [docs/publishing.md](docs/publishing.md).

## From a checkout

```bash
pip install -e sdk/python -e proxy -e cli
pip install -r mcp/requirements.txt
PYTHONPATH=mcp/src python -m satsgate_mcp.manual https://your-proxy.example/blog/post
docker compose -f proxy/docker-compose.yml up --build
```

## Code style

This project prefers:
- small, readable diffs
- clear error messages
- plain public docs and comments

## Pull requests

- Include a short description of the change and why it matters.
- Add/update tests when behavior changes.

## Security issues

Do **not** open public issues for vulnerabilities.
See `SECURITY.md`.
