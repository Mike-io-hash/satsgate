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

## Code style

This project prefers:
- small, readable diffs
- clear error messages
- English-only public docs/comments

## Pull requests

- Include a short description of the change and why it matters.
- Add/update tests when behavior changes.

## Security issues

Do **not** open public issues for vulnerabilities.
See `SECURITY.md`.
