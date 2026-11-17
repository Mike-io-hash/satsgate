# satsgate

Charge AI agents in Lightning and USDC on the same 402. 500 free unlocks per UTC month. Cobrale a agentes de IA en Lightning y USDC, en el mismo 402.

`satsgate` is the umbrella command. `satsgate init` writes a self-hosted paywall config. It is not on PyPI yet. Install from this repository:

```bash
pip install -e sdk/python -e proxy -e cli
satsgate --help
satsgate --version
```

`satsgate init` does not ask for a seed, a private key, or a recovery phrase. It does not hold sats or USDC. The account key stays in `.satsgate/account.env`. The project `.env` holds the restricted proxy key and the origin secret.
