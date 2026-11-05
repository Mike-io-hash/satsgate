"""Five-line wrapper around the SDK receipt middleware."""

from satsgate_sdk.receipts import SatsgateReceiptMiddleware, SqliteReceiptStore


def install(app, *, site: str, secret: str, store_path: str):
    return SatsgateReceiptMiddleware(app, site=site, secret=secret, store=SqliteReceiptStore(store_path))
