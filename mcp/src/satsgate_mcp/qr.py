"""BOLT11 QR as PNG bytes and as text. Nothing is written to stdout."""

from __future__ import annotations

import io


def invoice_qr(invoice: str) -> tuple[bytes | None, str | None]:
    if not invoice or len(invoice) > 4096:
        return None, None
    try:
        import segno
    except ModuleNotFoundError:
        return None, None
    code = segno.make(invoice, error="m")
    png = io.BytesIO()
    code.save(png, kind="png", scale=4, border=2)
    text = io.StringIO()
    code.save(text, kind="txt", border=1)
    return png.getvalue(), text.getvalue()
