"""Strip wallet URIs and API keys from logs and error text."""

from __future__ import annotations

import logging
import re

_NWC = re.compile(r"nostr\+walletconnect://\S+", re.IGNORECASE)
_KEY = re.compile(r"\b(?:sgr|sg)_[A-Za-z0-9_\-]{6,}\b")


def scrub(text: str, secrets: tuple[str, ...] = ()) -> str:
    cleaned = _NWC.sub("[redacted]", text)
    cleaned = _KEY.sub("[redacted]", cleaned)
    for secret in secrets:
        if secret and len(secret) >= 8:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            record.msg = scrub(record.getMessage())
            record.args = ()
        elif isinstance(record.msg, str):
            record.msg = scrub(record.msg)
        if record.exc_text:
            record.exc_text = scrub(record.exc_text)
        return True


def install() -> None:
    filt = RedactFilter()
    root = logging.getLogger()
    if not any(isinstance(item, RedactFilter) for item in root.filters):
        root.addFilter(filt)
    named = logging.getLogger("satsgate_mcp")
    if not any(isinstance(item, RedactFilter) for item in named.filters):
        named.addFilter(filt)
    if not named.handlers:
        handler = logging.StreamHandler()
        handler.addFilter(filt)
        named.addHandler(handler)
        named.setLevel(logging.INFO)
        named.propagate = False
