"""Plain-text and HTML bodies for security alerts.

Every interpolated value is escaped in the HTML part. There are no images,
no tracking pixels, and no links except the confirmation URL written out as
text. The full payout address is never included.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from . import config

SECURITY_ADVISORY_URL = "https://github.com/Mike-io-hash/satsgate/security/advisories"
ROTATE_QUICKSTART_URL = (
    "https://github.com/Mike-io-hash/satsgate/blob/main/CUSTOMER_QUICKSTART.md#rotate-the-account-key"
)
_ELLIPSIS = "…"


def shorten_evm(address: str) -> str:
    """First 6 and last 4 characters of the checksum form: ``0x4A9E…2Ce3``."""
    text = str(address)
    if len(text) < 10:
        return text
    return f"{text[:6]}{_ELLIPSIS}{text[-4:]}"


def shorten_lightning(address: str) -> str:
    """First 4 characters of the local part, then the full domain."""
    text = str(address)
    if "@" not in text:
        head = text[:4]
        return f"{head}{_ELLIPSIS}"
    local, domain = text.split("@", 1)
    return f"{local[:4]}{_ELLIPSIS}@{domain}"


def format_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(int(timestamp), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def payout_params(
    *,
    rail: str,
    new_address: str,
    previous: str | None,
    at: int,
    via: str,
    rails_cleared: bool,
) -> dict:
    """Shortened addresses only. The full payout address is not stored in the outbox."""
    shorten = shorten_evm if rail == "evm" else shorten_lightning
    return {
        "new": shorten(new_address) if new_address else "none",
        "previous": "none" if not previous else shorten(previous),
        "at": format_utc(at),
        "via": via,
        "rails_cleared": bool(rails_cleared),
    }


def render(kind: str, *, client_id: int, params: dict) -> tuple[str, str, str]:
    """Return ``(subject, text, html)`` for one outbox row."""
    if kind == "payee_evm_changed":
        return _payout(
            client_id=client_id,
            params=params,
            subject="Satsgate: your USDC payout address changed",
            rail="USDC on Base",
        )
    if kind == "payee_lightning_changed":
        return _payout(
            client_id=client_id,
            params=params,
            subject="Satsgate: your Lightning payout address changed",
            rail="Lightning",
        )
    if kind == "payee_ofac_flagged":
        shown = params.get("address") or "an address"
        text = "\n\n".join(
            [
                f"Account #{int(client_id)}",
                f"USDC payouts to {shown} were turned off because that address is on a sanctions list.",
                "USDC was turned off on your sites.",
                "If you think this is a mistake, write to the support address. Do not send a private key.",
            ]
        )
        return "Satsgate: a payout address was blocked", text, _html_of(text)
    builders = {
        "alert_email_confirm": _confirm,
        "alert_email_change_requested": _change_requested,
        "alert_email_changed": _changed,
        "alert_email_removed": _removed,
        "alert_email_confirmed": _confirmed,
        "account_key_rotated": _account_key_rotated,
        "webhook_disabled": _webhook_disabled,
    }
    builder = builders.get(kind)
    if builder is None:
        raise ValueError("unknown_email_kind")
    return builder(client_id=client_id, params=params)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _html_of(text: str) -> str:
    paragraphs = [part for part in text.split("\n\n") if part.strip()]
    body = "".join(f"<p>{_esc(part).replace(chr(10), '<br>')}</p>" for part in paragraphs)
    return f"<!DOCTYPE html><html><body>{body}</body></html>"


def _if_it_wasnt_you() -> str:
    """Stolen-key copy. Rotation first, then a support pause. Not used for sanctions mail."""
    support = (config.SUPPORT_EMAIL or "").strip()
    if support:
        contact = f"Then write to {support} and we will pause your sites."
    else:
        contact = f"Then write to {SECURITY_ADVISORY_URL} and we will pause your sites."
    return (
        "If you did not make this change, your Satsgate account key may have been copied. "
        "Rotate your account key with POST /v1/client/api-key/rotate. "
        f"The steps are at {ROTATE_QUICKSTART_URL}. "
        f"{contact} Never send a key, seed phrase or private key. Satsgate does not ask for them."
    )


def _payout(*, client_id: int, params: dict, subject: str, rail: str) -> tuple[str, str, str]:
    previous = params.get("previous") or "none"
    rails = params.get("rails_cleared")
    rails_line = (
        "USDC was turned off on your sites."
        if rails
        else "USDC on your sites was left as it was."
    )
    text = "\n\n".join(
        [
            f"Account #{int(client_id)}",
            f"{rail} payout address is now {params.get('new') or 'none'}.",
            f"Previous address: {previous}.",
            f"When: {params.get('at') or ''}.",
            f"How: {params.get('via') or 'API'}.",
            rails_line,
            _if_it_wasnt_you(),
            "If this was you, you don't need to do anything.",
        ]
    )
    return subject, text, _html_of(text)


def _confirm(*, client_id: int, params: dict) -> tuple[str, str, str]:
    link = f"{config.CONNECT_PUBLIC_BASE}/confirm-email#t={params.get('token') or ''}"
    text = "\n\n".join(
        [
            f"Confirm this address for security alerts on Satsgate account #{int(client_id)}.",
            link,
            "The link works once and expires in 24 hours. Alerts start after you confirm.",
            "If you did not ask for this, ignore this email. Nothing changes until you confirm.",
        ]
    )
    return "Satsgate: confirm your security alert email", text, _html_of(text)


def _change_requested(*, client_id: int, params: dict) -> tuple[str, str, str]:
    masked = params.get("masked_new") or "another address"
    text = "\n\n".join(
        [
            f"Account #{int(client_id)}",
            f"A change of your alert email was requested. Alerts still come here until {masked} is confirmed.",
            _if_it_wasnt_you(),
            "If this was you, confirm the new address from its inbox. You don't need to do anything else.",
        ]
    )
    return "Satsgate: a change of your alert email was requested", text, _html_of(text)


def _changed(*, client_id: int, params: dict) -> tuple[str, str, str]:
    masked = params.get("masked_new") or "another address"
    text = "\n\n".join(
        [
            f"Account #{int(client_id)}",
            f"Alerts now go to {masked}.",
            _if_it_wasnt_you(),
            "If this was you, you don't need to do anything.",
        ]
    )
    return "Satsgate: your alert email changed", text, _html_of(text)


def _removed(*, client_id: int, params: dict) -> tuple[str, str, str]:
    del params
    text = "\n\n".join(
        [
            f"Account #{int(client_id)}",
            "Security alerts were turned off. Satsgate will not email this address about payout changes.",
            _if_it_wasnt_you(),
            "If this was you, you don't need to do anything.",
        ]
    )
    return "Satsgate: security alerts were turned off", text, _html_of(text)


def _account_key_rotated(*, client_id: int, params: dict) -> tuple[str, str, str]:
    prefix = params.get("prefix") or ""
    text = "\n\n".join(
        [
            f"Account #{int(client_id)}",
            f"Your account key was rotated. The new key starts with {prefix}.",
            f"When: {params.get('at') or ''}.",
            f"How: {params.get('via') or 'api'}.",
            "The previous key stopped working immediately. The new key was shown once, in the API response.",
            _if_it_wasnt_you(),
            "If this was you, you don't need to do anything else.",
        ]
    )
    return "Satsgate: your account key was rotated", text, _html_of(text)


def _webhook_disabled(*, client_id: int, params: dict) -> tuple[str, str, str]:
    """The URL went away. This is not a stolen-key alert and it does not mention sanctions."""
    status = params.get("status") or ""
    text = "\n\n".join(
        [
            f"Account #{int(client_id)}",
            f"Your security webhook was turned off because the URL returned HTTP {status}.",
            "Satsgate stopped sending events to it. The URL is not included in this email.",
            "Register a new one with PUT /v1/client/webhook if you still want webhook alerts.",
            f"When: {params.get('at') or ''}.",
        ]
    )
    return "Satsgate: your security webhook was turned off", text, _html_of(text)


def _confirmed(*, client_id: int, params: dict) -> tuple[str, str, str]:
    del params
    text = (
        f"Security alerts are on for Satsgate account #{int(client_id)}. "
        "You'll get an email if your payout address changes."
    )
    return "Satsgate: security alerts are on", text, _html_of(text)
