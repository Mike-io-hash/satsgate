"""Country lookup for credit-pack quotes. The database is a local MMDB file.

An empty country list does no lookup. A configured list with a missing or
unreadable database fails closed. An unknown address is allowed. The file is
reopened when its mtime changes. Nothing is downloaded here.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from . import config

log = logging.getLogger("satsgate.geoblock")
_lock = threading.Lock()
_reader = None
_mtime: float | None = None
_path: str | None = None
_last_log = 0.0


class GeoblockUnavailable(Exception):
    """The country list is set and the database cannot be read."""


def _log_once(message: str) -> None:
    global _last_log
    now = time.monotonic()
    if now - _last_log < 60:
        return
    _last_log = now
    log.error("%s", message)


def _open(path: Path):
    import maxminddb

    return maxminddb.open_database(str(path))


def _current():
    global _reader, _mtime, _path
    target = config.GEOIP_DB
    file = Path(target)
    try:
        mtime = file.stat().st_mtime
    except OSError as exc:
        _log_once(f"geoblock database unreadable at {target}")
        raise GeoblockUnavailable() from exc
    with _lock:
        if _reader is not None and _path == target and _mtime == mtime:
            return _reader
        try:
            reader = _open(file)
        except Exception as exc:  # noqa: BLE001
            _log_once(f"geoblock database failed to open at {target}")
            raise GeoblockUnavailable() from exc
        if _reader is not None:
            try:
                _reader.close()
            except Exception:  # noqa: BLE001
                pass
        _reader = reader
        _mtime = mtime
        _path = target
        return reader


def country_for_ip(ip: str) -> str | None:
    if not config.GEOBLOCK_COUNTRIES:
        return None
    reader = _current()
    try:
        record = reader.get(ip)
    except (ValueError, OSError):
        return None
    if not isinstance(record, dict):
        return None
    country = record.get("country")
    if not isinstance(country, dict):
        return None
    code = country.get("iso_code")
    if not isinstance(code, str) or len(code) != 2:
        return None
    return code.upper()


def blocked_country(ip: str | None) -> str | None:
    """Blocked ISO code, or None when the quote may continue."""
    if not config.GEOBLOCK_COUNTRIES:
        return None
    if not ip or ip == "unknown":
        return None
    code = country_for_ip(ip)
    if code is None or code not in config.GEOBLOCK_COUNTRIES:
        return None
    return code


def status() -> dict:
    if not config.GEOBLOCK_COUNTRIES:
        return {"geoblock": "off"}
    try:
        _current()
    except GeoblockUnavailable:
        return {"geoblock": "unavailable", "countries": sorted(config.GEOBLOCK_COUNTRIES)}
    return {"geoblock": "ok", "countries": sorted(config.GEOBLOCK_COUNTRIES)}
