"""Offline receipt checks. Standard library only.

A use is reserved before the handler and committed only on a 2xx.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_DEFAULT_ISS = "https://gate.satsgate.org"


class ReceiptError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Receipt:
    token: str
    header: dict
    claims: dict
    jti: str
    site: str
    path: str
    uses: int
    exp: int
    iat: int
    iss: str

    def __repr__(self) -> str:
        return f"Receipt(jti={self.jti!r}, site={self.site!r}, path={self.path!r})"


@dataclass(frozen=True)
class Reservation:
    token: str
    jti: str
    exp: int


def normalize_path(path: str) -> str:
    text = (path or "").strip()
    if (
        not text
        or len(text) > 200
        or not text.startswith("/")
        or not _PATH.fullmatch(text)
        or ".." in text
        or "//" in text
        or "\\" in text
        or "?" in text
        or "#" in text
    ):
        raise ReceiptError("receipt_wrong_path")
    return text


def _b64decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # noqa: BLE001
        raise ReceiptError("receipt_invalid") from exc


def _kid(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def verify_receipt(
    token: str,
    *,
    secret: str,
    site: str,
    path: str,
    previous_secrets: Iterable[str] = (),
    leeway: int = 30,
    now: int | None = None,
    issuers: Iterable[str] = (_DEFAULT_ISS,),
    typ: str = "satsgate-receipt+jwt",
) -> Receipt:
    if not isinstance(token, str) or not token.strip():
        raise ReceiptError("receipt_missing")
    parts = token.strip().split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ReceiptError("receipt_invalid")
    try:
        header = json.loads(_b64decode(parts[0]))
        claims = json.loads(_b64decode(parts[1]))
    except ReceiptError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ReceiptError("receipt_invalid") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ReceiptError("receipt_invalid")
    if header.get("alg") != "HS256" or header.get("typ") != typ:
        raise ReceiptError("receipt_invalid")
    matched = [item for item in (secret, *tuple(previous_secrets)) if item and _kid(item) == header.get("kid")]
    if not matched:
        raise ReceiptError("receipt_invalid")
    signing = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        presented = _b64decode(parts[2])
    except ReceiptError:
        raise
    ok = False
    for item in matched:
        expected = hmac.new(item.encode("utf-8"), signing, hashlib.sha256).digest()
        if len(presented) == len(expected) and hmac.compare_digest(presented, expected):
            ok = True
            break
    if not ok:
        raise ReceiptError("receipt_invalid")
    if claims.get("aud") != site:
        raise ReceiptError("receipt_wrong_site")
    try:
        expected_path = normalize_path(path)
        token_path = normalize_path(str(claims.get("sub") or ""))
    except ReceiptError:
        raise ReceiptError("receipt_wrong_path") from None
    if token_path != expected_path:
        raise ReceiptError("receipt_wrong_path")
    allowed = {item.rstrip("/") for item in issuers}
    iss = claims.get("iss")
    if not isinstance(iss, str) or iss.rstrip("/") not in allowed:
        raise ReceiptError("receipt_invalid")
    try:
        exp = int(claims["exp"])
        iat = int(claims["iat"])
        uses = int(claims["uses"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReceiptError("receipt_invalid") from exc
    if uses < 1:
        raise ReceiptError("receipt_invalid")
    current = int(time.time()) if now is None else int(now)
    if current > exp + int(leeway):
        raise ReceiptError("receipt_expired")
    if iat > current + int(leeway):
        raise ReceiptError("receipt_invalid")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise ReceiptError("receipt_invalid")
    return Receipt(
        token=token.strip(),
        header=header,
        claims=claims,
        jti=jti,
        site=site,
        path=token_path,
        uses=uses,
        exp=exp,
        iat=iat,
        iss=iss,
    )


def check_proof(secret: str, jti: str) -> str:
    return hmac.new(secret.encode("utf-8"), f"satsgate-check|{jti}".encode("utf-8"), hashlib.sha256).hexdigest()


class ReceiptStore(Protocol):
    def reserve(self, jti: str, uses: int, exp: int) -> Reservation: ...

    def commit(self, reservation: Reservation) -> None: ...

    def release(self, reservation: Reservation) -> None: ...


class MemoryReceiptStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[str, dict] = {}

    def reserve(self, jti: str, uses: int, exp: int) -> Reservation:
        now = int(time.time())
        with self._lock:
            stale = [key for key, row in self._rows.items() if int(row["exp"]) <= now and not row["reserved"]]
            for key in stale:
                del self._rows[key]
            row = self._rows.get(jti)
            if row is None:
                row = {"uses": int(uses), "committed": 0, "reserved": {}, "exp": int(exp)}
                self._rows[jti] = row
            if int(row["committed"]) + len(row["reserved"]) >= int(row["uses"]):
                raise ReceiptError("receipt_used_up")
            token = secrets.token_hex(8)
            row["reserved"][token] = int(exp)
            return Reservation(token=token, jti=jti, exp=int(exp))

    def commit(self, reservation: Reservation) -> None:
        with self._lock:
            row = self._rows.get(reservation.jti)
            if row is None or reservation.token not in row["reserved"]:
                return
            del row["reserved"][reservation.token]
            row["committed"] += 1

    def release(self, reservation: Reservation) -> None:
        with self._lock:
            row = self._rows.get(reservation.jti)
            if row is not None:
                row["reserved"].pop(reservation.token, None)


class SqliteReceiptStore:
    def __init__(self, path: str) -> None:
        self.path = path
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipt_uses (
                  jti TEXT PRIMARY KEY,
                  uses INTEGER NOT NULL,
                  committed INTEGER NOT NULL,
                  exp INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipt_reservations (
                  token TEXT PRIMARY KEY,
                  jti TEXT NOT NULL,
                  exp INTEGER NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30, check_same_thread=False)

    def reserve(self, jti: str, uses: int, exp: int) -> Reservation:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM receipt_reservations WHERE exp <= ?", (now,))
            row = conn.execute("SELECT uses, committed FROM receipt_uses WHERE jti = ?", (jti,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO receipt_uses(jti, uses, committed, exp) VALUES(?, ?, 0, ?)",
                    (jti, int(uses), int(exp)),
                )
                committed, allowed = 0, int(uses)
            else:
                allowed, committed = int(row[0]), int(row[1])
            held = conn.execute("SELECT COUNT(*) FROM receipt_reservations WHERE jti = ?", (jti,)).fetchone()
            if committed + int(held[0]) >= allowed:
                conn.execute("ROLLBACK")
                raise ReceiptError("receipt_used_up")
            token = secrets.token_hex(8)
            conn.execute(
                "INSERT INTO receipt_reservations(token, jti, exp) VALUES(?, ?, ?)",
                (token, jti, int(exp)),
            )
            conn.execute("COMMIT")
        return Reservation(token=token, jti=jti, exp=int(exp))

    def commit(self, reservation: Reservation) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("DELETE FROM receipt_reservations WHERE token = ?", (reservation.token,))
            if cur.rowcount:
                conn.execute("UPDATE receipt_uses SET committed = committed + 1 WHERE jti = ?", (reservation.jti,))
            conn.execute("COMMIT")

    def release(self, reservation: Reservation) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM receipt_reservations WHERE token = ?", (reservation.token,))
            conn.commit()


def _header(scope, name: bytes) -> str:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value.decode("latin-1").strip()
    return ""


async def _send_json(send, status: int, payload: dict, extra: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"cache-control", b"no-store"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if extra:
        headers.extend(extra)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class SatsgateReceiptMiddleware:
    def __init__(
        self,
        app,
        *,
        site: str,
        secret: str,
        store: ReceiptStore,
        previous_secrets: Iterable[str] = (),
        protected: Iterable[str] | None = None,
        gate_base: str = _DEFAULT_ISS,
        issuers: Iterable[str] = (_DEFAULT_ISS,),
        mount_prefix: str = "",
        leeway: int = 30,
    ) -> None:
        self.app = app
        self.site = site
        self.secret = secret
        self.previous_secrets = tuple(previous_secrets)
        self.store = store
        self.protected = None if protected is None else {normalize_path(item) for item in protected}
        self.gate_base = gate_base.rstrip("/")
        self.issuers = tuple(issuers)
        self.mount_prefix = "/" + mount_prefix.strip("/") if mount_prefix.strip("/") else ""
        self.leeway = leeway

    def _route_path(self, path: str) -> str | None:
        prefix = self.mount_prefix
        if prefix:
            if path == prefix:
                route = "/"
            elif path.startswith(prefix + "/"):
                route = path[len(prefix) :]
            else:
                return None
        else:
            route = path or "/"
        try:
            return normalize_path(route)
        except ReceiptError:
            return None

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        route = self._route_path(scope.get("path") or "/")
        if route is None:
            await self.app(scope, receive, send)
            return
        if route == "/.well-known/satsgate-check":
            await self._origin_check(scope, send)
            return
        if self.protected is not None and route not in self.protected:
            await self.app(scope, receive, send)
            return
        header = _header(scope, b"satsgate-receipt")
        if not header:
            pay_at = f"{self.gate_base}/{self.site}{'' if route == '/' else route}"
            await _send_json(
                send,
                402,
                {"error": "payment_required", "pay_at": pay_at},
                [(b"link", f"<{pay_at}>; rel=\"satsgate-pay\"".encode("ascii"))],
            )
            return
        try:
            receipt = verify_receipt(
                header,
                secret=self.secret,
                site=self.site,
                path=route,
                previous_secrets=self.previous_secrets,
                leeway=self.leeway,
                issuers=self.issuers,
            )
        except ReceiptError as exc:
            await _send_json(send, 401, {"error": exc.code})
            return
        try:
            reservation = self.store.reserve(receipt.jti, receipt.uses, receipt.exp)
        except ReceiptError as exc:
            await _send_json(send, 401, {"error": exc.code})
            return
        scope["satsgate_route"] = route
        state = scope.setdefault("state", {})
        try:
            state["satsgate_receipt"] = receipt
        except TypeError:
            setattr(state, "satsgate_receipt", receipt)
        status = 500

        async def _send(message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, _send)
        except Exception:
            self.store.release(reservation)
            raise
        if 200 <= status < 300:
            self.store.commit(reservation)
        else:
            self.store.release(reservation)

    async def _origin_check(self, scope, send) -> None:
        token = _header(scope, b"satsgate-check")
        status, body = origin_check_response(
            token,
            secret=self.secret,
            site=self.site,
            previous_secrets=self.previous_secrets,
            issuers=self.issuers,
        )
        await _send_json(send, status, body)


def origin_check_response(
    token: str,
    *,
    secret: str,
    site: str,
    previous_secrets: Iterable[str] = (),
    issuers: Iterable[str] = (_DEFAULT_ISS,),
) -> tuple[int, dict]:
    try:
        receipt = verify_receipt(
            token,
            secret=secret,
            site=site,
            path="/.well-known/satsgate-check",
            previous_secrets=previous_secrets,
            leeway=5,
            issuers=issuers,
            typ="satsgate-check+jwt",
        )
    except ReceiptError as exc:
        return 401, {"error": exc.code}
    return 200, {"ok": True, "proof": check_proof(secret, receipt.jti)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m satsgate_sdk.receipts")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--site", required=True)
    verify.add_argument("--path", required=True)
    args = parser.parse_args(argv)
    secret = os.environ.get("SATSGATE_SITE_SECRET", "")
    if not secret:
        print("SATSGATE_SITE_SECRET is unset", file=sys.stderr)
        return 2
    try:
        receipt = verify_receipt(sys.stdin.read().strip(), secret=secret, site=args.site, path=args.path)
    except ReceiptError as exc:
        print(exc.code)
        return 1
    print(json.dumps({"ok": True, "jti": receipt.jti, "exp": receipt.exp, "uses": receipt.uses}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
