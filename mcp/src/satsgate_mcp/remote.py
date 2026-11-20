"""One-shot client for a remote MCP server. Every request goes through Buyer._send."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from mcp.shared.inbound import encode_header_value, find_invalid_x_mcp_header, mcp_param_headers, x_mcp_header_map

from satsgate_mcp import __version__
from satsgate_mcp.budget import refusal
from satsgate_mcp.buyer import Buyer, BuyerError, Presentation, _clean_payment_signature
from satsgate_mcp.challenge import ChallengeError, parse_challenge
from satsgate_mcp.nwc import NwcError
from satsgate_mcp.urls import validate_url

_MODERN = "2026-07-28"
_PROPOSED = "2025-11-25"
_HANDSHAKE = frozenset({"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"})
_ACCEPT = "application/json, text/event-stream"
_SESSION = re.compile(r"^[\x21-\x7e]{1,1024}$")
_PREIMAGE = re.compile(r"^[0-9a-fA-F]{64}$")
_LIST_PAGES = 10

_HANDSHAKE_NOT_FREE = (
    "The server asked for payment during {step}. This client does not pay for the handshake. Nothing was paid."
)
_INCOMPATIBLE = "This server does not support a protocol version this client can use. Nothing was paid."
_CONNECT_HTTP = "The MCP handshake failed (HTTP {status}). Nothing was paid."
_SESSION_INVALID = "The server sent an invalid Mcp-Session-Id. Nothing was paid."
_LISTING_NOT_FREE = "The server asked for payment to list tools. This client does not pay for tools/list. Nothing was paid."
_LIST_FAILED = "tools/list failed (HTTP {status}). Nothing was paid."
_UNKNOWN = "The server does not list a tool with that name. Nothing was sent or paid."
_UNKNOWN_CUT = _UNKNOWN + " The listing stopped after 10 pages."
_BAD_SCHEMA = "The tool's inputSchema has an invalid x-mcp-header annotation. Nothing was sent or paid."
_INVALID_RESPONSE = "The server did not return a JSON-RPC response for this request. Nothing was paid."
_REDIRECT = "The server redirected. This client does not follow redirects."
_TOO_LARGE = "The response is above SATSGATE_MCP_MAX_BODY_BYTES. Nothing was paid."
_LIST_DETAIL = "Listing tools is free. A price, when there is one, is shown when the tool is called."
_NWC_MISSING = (
    "SATSGATE_MCP_NWC_URI is not set. Use mode human, or set the wallet URI in the environment. "
    "Do not paste it into the chat."
)
_TOOL_MESSAGE = "tool must be a non-empty string of at most 128 characters without control characters."
_ARGUMENTS_OBJECT = "arguments must be a JSON object with string keys."
_ARGUMENTS_JSON = "arguments must be JSON-serializable."
_ARGUMENTS_SIZE = "arguments are above SATSGATE_MCP_MAX_BODY_BYTES."
_MODE = "mode must be human or nwc."
_SIGNATURE_TYPE = "payment_signature must be a string. It was not sent."
_SIGNATURE_OBJECT = "PAYMENT-SIGNATURE must be base64 of a JSON object. It was not sent."


@dataclass
class _Conn:
    url: str
    era: str = ""
    protocol_version: str = ""
    session_id: str | None = None
    _next: int = 1
    renewed: bool = False
    in_handshake: bool = False

    def alloc(self) -> int:
        value = self._next
        self._next += 1
        return value


def _dumps(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _envelope(version: str) -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "satsgate-mcp", "version": __version__},
    }


def _call_limit_body(tool: str, arguments: dict) -> bytes:
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments, "_meta": _envelope(_MODERN)},
    }
    return _dumps(message)


def _validate_url(buyer: Buyer, url: object) -> str:
    if isinstance(url, bool) or not isinstance(url, str):
        raise BuyerError("invalid_url", "url must be a string.")
    return validate_url(url, buyer.settings.allowlist)


def _validate_tool(tool: object) -> str:
    if isinstance(tool, bool) or not isinstance(tool, str):
        raise BuyerError("invalid_tool_name", _TOOL_MESSAGE)
    if not 1 <= len(tool) <= 128 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in tool):
        raise BuyerError("invalid_tool_name", _TOOL_MESSAGE)
    return tool


def _validate_arguments(buyer: Buyer, tool: str, arguments: object) -> dict:
    if arguments is None:
        arguments = {}
    if isinstance(arguments, bool) or not isinstance(arguments, dict):
        raise BuyerError("invalid_arguments", _ARGUMENTS_OBJECT)
    if any(isinstance(key, bool) or not isinstance(key, str) for key in arguments):
        raise BuyerError("invalid_arguments", _ARGUMENTS_OBJECT)
    try:
        json.dumps(arguments, allow_nan=False)
    except (TypeError, ValueError):
        raise BuyerError("invalid_arguments", _ARGUMENTS_JSON) from None
    if len(_call_limit_body(tool, arguments)) > buyer.settings.max_body_bytes:
        raise BuyerError("invalid_arguments", _ARGUMENTS_SIZE)
    return arguments


def _validate_mode(mode: object) -> str:
    if isinstance(mode, bool) or not isinstance(mode, str):
        raise BuyerError("invalid_mode", _MODE)
    way = mode.strip().lower()
    if way not in {"human", "nwc"}:
        raise BuyerError("invalid_mode", _MODE)
    return way


def _validate_signature(signature: object) -> dict | None:
    if signature is None or signature == "":
        return None
    if isinstance(signature, bool) or not isinstance(signature, str):
        raise BuyerError("invalid_payment_signature", _SIGNATURE_TYPE)
    cleaned = _clean_payment_signature(signature)
    try:
        parsed = json.loads(base64.b64decode(cleaned, validate=True))
    except (ValueError, json.JSONDecodeError):
        raise BuyerError("invalid_payment_signature", _SIGNATURE_OBJECT) from None
    if not isinstance(parsed, dict):
        raise BuyerError("invalid_payment_signature", _SIGNATURE_OBJECT)
    return parsed


def _cache_key(url: str, tool: str) -> str:
    return "mcp " + json.dumps([url, tool], separators=(",", ":"), ensure_ascii=False)


def _content_type(headers: dict) -> str:
    return headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _sse_objects(text: str) -> list[dict]:
    found: list[dict] = []
    data_lines: list[str] = []

    def flush() -> None:
        if not data_lines:
            return
        raw = "\n".join(data_lines)
        data_lines.clear()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(parsed, dict):
            found.append(parsed)

    for line in text.splitlines():
        if line == "":
            flush()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            value = line[5:]
            if value.startswith(" "):
                value = value[1:]
            data_lines.append(value)
    flush()
    return found


def _messages(raw) -> list[dict]:
    if _content_type(raw.headers) == "text/event-stream":
        return _sse_objects(raw.body.decode("utf-8", errors="replace"))
    if not raw.body:
        return []
    try:
        parsed = json.loads(raw.body)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def _same_id(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _match(raw, request_id: int) -> dict | None:
    for message in _messages(raw):
        if "id" not in message or not _same_id(message["id"], request_id):
            continue
        if "result" in message or "error" in message:
            return message
    return None


def _modern_answer(status: int, message: dict | None) -> bool:
    if status != 200 or message is None:
        return False
    result = message.get("result")
    if not isinstance(result, dict):
        return False
    versions = result.get("supportedVersions")
    return isinstance(versions, list) and _MODERN in versions


def _disjoint_modern(message: dict | None) -> bool:
    if message is None:
        return False
    error = message.get("error")
    if not isinstance(error, dict) or error.get("code") != -32022:
        return False
    data = error.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("supported"), list):
        return False
    return not any(item in _HANDSHAKE for item in data["supported"])


def _list_is_priced(message: dict | None) -> bool:
    if message is None:
        return False
    result = message.get("result")
    if not isinstance(result, dict) or result.get("isError") is not True:
        return False
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        return False
    if structured.get("error") == "payment_required":
        return True
    if structured.get("x402Version") == 2 and isinstance(structured.get("accepts"), list):
        return True
    return False


def _authorization(row: dict) -> str:
    header = f"L402 {row['macaroon']}"
    preimage = row.get("preimage")
    if isinstance(preimage, str) and preimage:
        header = f"{header}:{preimage}"
    return header


class _Remote:
    def __init__(self, buyer: Buyer) -> None:
        self.buyer = buyer

    async def list_tools(self, url: object) -> Presentation:
        target = _validate_url(self.buyer, url)
        conn: _Conn | None = None
        try:
            conn = await self._connect(target)
            tools, truncated = await self._list(conn)
            return Presentation(
                {
                    "ok": True,
                    "url": target,
                    "protocol_version": conn.protocol_version,
                    "tools": tools,
                    "truncated": truncated,
                    "detail": _LIST_DETAIL,
                }
            )
        finally:
            if conn is not None:
                await self._close(conn)

    async def call_tool(
        self,
        url: object,
        tool: object,
        arguments: object,
        mode: object,
        payment_signature: object,
    ) -> Presentation:
        target = _validate_url(self.buyer, url)
        name = _validate_tool(tool)
        payload = _validate_arguments(self.buyer, name, arguments)
        way = _validate_mode(mode)
        _validate_signature(payment_signature)
        conn: _Conn | None = None
        try:
            conn = await self._connect(target)
            tools, truncated = await self._list(conn)
            found = next((item for item in tools if item["name"] == name), None)
            if found is None:
                raise BuyerError("unknown_tool", _UNKNOWN_CUT if truncated else _UNKNOWN)
            name_header, param_headers = self._call_headers(conn, found["input_schema"], name, payload)
            try:
                return await self._invoke(conn, name, payload, way, name_header, param_headers)
            except BuyerError as exc:
                return Presentation(self._caught(conn, name, exc))
        finally:
            if conn is not None:
                await self._close(conn)

    def _call_headers(self, conn: _Conn, schema: dict | None, tool: str, arguments: dict) -> tuple[str | None, dict]:
        if conn.era != "modern":
            return None, {}
        if find_invalid_x_mcp_header(schema) is not None:
            raise BuyerError("invalid_tool_schema", _BAD_SCHEMA)
        return encode_header_value(tool), mcp_param_headers(x_mcp_header_map(schema), arguments)

    async def _connect(self, url: str) -> _Conn:
        conn = _Conn(url=url)
        try:
            if await self._probe(conn):
                conn.era = "modern"
                conn.protocol_version = _MODERN
                conn.session_id = None
                return conn
            await self._legacy(conn)
            return conn
        except Exception:
            await self._close(conn)
            raise

    async def _probe(self, conn: _Conn) -> bool:
        request_id = conn.alloc()
        body = _dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "server/discover",
                "params": {"_meta": _envelope(_MODERN)},
            }
        )
        headers = {
            "Content-Type": "application/json",
            "Accept": _ACCEPT,
            "MCP-Protocol-Version": _MODERN,
            "Mcp-Method": "server/discover",
        }
        raw = await self.buyer._send("POST", conn.url, headers, body)
        self._raise_transport_status(raw, "server/discover")
        message = _match(raw, request_id)
        if _modern_answer(raw.status, message):
            return True
        if _disjoint_modern(message):
            raise BuyerError("incompatible_protocol", _INCOMPATIBLE)
        return False

    async def _legacy(self, conn: _Conn) -> None:
        conn.in_handshake = True
        conn.session_id = None
        try:
            request_id = conn.alloc()
            body = _dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": _PROPOSED,
                        "capabilities": {},
                        "clientInfo": {"name": "satsgate-mcp", "version": __version__},
                    },
                }
            )
            raw = await self.buyer._send(
                "POST",
                conn.url,
                {"Content-Type": "application/json", "Accept": _ACCEPT},
                body,
            )
            self._raise_transport_status(raw, "initialize")
            message = _match(raw, request_id)
            if raw.status != 200 or message is None or not isinstance(message.get("result"), dict):
                raise BuyerError("connect_failed", _CONNECT_HTTP.format(status=raw.status))
            result = message["result"]
            version = result.get("protocolVersion")
            self._take_session(conn, raw, version)
            if version not in _HANDSHAKE:
                if isinstance(version, str):
                    conn.protocol_version = version
                raise BuyerError("incompatible_protocol", _INCOMPATIBLE)
            conn.protocol_version = str(version)
            conn.era = "legacy"
            note = await self.buyer._send(
                "POST",
                conn.url,
                self._legacy_headers(conn),
                _dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            self._raise_transport_status(note, "notifications/initialized")
        finally:
            conn.in_handshake = False

    def _take_session(self, conn: _Conn, raw, version: object) -> None:
        if "mcp-session-id" not in raw.headers:
            return
        session = raw.headers.get("mcp-session-id")
        if isinstance(session, str) and _SESSION.fullmatch(session):
            conn.session_id = session
            return
        if version in _HANDSHAKE:
            raise BuyerError("connect_failed", _SESSION_INVALID)

    def _raise_transport_status(self, raw, step: str) -> None:
        if raw.status == 402:
            raise BuyerError("handshake_not_free", _HANDSHAKE_NOT_FREE.format(step=step))
        if 300 <= raw.status < 400:
            raise BuyerError("redirect_not_followed", _REDIRECT)
        if raw.truncated:
            raise BuyerError("response_too_large", _TOO_LARGE)

    def _legacy_headers(self, conn: _Conn, extra: dict | None = None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": _ACCEPT,
            "MCP-Protocol-Version": conn.protocol_version,
        }
        if conn.session_id:
            headers["Mcp-Session-Id"] = conn.session_id
        if extra:
            headers.update(extra)
        return headers

    def _modern_headers(
        self,
        method: str,
        *,
        name_header: str | None = None,
        param_headers: dict | None = None,
        extra: dict | None = None,
    ) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": _ACCEPT,
            "MCP-Protocol-Version": _MODERN,
            "Mcp-Method": method,
        }
        if name_header is not None:
            headers["Mcp-Name"] = name_header
        if param_headers:
            headers.update(param_headers)
        if extra:
            headers.update(extra)
        return headers

    async def _post(
        self,
        conn: _Conn,
        method: str,
        params: dict,
        *,
        name_header: str | None = None,
        param_headers: dict | None = None,
        extra: dict | None = None,
        allow_renew: bool = True,
    ):
        request_id = conn.alloc()
        body_params = dict(params)
        if conn.era == "modern":
            merged = dict(body_params.get("_meta") or {})
            merged.update(_envelope(_MODERN))
            # Envelope keys stay first when the caller did not already set _meta.
            if "_meta" not in body_params:
                body_params["_meta"] = _envelope(_MODERN)
            else:
                body_params["_meta"] = merged
            headers = self._modern_headers(method, name_header=name_header, param_headers=param_headers, extra=extra)
        else:
            headers = self._legacy_headers(conn, extra)
        raw = await self.buyer._send(
            "POST",
            conn.url,
            headers,
            _dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": body_params}),
        )
        carried = bool(conn.session_id) and not conn.in_handshake
        if raw.status == 404 and carried and allow_renew and not conn.renewed:
            conn.renewed = True
            await self._legacy(conn)
            return await self._post(
                conn,
                method,
                params,
                name_header=name_header,
                param_headers=param_headers,
                extra=extra,
                allow_renew=False,
            )
        return raw, request_id

    async def _list(self, conn: _Conn) -> tuple[list[dict], bool]:
        tools: list[dict] = []
        cursor: str | None = None
        for _page in range(_LIST_PAGES):
            params: dict = {}
            if cursor is not None:
                params["cursor"] = cursor
            raw, request_id = await self._post(conn, "tools/list", params)
            if raw.truncated:
                raise BuyerError("response_too_large", _TOO_LARGE)
            if 300 <= raw.status < 400:
                raise BuyerError("redirect_not_followed", _REDIRECT)
            message = _match(raw, request_id)
            if raw.status == 402 or _list_is_priced(message):
                raise BuyerError("listing_not_free", _LISTING_NOT_FREE)
            if raw.status == 404 and conn.session_id:
                raise BuyerError("session_expired", "The MCP session expired. Nothing was paid.")
            if raw.status != 200 or message is None or "result" not in message:
                if raw.status == 200 and message is None:
                    raise BuyerError("invalid_response", _INVALID_RESPONSE)
                raise BuyerError("list_failed", _LIST_FAILED.format(status=raw.status))
            result = message["result"]
            items = result.get("tools") if isinstance(result, dict) else None
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
                        continue
                    description = item.get("description")
                    schema = item.get("inputSchema")
                    tools.append(
                        {
                            "name": item["name"],
                            "description": description if isinstance(description, str) else None,
                            "input_schema": schema if isinstance(schema, dict) else None,
                        }
                    )
            nxt = result.get("nextCursor") if isinstance(result, dict) else None
            if not isinstance(nxt, str) or not nxt:
                return tools, False
            cursor = nxt
        return tools, True

    async def _invoke(
        self,
        conn: _Conn,
        tool: str,
        arguments: dict,
        mode: str,
        name_header: str | None,
        param_headers: dict,
    ) -> Presentation:
        key = _cache_key(conn.url, tool)
        token = self.buyer._usable_token(key)
        extra = {"Authorization": _authorization(token)} if token is not None else None
        raw, request_id = await self._post(
            conn,
            "tools/call",
            {"name": tool, "arguments": arguments},
            name_header=name_header,
            param_headers=param_headers,
            extra=extra,
        )
        if raw.status == 404 and conn.session_id:
            return Presentation(self._expired(conn, tool, token is not None))
        if raw.status == 402 and mode == "nwc" and token is None:
            paid = await self._pay_once(conn, raw, tool, arguments, name_header, param_headers)
            if isinstance(paid, Presentation):
                return paid
            raw, request_id = paid
        return Presentation(self._read_call(conn, tool, raw, request_id))

    async def _pay_once(self, conn, raw, tool: str, arguments: dict, name_header, param_headers):
        try:
            challenge = parse_challenge(
                method="POST",
                url=conn.url,
                status=402,
                www_authenticate=raw.headers.get("www-authenticate", ""),
                body=raw.body,
                request_body=None,
                payment_required=raw.headers.get("payment-required", ""),
            )
        except ChallengeError as exc:
            return Presentation({"ok": False, "error": exc.code, "url": conn.url, "tool": tool, "detail": exc.message})
        if not challenge.offers_lightning:
            return Presentation({"ok": False, "error": "payment_required", "url": conn.url, "tool": tool})
        if not self.buyer.settings.nwc_uri:
            raise BuyerError("nwc_not_configured", _NWC_MISSING)
        blocked = refusal(self.buyer.settings, self.buyer.store, challenge.amount_sats, self.buyer._now())
        if blocked:
            payload = self.buyer._annotate(challenge)
            payload["ok"] = False
            payload["error"] = "over_budget"
            payload["tool"] = tool
            payload["protocol_version"] = conn.protocol_version
            payload["detail"] = blocked
            return Presentation(payload)
        try:
            preimage = await self.buyer.wallet.pay_invoice(challenge.invoice)
        except (NwcError, BuyerError) as exc:
            raise BuyerError("nwc_failed", self.buyer._scrub(str(exc), challenge.macaroon)) from None
        if not isinstance(preimage, str) or not _PREIMAGE.fullmatch(preimage):
            raise BuyerError("nwc_failed", "NWC wallet returned a preimage that is not 64 hex characters.")
        host = urlsplit(conn.url).hostname or ""
        self.buyer.store.record_spend(
            created_at=self.buyer._now(),
            amount_sats=challenge.amount_sats,
            payment_hash=challenge.payment_hash,
            host=host,
        )
        return await self._post(
            conn,
            "tools/call",
            {"name": tool, "arguments": arguments},
            name_header=name_header,
            param_headers=param_headers,
            extra={"Authorization": f"L402 {challenge.macaroon}:{preimage.lower()}"},
        )

    def _read_call(self, conn: _Conn, tool: str, raw, request_id: int) -> dict:
        head = {"url": conn.url, "tool": tool, "protocol_version": conn.protocol_version}
        if raw.truncated:
            return {"ok": False, "error": "response_too_large", **head, "detail": _TOO_LARGE}
        if 300 <= raw.status < 400:
            return {"ok": False, "error": "redirect_not_followed", **head, "detail": _REDIRECT}
        if raw.status == 404 and conn.session_id:
            return self._expired(conn, tool, False)
        message = _match(raw, request_id)
        if raw.status == 200 and message is not None and isinstance(message.get("result"), dict):
            result = message["result"]
            content = result.get("content")
            return {
                "ok": True,
                **head,
                "content": content if isinstance(content, list) else [],
                "is_error": result.get("isError") is True,
            }
        if raw.status == 200:
            return {"ok": False, "error": "invalid_response", **head, "detail": _INVALID_RESPONSE}
        return {
            "ok": False,
            "error": "request_failed",
            **head,
            "http_status": raw.status,
            "detail": f"The server returned HTTP {raw.status}. Nothing was paid.",
        }

    def _expired(self, conn: _Conn, tool: str, token_kept: bool) -> dict:
        return {
            "ok": False,
            "error": "session_expired",
            "url": conn.url,
            "tool": tool,
            "protocol_version": conn.protocol_version,
            "token_kept": token_kept,
            "detail": "The MCP session expired. Nothing was paid.",
        }

    def _caught(self, conn: _Conn, tool: str, exc: BuyerError) -> dict:
        return {
            "ok": False,
            "error": exc.code,
            "url": conn.url,
            "tool": tool,
            "protocol_version": conn.protocol_version,
            "detail": exc.message,
        }

    async def _close(self, conn: _Conn) -> None:
        session = conn.session_id
        if not session:
            return
        conn.session_id = None
        headers = {
            "Accept": _ACCEPT,
            "MCP-Protocol-Version": conn.protocol_version or _PROPOSED,
            "Mcp-Session-Id": session,
        }
        try:
            await self.buyer._send("DELETE", conn.url, headers, None)
        except Exception:
            return


async def list_remote_tools(buyer: Buyer, url: object) -> Presentation:
    return await _Remote(buyer).list_tools(url)


async def call_remote_tool(
    buyer: Buyer,
    url: object,
    tool: object,
    arguments: object = None,
    mode: object = "human",
    payment_signature: object = None,
) -> Presentation:
    return await _Remote(buyer).call_tool(url, tool, arguments, mode, payment_signature)
