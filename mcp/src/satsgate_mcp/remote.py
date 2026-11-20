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
from satsgate_mcp.buyer import (
    Buyer,
    BuyerError,
    Presentation,
    _REQUOTE,
    _X402_ERRORS,
    _X402_RETRY_NEW,
    _challenge_from_quote,
    _clean_payment_signature,
    _first_display,
    _retry_after,
)
from satsgate_mcp.challenge import Challenge, ChallengeError, parse_challenge
from satsgate_mcp.nwc import NwcError
from satsgate_mcp.qr import invoice_qr
from satsgate_mcp.urls import validate_url
from satsgate_mcp.x402 import payment_response_fields, payment_response_object

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
_REMOTE_HUMAN = (
    "Pay this invoice from any Lightning wallet, then call remote_call_tool again with the same url and tool. "
    "Do not send a preimage. The same invoice is used until it expires. Do not call check_payment for a remote tool."
)
_REMOTE_PAY_DETAIL = (
    "This MCP server does not hold a buyer private key, does not sign, and does not submit this payment. "
    "Satsgate does not custody, forward, or refund it. "
    "Pay the exact atomic amount from an external wallet, on the network and asset in this offer, to pay_to, "
    "for resource_url. Then call remote_call_tool again with the same url and tool and payment_signature set to "
    "that PAYMENT-SIGNATURE. It is sent inside the tool call, never together with an L402 Authorization. "
    "The proxy verifies, calls the tool, and settles only after the tool succeeds. If the tool fails, nothing is settled. "
    "Retry the same PAYMENT-SIGNATURE."
)
_D_FREE = "The tool returned a result. Nothing was paid."
_D_PAID = (
    "The tool returned a result after one Lightning payment. "
    "The token is stored for later calls to this tool while it has uses or time."
)
_D_REUSED = "The tool returned a result with a stored token. Nothing new was paid."
_D_SETTLED = (
    "The invoice is settled and the tool returned a result. "
    "The token is stored for later calls to this tool while it has uses or time."
)
_D_X402 = (
    "The tool returned a result. payment_response, when present, is the settlement report "
    "(success, transaction, network, payer). This server did not sign the payment and did not log it."
)
_PENDING_DETAIL = (
    "The invoice is not settled yet. Pay it if you have not, then call remote_call_tool again with the same url and tool. "
    "Do not pay a second invoice."
)
_PREIMAGE_DETAIL = (
    "The payee wallet did not advertise LUD-21 verify, so a retry without the preimage cannot finish. "
    "Call remote_call_tool with mode nwc, which pays with the preimage, or use a wallet that can show the preimage."
)
_REQUOTE_DETAIL = (
    "The server rejected the token ({reason}). Here is a new quote. "
    "It was not paid. Call remote_call_tool again if you want to pay it."
)
_PAYWALL_KEYS = {"error", "tool", "reason", "retry_after_seconds", "hint", "payment_hash"}
_LIGHTNING_KEYS = (
    "amount_sats",
    "invoice",
    "invoice_expires_at",
    "macaroon",
    "payment_hash",
    "resource",
    "max_uses",
    "access_seconds",
)
_TOOL_MESSAGE = "tool must be a non-empty string of at most 128 characters without control characters."
_ARGUMENTS_OBJECT = "arguments must be a JSON object with string keys."
_ARGUMENTS_JSON = "arguments must be JSON-serializable."
_ARGUMENTS_SIZE = "arguments are above SATSGATE_MCP_MAX_BODY_BYTES."
_MODE = "mode must be human or nwc."
_SIGNATURE_TYPE = "payment_signature must be a string. It was not sent."
_SIGNATURE_OBJECT = "PAYMENT-SIGNATURE must be base64 of a JSON object. It was not sent."


@dataclass
class _Call:
    conn: _Conn
    tool: str
    arguments: dict
    mode: str
    name_header: str | None
    param_headers: dict
    signature: dict | None
    signature_text: str | None
    key: str
    paid: bool = False
    token_in_use: bool = False
    signature_sent: bool = False
    secrets: tuple = ()


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


def _object(body: bytes) -> dict:
    if not body:
        return {}
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _generic_document(result: dict) -> dict | None:
    structured = result.get("structuredContent")
    if isinstance(structured, dict) and structured.get("error") == "payment_required" and "tool" in structured:
        return None
    if isinstance(structured, dict) and structured.get("x402Version") == 2 and isinstance(structured.get("accepts"), list):
        return structured
    content = result.get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        return None
    if content[0].get("type") != "text" or not isinstance(content[0].get("text"), str):
        return None
    try:
        parsed = json.loads(content[0]["text"])
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict) and parsed.get("x402Version") == 2 and isinstance(parsed.get("accepts"), list):
        return parsed
    return None


def _challenge_for_notice(url: str, structured: dict, *, generic: bool) -> Challenge:
    if generic:
        required = base64.standard_b64encode(_dumps(structured)).decode("ascii")
        body = b""
    else:
        lightning = structured.get("lightning") if isinstance(structured.get("lightning"), dict) else {}
        body_obj = {key: lightning[key] for key in _LIGHTNING_KEYS if key in lightning}
        if "reason" in structured:
            body_obj["reason"] = structured["reason"]
        if isinstance(structured.get("x402"), dict):
            body_obj["x402"] = structured["x402"]
        if "x402Version" in structured:
            document = {key: structured[key] for key in ("x402Version", "resource", "accepts") if key in structured}
            required = base64.standard_b64encode(_dumps(document)).decode("ascii")
        else:
            required = ""
        body = _dumps(body_obj)
    return parse_challenge(
        method="POST",
        url=url,
        status=402,
        www_authenticate="",
        body=body,
        request_body=None,
        payment_required=required,
    )


def _suffix(ctx: "_Call", paid: bool, token_kept: bool) -> str:
    if ctx.signature_sent or ctx.signature is not None and paid:
        return " Retry the same payment_signature while the offer is valid. It is settled at most once."
    if token_kept or ctx.token_in_use or paid:
        return " The stored token was kept. Call remote_call_tool again to retry with it. Do not pay again."
    return " Nothing was paid."


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
        signature = _validate_signature(payment_signature)
        async with self.buyer.hold_remote(_cache_key(target, name)):
            return await self._locked_call(target, name, payload, way, signature, payment_signature)

    async def _locked_call(self, target, name, payload, way, signature, payment_signature) -> Presentation:
        conn: _Conn | None = None
        try:
            conn = await self._connect(target)
            tools, truncated = await self._list(conn)
            found = next((item for item in tools if item["name"] == name), None)
            if found is None:
                raise BuyerError("unknown_tool", _UNKNOWN_CUT if truncated else _UNKNOWN)
            name_header, param_headers = self._call_headers(conn, found["input_schema"], name, payload)
            try:
                return await self._invoke(
                    conn,
                    name,
                    payload,
                    way,
                    name_header,
                    param_headers,
                    signature,
                    payment_signature if isinstance(payment_signature, str) else None,
                )
            except BuyerError as exc:
                if exc.code not in {"timeout", "connection_failed"}:
                    raise
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
            supplied = body_params.get("_meta") if isinstance(body_params.get("_meta"), dict) else {}
            meta = _envelope(_MODERN)
            for key, value in supplied.items():
                meta[key] = value
            body_params["_meta"] = meta
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
        signature: dict | None,
        signature_text: str | None,
    ) -> Presentation:
        ctx = _Call(conn, tool, arguments, mode, name_header, param_headers, signature, signature_text, _cache_key(conn.url, tool))
        if signature is not None:
            return await self._with_signature(ctx)
        token = self.buyer._usable_token(ctx.key)
        if token is not None:
            return await self._with_token(ctx, token)
        quote = self._reusable_lightning(ctx.key)
        if quote is not None and mode == "nwc":
            return await self._pay_lightning(ctx, quote)
        if quote is not None and mode == "human":
            return await self._human_quote(ctx, quote)
        raw, request_id, expired = await self._tools_call(ctx, None, None)
        if expired is not None:
            return Presentation(expired)
        return await self._after_unpaid(ctx, raw, request_id)

    async def _tools_call(self, ctx: "_Call", authorization: str | None, payment: dict | None):
        params: dict = {"name": ctx.tool, "arguments": ctx.arguments}
        if payment is not None:
            params["_meta"] = {"x402/payment": payment}
        extra = {"Authorization": authorization} if authorization else None
        raw, request_id = await self._post(
            ctx.conn,
            "tools/call",
            params,
            name_header=ctx.name_header,
            param_headers=ctx.param_headers,
            extra=extra,
        )
        if raw.status == 404 and ctx.conn.session_id:
            return raw, request_id, self._expired(ctx, bool(ctx.token_in_use or ctx.paid))
        return raw, request_id, None

    async def _after_unpaid(self, ctx: "_Call", raw, request_id: int) -> Presentation:
        if raw.truncated:
            return Presentation(self._fail(ctx, "response_too_large", _TOO_LARGE))
        found = self._classify(ctx, raw, request_id)
        if found.get("session"):
            return Presentation(found["session"])
        if found["kind"] == "notice":
            return await self._on_notice(ctx, found["challenge"], found.get("challenge_error"), paid_retry=False)
        if found["kind"] == "success":
            return Presentation(self._ok(ctx, found["result"], detail=_D_FREE, paid=False, paid_with=None, paid_sats=None, reused=False, payment_hash=None, uses=None, access_until=None))
        return Presentation(self._from_class(ctx, found, paid=False, paid_with=None, paid_sats=None, token_kept=False))

    async def _on_notice(self, ctx: "_Call", challenge: Challenge | None, error: ChallengeError | None, *, paid_retry: bool) -> Presentation:
        if error is not None:
            return Presentation(self._fail(ctx, error.code, error.message))
        if challenge is None:
            return Presentation(self._fail(ctx, "request_failed", "The server returned a price notice that could not be read. Nothing was paid."))
        if paid_retry:
            self.buyer.store.delete_token(ctx.key)
            self._store_quote(ctx, challenge)
            return self._requote(ctx, challenge, challenge.reason)
        if not challenge.offers_lightning:
            self._store_quote(ctx, challenge)
            return self._x402_offer(ctx, challenge, signature_given=False)
        if ctx.mode == "human":
            self._store_quote(ctx, challenge)
            return self._human_offer(ctx, challenge)
        return await self._pay_lightning(ctx, challenge)

    async def _with_token(self, ctx: "_Call", token: dict) -> Presentation:
        ctx.token_in_use = True
        ctx.secrets = (str(token["macaroon"]), token.get("preimage") if isinstance(token.get("preimage"), str) else None)
        try:
            raw, request_id, expired = await self._tools_call(ctx, _authorization(token), None)
        except BuyerError as exc:
            return Presentation(self._transport(ctx, exc, paid=False, token_kept=True))
        if expired is not None:
            return Presentation(expired)
        found = self._classify(ctx, raw, request_id)
        if found["kind"] == "success":
            uses, access_until = self._decrement_token(token)
            return Presentation(
                self._ok(
                    ctx,
                    found["result"],
                    detail=_D_REUSED,
                    paid=False,
                    paid_with=None,
                    paid_sats=None,
                    reused=True,
                    payment_hash=str(token["payment_hash"]),
                    uses=uses,
                    access_until=access_until,
                )
            )
        if found["kind"] == "notice" and found.get("challenge") is not None:
            self.buyer.store.delete_token(ctx.key)
            challenge = found["challenge"]
            self._store_quote(ctx, challenge)
            reason = challenge.reason or "unknown"
            if ctx.mode == "nwc" and self.buyer.settings.auto_pay and reason in _REQUOTE and challenge.offers_lightning:
                return await self._pay_lightning(ctx, challenge)
            return self._requote(ctx, challenge, reason)
        if found["kind"] == "notice" and found.get("challenge_error") is not None:
            self.buyer.store.delete_token(ctx.key)
            err = found["challenge_error"]
            return Presentation(self._fail(ctx, err.code, err.message, token_kept=False))
        return Presentation(self._from_class(ctx, found, paid=False, paid_with=None, paid_sats=None, token_kept=True))

    async def _human_quote(self, ctx: "_Call", challenge: Challenge) -> Presentation:
        if self.buyer.settings.api_key and challenge.resource:
            state = await self.buyer._core_status(challenge)
            if state["state"] == "pending":
                return Presentation(self._pending(ctx, challenge.payment_hash, state.get("retry_after")))
            if state["state"] == "preimage_required":
                return Presentation(self._preimage(ctx, challenge.payment_hash))
            if state["state"] == "error":
                payload = dict(state["payload"])
                code = payload.get("error") or "unknown"
                payload["detail"] = (
                    f"Core rejected the token ({code}). Call remote_call_tool again for a new quote. Nothing was paid."
                )
                payload["url"] = ctx.conn.url
                payload["tool"] = ctx.tool
                payload["protocol_version"] = ctx.conn.protocol_version
                return Presentation(payload)
        raw, request_id, expired = await self._tools_call(ctx, f"L402 {challenge.macaroon}", None)
        if expired is not None:
            return Presentation(expired)
        found = self._classify(ctx, raw, request_id)
        if found["kind"] == "success":
            uses = None if challenge.max_uses is None else int(challenge.max_uses) - 1
            access_until = None if challenge.access_seconds is None else self.buyer._now() + int(challenge.access_seconds)
            self._save_token(ctx, challenge, preimage=None, uses_remaining=uses, access_until=access_until)
            self.buyer.store.delete_quote(challenge.payment_hash)
            return Presentation(
                self._ok(
                    ctx,
                    found["result"],
                    detail=_D_SETTLED,
                    paid=False,
                    paid_with="lightning",
                    paid_sats=None,
                    reused=False,
                    payment_hash=challenge.payment_hash,
                    uses=uses,
                    access_until=access_until,
                )
            )
        if found["kind"] == "pending":
            return Presentation(self._pending(ctx, found.get("payment_hash") or challenge.payment_hash, found.get("retry")))
        if found["kind"] == "notice" and found.get("challenge") is not None:
            fresh = found["challenge"]
            if fresh.payment_hash == challenge.payment_hash and fresh.reason == "preimage_required":
                return Presentation(self._preimage(ctx, challenge.payment_hash))
            if fresh.payment_hash != challenge.payment_hash:
                return self._human_offer(ctx, fresh, store=True)
            return self._human_offer(ctx, fresh, store=True)
        if found["kind"] in {"tool_error", "rpc", "request_failed", "input_required", "invalid", "redirect", "too_large", "paywall"}:
            uses = challenge.max_uses
            access_until = None if challenge.access_seconds is None else self.buyer._now() + int(challenge.access_seconds)
            self._save_token(ctx, challenge, preimage=None, uses_remaining=uses, access_until=access_until)
            self.buyer.store.delete_quote(challenge.payment_hash)
            return Presentation(self._from_class(ctx, found, paid=False, paid_with="lightning", paid_sats=None, token_kept=True, uses=uses, access_until=access_until, payment_hash=challenge.payment_hash))
        return Presentation(self._from_class(ctx, found, paid=False, paid_with=None, paid_sats=None, token_kept=False))

    async def _pay_lightning(self, ctx: "_Call", challenge: Challenge) -> Presentation:
        if not self.buyer.settings.nwc_uri:
            raise BuyerError("nwc_not_configured", _NWC_MISSING)
        blocked = refusal(self.buyer.settings, self.buyer.store, challenge.amount_sats, self.buyer._now())
        if blocked:
            self._store_quote(ctx, challenge)
            payload = self._annotated(ctx, challenge)
            payload["ok"] = False
            payload["error"] = "over_budget"
            payload["action"] = "requote"
            payload["auto_paid"] = False
            payload["detail"] = blocked
            return Presentation(payload)
        try:
            preimage = await self.buyer.wallet.pay_invoice(challenge.invoice)
        except (NwcError, BuyerError) as exc:
            raise BuyerError("nwc_failed", self.buyer._scrub(str(exc), challenge.macaroon)) from None
        if not isinstance(preimage, str) or not _PREIMAGE.fullmatch(preimage):
            raise BuyerError("nwc_failed", "NWC wallet returned a preimage that is not 64 hex characters.")
        preimage = preimage.lower()
        self.buyer.store.record_spend(
            created_at=self.buyer._now(),
            amount_sats=challenge.amount_sats,
            payment_hash=challenge.payment_hash,
            host=urlsplit(ctx.conn.url).hostname or "",
        )
        access_until = None if challenge.access_seconds is None else self.buyer._now() + int(challenge.access_seconds)
        self._save_token(ctx, challenge, preimage=preimage, uses_remaining=challenge.max_uses, access_until=access_until)
        self.buyer.store.delete_quote(challenge.payment_hash)
        ctx.paid = True
        ctx.secrets = (challenge.macaroon, preimage, ctx.signature_text)
        try:
            raw, request_id, expired = await self._tools_call(ctx, f"L402 {challenge.macaroon}:{preimage}", None)
        except BuyerError as exc:
            return Presentation(self._transport(ctx, exc, paid=True, token_kept=True, paid_with="lightning", paid_sats=challenge.amount_sats))
        if expired is not None:
            expired["paid"] = True
            expired["token_kept"] = True
            return Presentation(expired)
        found = self._classify(ctx, raw, request_id)
        if found["kind"] == "success":
            row = self.buyer.store.token_for(ctx.key)
            uses, access = self._decrement_token(dict(row))
            return Presentation(
                self._ok(
                    ctx,
                    found["result"],
                    detail=_D_PAID,
                    paid=True,
                    paid_with="lightning",
                    paid_sats=challenge.amount_sats,
                    reused=False,
                    payment_hash=challenge.payment_hash,
                    uses=uses,
                    access_until=access,
                )
            )
        if found["kind"] == "notice" and found.get("challenge") is not None:
            self.buyer.store.delete_token(ctx.key)
            fresh = found["challenge"]
            self._store_quote(ctx, fresh)
            return self._requote(ctx, fresh, fresh.reason)
        if found["kind"] == "notice" and found.get("challenge_error") is not None:
            self.buyer.store.delete_token(ctx.key)
            err = found["challenge_error"]
            return Presentation(self._fail(ctx, err.code, err.message, paid=True, paid_with="lightning", paid_sats=challenge.amount_sats, token_kept=False))
        return Presentation(
            self._from_class(
                ctx,
                found,
                paid=True,
                paid_with="lightning",
                paid_sats=challenge.amount_sats,
                token_kept=True,
                uses=challenge.max_uses,
                access_until=access_until,
                payment_hash=challenge.payment_hash,
            )
        )

    async def _with_signature(self, ctx: "_Call") -> Presentation:
        challenge = self._fresh_x402(ctx.key)
        if challenge is None:
            raw, request_id, expired = await self._tools_call(ctx, None, None)
            if expired is not None:
                return Presentation(expired)
            found = self._classify(ctx, raw, request_id)
            if found["kind"] != "notice":
                payload = self._from_class(ctx, found, paid=False, paid_with=None, paid_sats=None, token_kept=False)
                payload["signature_sent"] = False
                return Presentation(payload)
            if found.get("challenge_error") is not None:
                err = found["challenge_error"]
                payload = self._fail(ctx, err.code, err.message)
                payload["signature_sent"] = False
                return Presentation(payload)
            challenge = found["challenge"]
            if challenge is not None:
                self._store_quote(ctx, challenge)
        if challenge is None or challenge.x402 is None:
            annotated = self._annotated(ctx, challenge) if challenge is not None else {"ok": False, "url": ctx.conn.url, "tool": ctx.tool}
            annotated["ok"] = False
            annotated["error"] = "x402_not_offered"
            annotated["signature_sent"] = False
            annotated["detail"] = "This price notice does not offer x402. The PAYMENT-SIGNATURE was not sent."
            return Presentation(annotated)
        view = self.buyer._annotate(challenge).get("x402")
        if not isinstance(view, dict) or not view.get("offered"):
            return Presentation(self._x402_offer(ctx, challenge, signature_given=True).payload)
        if not view.get("payable"):
            offered = self._x402_offer(ctx, challenge, signature_given=True)
            offered.payload["signature_sent"] = False
            return offered
        ctx.secrets = (challenge.macaroon, None, ctx.signature_text)
        try:
            raw, request_id, expired = await self._tools_call(ctx, None, ctx.signature)
        except BuyerError as exc:
            return Presentation(self._transport(ctx, exc, paid=False, token_kept=False, signature_sent=True, retry_same=True))
        if expired is not None:
            expired["signature_sent"] = True
            expired["retry_same_payment_signature"] = True
            return Presentation(expired)
        ctx.signature_sent = True
        found = self._classify(ctx, raw, request_id)
        if found["kind"] == "success":
            return Presentation(self._x402_success(ctx, challenge, view, found["result"], raw))
        if found["kind"] in {"paywall", "pending"} or (found["kind"] == "request_failed" and raw.status == 402):
            return Presentation(self._x402_error(ctx, found))
        if found["kind"] == "notice":
            payload = self._fail(
                ctx,
                "payment_required",
                _X402_ERRORS["payment_required"],
                paid=False,
                signature_sent=True,
                retry_same=True,
            )
            return Presentation(payload)
        return Presentation(self._from_class(ctx, found, paid=False, paid_with=None, paid_sats=None, token_kept=False, signature_sent=True, retry_same=True))

    def _x402_success(self, ctx: "_Call", challenge: Challenge, view: dict, result: dict, raw) -> dict:
        charge = view.get("charge_atomic")
        if isinstance(charge, int) and not isinstance(charge, bool) and charge > 0:
            self.buyer.store.record_usd_spend(
                created_at=self.buyer._now(),
                amount_usd_atomic=charge,
                host=urlsplit(ctx.conn.url).hostname or "",
                resource=challenge.url,
            )
        meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        fields = payment_response_object(meta.get("x402/payment-response"))
        if fields is None:
            fields = payment_response_fields(raw.headers.get("payment-response", ""))
        flags: dict = {"signature_sent": True, "retry_same_payment_signature": False}
        display = _first_display(view)
        if display:
            flags["amount_atomic"] = display[0]
            flags["amount_display"] = display[1]
        if fields:
            flags["payment_response"] = fields
        return self._ok(
            ctx,
            result,
            detail=_D_X402,
            paid=True,
            paid_with="x402",
            paid_sats=None,
            reused=False,
            payment_hash=None,
            uses=None,
            access_until=None,
            flags=flags,
        )

    def _x402_error(self, ctx: "_Call", found: dict) -> dict:
        code = found.get("error") or "request_failed"
        explanation = _X402_ERRORS.get(code)
        if explanation is None:
            explanation = _X402_ERRORS["payment_required"]
        return self._fail(
            ctx,
            code,
            explanation,
            http_status=found.get("http_status"),
            hint=found.get("hint"),
            paywall=found["kind"] == "paywall",
            paid=False,
            signature_sent=True,
            retry_same=code not in _X402_RETRY_NEW,
        )

    def _classify(self, ctx: "_Call", raw, request_id: int) -> dict:
        if raw.truncated:
            return {"kind": "too_large"}
        if 300 <= raw.status < 400:
            return {"kind": "redirect"}
        body = _object(raw.body)
        if raw.status == 402 and body.get("error") == "payment_pending":
            return {"kind": "pending", "payment_hash": body.get("payment_hash"), "retry": _retry_after(raw, body), "http_status": 402}
        if raw.status == 402:
            try:
                challenge = parse_challenge(
                    method="POST",
                    url=ctx.conn.url,
                    status=402,
                    www_authenticate=raw.headers.get("www-authenticate", ""),
                    body=raw.body,
                    request_body=None,
                    payment_required=raw.headers.get("payment-required", ""),
                )
            except ChallengeError as exc:
                return {"kind": "notice", "challenge": None, "challenge_error": exc, "http_status": 402, "error": exc.code}
            return {"kind": "notice", "challenge": challenge, "http_status": 402}
        message = _match(raw, request_id)
        if raw.status == 200 and message is not None and isinstance(message.get("result"), dict):
            result = message["result"]
            structured = result.get("structuredContent") if isinstance(result.get("structuredContent"), dict) else None
            if result.get("isError") is True and isinstance(structured, dict) and structured.get("error") == "payment_required" and "tool" in structured:
                if structured.get("tool") != ctx.tool:
                    return {"kind": "offer_mismatch"}
                return self._notice_class(ctx, structured, generic=False)
            if (
                result.get("isError") is True
                and isinstance(structured, dict)
                and structured.get("tool") == ctx.tool
                and isinstance(structured.get("error"), str)
                and set(structured) <= _PAYWALL_KEYS
            ):
                if structured.get("error") == "payment_pending":
                    return {
                        "kind": "pending",
                        "payment_hash": structured.get("payment_hash"),
                        "retry": _retry_after(raw, structured),
                    }
                return {
                    "kind": "paywall",
                    "error": structured.get("error"),
                    "hint": structured.get("hint") if isinstance(structured.get("hint"), str) else None,
                    "retry": structured.get("retry_after_seconds") if isinstance(structured.get("retry_after_seconds"), int) else _retry_after(raw, structured) if "retry-after" in raw.headers else None,
                }
            generic = _generic_document(result)
            if result.get("isError") is True and generic is not None:
                return self._notice_class(ctx, generic, generic=True)
            if "resultType" in result and result.get("resultType") != "complete":
                return {"kind": "input_required"}
            if result.get("isError") is True:
                return {"kind": "tool_error", "result": result}
            return {"kind": "success", "result": result}
        if message is not None and isinstance(message.get("error"), dict) and "result" not in message:
            error = message["error"]
            code = error.get("code") if isinstance(error.get("code"), int) and not isinstance(error.get("code"), bool) else None
            text = error.get("message") if isinstance(error.get("message"), str) else ""
            text = self._scrub(ctx, text)[:500]
            return {"kind": "rpc", "rpc_code": code, "rpc_message": text, "http_status": raw.status}
        if raw.status == 404 and ctx.conn.session_id:
            return {"kind": "session", "session": self._expired(ctx, bool(ctx.token_in_use or ctx.paid))}
        if raw.status == 200:
            return {"kind": "invalid"}
        return {"kind": "request_failed", "http_status": raw.status, "error": body.get("error") if isinstance(body.get("error"), str) else None}

    def _notice_class(self, ctx: "_Call", structured: dict, *, generic: bool) -> dict:
        try:
            challenge = _challenge_for_notice(ctx.conn.url, structured, generic=generic)
        except ChallengeError as exc:
            return {"kind": "notice", "challenge": None, "challenge_error": exc}
        return {"kind": "notice", "challenge": challenge}

    def _from_class(self, ctx: "_Call", found: dict, *, paid: bool, paid_with, paid_sats, token_kept: bool, uses=None, access_until=None, payment_hash=None, signature_sent=None, retry_same=None) -> dict:
        kind = found["kind"]
        if kind == "tool_error":
            if ctx.signature_sent or signature_sent:
                detail = "The tool returned an error result. The payment was not settled. Retry the same payment_signature while the offer is valid."
            elif token_kept or ctx.token_in_use:
                detail = "The tool returned an error result. A failed call takes no use, so the stored token was kept. Call remote_call_tool again to retry with it."
            else:
                detail = "The tool returned an error result. Nothing was paid."
            payload = self._ok(
                ctx,
                found.get("result") or {},
                detail=detail,
                paid=paid,
                paid_with=paid_with,
                paid_sats=paid_sats,
                reused=False,
                payment_hash=payment_hash,
                uses=uses,
                access_until=access_until,
                tool_error=True,
                token_kept=token_kept,
            )
            if signature_sent or ctx.signature_sent:
                payload["signature_sent"] = True
                payload["retry_same_payment_signature"] = True if retry_same is None else retry_same
                # detail must stay last
                detail_text = payload.pop("detail")
                payload["detail"] = detail_text
            return payload
        if kind == "rpc":
            detail = "The server answered with a JSON-RPC error." + _suffix(ctx, paid, token_kept)
            return self._fail(ctx, "rpc_error", detail, http_status=found.get("http_status"), rpc_code=found.get("rpc_code"), rpc_message=found.get("rpc_message"), paid=paid, paid_with=paid_with, paid_sats=paid_sats, token_kept=token_kept, signature_sent=signature_sent, retry_same=retry_same)
        if kind == "paywall":
            code = str(found.get("error") or "paywall")
            detail = f"The paywall answered {code}."
            if found.get("retry") is not None:
                detail += " Retry after retry_after_seconds."
            detail += _suffix(ctx, paid, token_kept)
            hint = found.get("hint")
            if isinstance(hint, str):
                hint = self._scrub(ctx, hint)[:1000]
            return self._fail(ctx, code, detail, hint=hint, retry=found.get("retry"), paywall=True, paid=paid, paid_with=paid_with, paid_sats=paid_sats, token_kept=token_kept, signature_sent=signature_sent, retry_same=retry_same)
        if kind == "pending":
            return self._pending(ctx, found.get("payment_hash"), found.get("retry"))
        if kind == "input_required":
            return self._fail(ctx, "input_required_not_supported", "The tool asked for more input. This client does not support that." + _suffix(ctx, paid, token_kept), paid=paid, paid_with=paid_with, paid_sats=paid_sats, token_kept=token_kept, signature_sent=signature_sent, retry_same=retry_same)
        if kind == "invalid":
            return self._fail(ctx, "invalid_response", _INVALID_RESPONSE, paid=paid, token_kept=token_kept, signature_sent=signature_sent, retry_same=retry_same)
        if kind == "redirect":
            return self._fail(ctx, "redirect_not_followed", _REDIRECT, paid=paid, token_kept=token_kept, signature_sent=signature_sent, retry_same=retry_same)
        if kind == "too_large":
            return self._fail(ctx, "response_too_large", _TOO_LARGE, paid=paid, token_kept=token_kept, signature_sent=signature_sent, retry_same=retry_same)
        if kind == "offer_mismatch":
            return self._fail(ctx, "offer_mismatch", "The price notice names another tool. It was not paid.")
        if kind == "session":
            return found["session"]
        status = found.get("http_status")
        return self._fail(
            ctx,
            "request_failed",
            f"The server returned HTTP {status}." + _suffix(ctx, paid, token_kept),
            http_status=status,
            paid=paid,
            paid_with=paid_with,
            paid_sats=paid_sats,
            token_kept=token_kept,
            signature_sent=signature_sent,
            retry_same=retry_same,
        )

    def _ok(self, ctx, result, *, detail, paid, paid_with, paid_sats, reused, payment_hash, uses, access_until, tool_error=False, token_kept=False, flags=None) -> dict:
        content = result.get("content") if isinstance(result, dict) and isinstance(result.get("content"), list) else []
        structured = result.get("structuredContent") if isinstance(result, dict) and isinstance(result.get("structuredContent"), dict) else None
        if tool_error or (isinstance(result, dict) and result.get("isError") is True and tool_error):
            payload = {
                "ok": False,
                "error": "tool_error",
                "url": ctx.conn.url,
                "tool": ctx.tool,
                "protocol_version": ctx.conn.protocol_version,
                "is_error": True,
                "content": content,
                "structured_content": structured,
                "paid": paid,
                "paid_with": paid_with,
                "paid_sats": paid_sats,
                "reused_token": reused,
                "payment_hash": payment_hash,
                "uses_remaining": uses,
                "access_until": access_until,
                "token_kept": token_kept,
            }
        else:
            payload = {
                "ok": True,
                "url": ctx.conn.url,
                "tool": ctx.tool,
                "protocol_version": ctx.conn.protocol_version,
                "is_error": False,
                "content": content,
                "structured_content": structured,
                "paid": paid,
                "paid_with": paid_with,
                "paid_sats": paid_sats,
                "reused_token": reused,
                "payment_hash": payment_hash,
                "uses_remaining": uses,
                "access_until": access_until,
            }
        if flags:
            for key in ("signature_sent", "retry_same_payment_signature", "amount_atomic", "amount_display", "payment_response"):
                if key in flags:
                    payload[key] = flags[key]
        payload["detail"] = detail
        return payload

    def _fail(self, ctx, code, detail, *, http_status=None, rpc_code=None, rpc_message=None, hint=None, retry=None, paywall=False, paid=False, paid_with=None, paid_sats=None, token_kept=False, signature_sent=None, retry_same=None) -> dict:
        payload: dict = {
            "ok": False,
            "error": code,
            "url": ctx.conn.url,
            "tool": ctx.tool,
            "protocol_version": ctx.conn.protocol_version,
        }
        if http_status is not None:
            payload["http_status"] = http_status
        if code == "rpc_error":
            payload["rpc_code"] = rpc_code
            payload["rpc_message"] = rpc_message
        if retry is not None:
            payload["retry_after_seconds"] = retry
        if paywall:
            payload["paywall"] = True
            if isinstance(hint, str):
                payload["hint"] = hint
        payload["paid"] = paid
        payload["paid_with"] = paid_with
        payload["paid_sats"] = paid_sats
        payload["token_kept"] = token_kept
        if signature_sent is not None:
            payload["signature_sent"] = signature_sent
            payload["retry_same_payment_signature"] = bool(retry_same)
        payload["detail"] = detail
        return payload

    def _pending(self, ctx, payment_hash, retry) -> dict:
        payload = self._fail(ctx, "payment_pending", _PENDING_DETAIL, retry=retry or 2, paid=False, token_kept=False)
        payload.pop("paid")
        payload.pop("paid_with")
        payload.pop("paid_sats")
        payload.pop("token_kept")
        # Keep the documented order: class fields, then paid flags, then detail.
        detail = payload.pop("detail")
        ordered = {
            "ok": False,
            "error": "payment_pending",
            "url": ctx.conn.url,
            "tool": ctx.tool,
            "protocol_version": ctx.conn.protocol_version,
            "payment_hash": payment_hash if isinstance(payment_hash, str) else None,
            "retry_after_seconds": retry or 2,
            "paid": False,
            "paid_with": None,
            "paid_sats": None,
            "token_kept": False,
            "detail": detail,
        }
        return ordered

    def _preimage(self, ctx, payment_hash) -> dict:
        return {
            "ok": False,
            "error": "preimage_required",
            "url": ctx.conn.url,
            "tool": ctx.tool,
            "protocol_version": ctx.conn.protocol_version,
            "payment_hash": payment_hash,
            "paid": False,
            "paid_with": None,
            "paid_sats": None,
            "token_kept": False,
            "detail": _PREIMAGE_DETAIL,
        }

    def _transport(self, ctx, exc: BuyerError, *, paid: bool, token_kept: bool, paid_with=None, paid_sats=None, signature_sent=None, retry_same=None) -> dict:
        detail = exc.message + _suffix(ctx, paid, token_kept)
        return self._fail(ctx, exc.code, detail, paid=paid, paid_with=paid_with, paid_sats=paid_sats, token_kept=token_kept, signature_sent=signature_sent, retry_same=retry_same)

    def _annotated(self, ctx, challenge: Challenge) -> dict:
        offer = self.buyer._annotate(challenge)
        offer["summary"] = f"Tool {ctx.tool}: {offer.get('summary') or ''}"
        offer["tool"] = ctx.tool
        offer["protocol_version"] = ctx.conn.protocol_version
        view = offer.get("x402")
        if isinstance(view, dict) and isinstance(view.get("payment"), dict):
            view["payment"]["detail"] = _REMOTE_PAY_DETAIL
        return offer

    def _human_offer(self, ctx, challenge: Challenge, *, store: bool = True) -> Presentation:
        if store:
            self._store_quote(ctx, challenge)
        offer = self._annotated(ctx, challenge)
        png, text = invoice_qr(challenge.invoice)
        offer["mode"] = "human"
        offer["action"] = "pay_invoice"
        offer["qr_text"] = text
        view = offer.get("x402") if isinstance(offer.get("x402"), dict) else None
        if view and view.get("payable"):
            offer["detail"] = (
                _REMOTE_HUMAN
                + " This price notice also offers USDC. Paying the invoice does not pay the USDC amount. "
                + str(view["payment"]["detail"])
            )
        elif view:
            extra = view.get("cap_detail") or view.get("detail") or ""
            offer["detail"] = f"{_REMOTE_HUMAN} {extra}".strip()
        else:
            offer["detail"] = _REMOTE_HUMAN
        return Presentation(offer, png)

    def _x402_offer(self, ctx, challenge: Challenge, *, signature_given: bool) -> Presentation:
        offer = self._annotated(ctx, challenge)
        offer["mode"] = ctx.mode
        offer["auto_paid"] = False
        view = offer.get("x402") if isinstance(offer.get("x402"), dict) else {}
        if view.get("payable"):
            offer["action"] = "pay_x402_external"
            detail = str(view["payment"]["detail"])
            if ctx.mode == "nwc":
                detail = "NWC pays a Lightning invoice. This price notice has no invoice. " + detail
            offer["detail"] = detail
            return Presentation(offer)
        offer["ok"] = False
        offer["error"] = "x402_not_offered" if not view.get("offered") else (view.get("error") or "not_payable")
        offer["action"] = "refused" if view.get("offered") else "requote"
        if signature_given or not view.get("offered"):
            offer["signature_sent"] = False
        if not view.get("offered"):
            offer["detail"] = "This price notice does not offer x402. The PAYMENT-SIGNATURE was not sent."
        else:
            offer["detail"] = str(view.get("cap_detail") or view.get("detail") or "The USDC requirement was not paid.")
        return Presentation(offer)

    def _requote(self, ctx, challenge: Challenge, reason: str | None) -> Presentation:
        if challenge.offers_lightning:
            presented = self._human_offer(ctx, challenge, store=False)
            presented.payload["action"] = "requote"
            presented.payload["auto_paid"] = False
            presented.payload["mode"] = ctx.mode
            presented.payload["detail"] = _REQUOTE_DETAIL.format(reason=reason or "unknown")
            return presented
        presented = self._x402_offer(ctx, challenge, signature_given=False)
        presented.payload["action"] = "requote"
        presented.payload["auto_paid"] = False
        presented.payload["detail"] = _REQUOTE_DETAIL.format(reason=reason or "unknown")
        return presented

    def _store_quote(self, ctx, challenge: Challenge) -> None:
        self.buyer.store.save_quote(
            {
                "payment_hash": challenge.payment_hash,
                "cache_key": ctx.key,
                "method": "POST",
                "url": ctx.conn.url,
                "macaroon": challenge.macaroon,
                "invoice": challenge.invoice,
                "resource": challenge.resource,
                "amount_sats": challenge.amount_sats,
                "max_uses": challenge.max_uses,
                "access_seconds": challenge.access_seconds,
                "invoice_expires_at": challenge.invoice_expires_at,
                "reason": challenge.reason,
                "request_body": None,
                "created_at": self.buyer._now(),
                "x402_json": None if challenge.x402 is None else challenge.x402.to_json(),
            }
        )

    def _save_token(self, ctx, challenge: Challenge, *, preimage, uses_remaining, access_until) -> None:
        self.buyer.store.save_token(
            {
                "cache_key": ctx.key,
                "method": "POST",
                "url": ctx.conn.url,
                "macaroon": challenge.macaroon,
                "preimage": preimage,
                "payment_hash": challenge.payment_hash,
                "resource": challenge.resource,
                "amount_sats": challenge.amount_sats,
                "max_uses": challenge.max_uses,
                "access_seconds": challenge.access_seconds,
                "uses_remaining": uses_remaining,
                "access_until": access_until,
                "invoice_expires_at": challenge.invoice_expires_at,
                "updated_at": self.buyer._now(),
            }
        )

    def _decrement_token(self, row: dict) -> tuple:
        remaining = row.get("uses_remaining")
        if remaining is not None:
            remaining = int(remaining) - 1
        updated = dict(row)
        updated["uses_remaining"] = remaining
        updated["updated_at"] = self.buyer._now()
        self.buyer.store.save_token(updated)
        return remaining, updated.get("access_until")

    def _reusable_lightning(self, key: str) -> Challenge | None:
        row = self.buyer.store.quote_for(key)
        if row is None:
            return None
        challenge = _challenge_from_quote(row)
        if not challenge.invoice:
            return None
        expires = challenge.invoice_expires_at
        if expires is not None and self.buyer._now() >= int(expires):
            self.buyer.store.delete_quote(challenge.payment_hash)
            return None
        return challenge

    def _fresh_x402(self, key: str) -> Challenge | None:
        row = self.buyer.store.quote_for(key)
        if row is None:
            return None
        challenge = _challenge_from_quote(row)
        if challenge.x402 is None:
            return None
        expires = challenge.x402.expires_at
        if expires is not None and self.buyer._now() >= int(expires):
            return None
        return challenge

    def _expired(self, ctx, token_kept: bool) -> dict:
        detail = "The MCP session expired." + (_suffix(ctx, ctx.paid, token_kept))
        return {
            "ok": False,
            "error": "session_expired",
            "url": ctx.conn.url,
            "tool": ctx.tool,
            "protocol_version": ctx.conn.protocol_version,
            "token_kept": token_kept,
            "detail": detail,
        }

    def _scrub(self, ctx, text: str) -> str:
        extra = [item for item in (ctx.secrets or ()) if isinstance(item, str)]
        if ctx.signature_text:
            extra.append(ctx.signature_text)
        return self.buyer._scrub(text, *extra)

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
