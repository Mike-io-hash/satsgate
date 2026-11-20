"""MCP checks for one opted-in route. Validation finishes before any invoice."""

from __future__ import annotations

import base64
import json
import logging
import re
import unicodedata
from dataclasses import dataclass

from satsgate_proxy.config import McpPolicy, tool_resource

log = logging.getLogger("satsgate_proxy")

PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
)
UNSUPPORTED_METHODS = (
    "subscriptions/listen",
    "tasks/get",
    "tasks/result",
    "tasks/list",
    "tasks/cancel",
)
_NAME_FIELDS = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}
_WATCHED = ("tools/call", *UNSUPPORTED_METHODS)
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_B64_NAME = re.compile(r"^=\?base64\?(.*)\?=$")
_ROUTING = ("mcp-protocol-version", "mcp-method", "mcp-name")
_META_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
ZERO_PAYMENT_HASH = "0" * 64
_RESOURCE_MAX = 200

_CODE = {
    "invalid_json": -32700,
    "unsupported_content_type": -32600,
    "accept_json_and_sse_required": -32600,
    "invalid_message": -32600,
    "invalid_method": -32600,
    "invalid_tool_call": -32600,
    "tasks_not_supported": -32600,
    "invalid_tool_name": -32600,
    "batch_with_paid_tool": -32600,
    "delete_body_not_allowed": -32600,
    "duplicate_routing_header": -32020,
    "header_mismatch": -32020,
    "unsupported_protocol_version": -32022,
    "missing_request_envelope": -32602,
    "unsupported_method": -32601,
}
_TEXT = {
    "invalid_json": "The body is not valid JSON.",
    "unsupported_content_type": "Content-Type must be application/json.",
    "accept_json_and_sse_required": "Accept must list application/json and text/event-stream.",
    "invalid_message": "The JSON-RPC message is not valid.",
    "invalid_method": "The method name is not accepted.",
    "invalid_tool_call": "The tool call is not valid.",
    "tasks_not_supported": "Tasks are not supported.",
    "invalid_tool_name": "The tool name is not accepted.",
    "batch_with_paid_tool": "A batch cannot include a priced tool.",
    "delete_body_not_allowed": "DELETE must not include a body.",
    "duplicate_routing_header": "A routing header is repeated.",
    "header_mismatch": "A routing header does not match the body.",
    "unsupported_protocol_version": "The protocol version is not supported.",
    "missing_request_envelope": "The request is missing its protocol envelope.",
    "unsupported_method": "Method not supported by this gateway",
}


@dataclass(frozen=True)
class RpcError:
    word: str
    request_id: object = None
    extra: dict | None = None

    @property
    def code(self) -> int:
        return _CODE[self.word]

    @property
    def message(self) -> str:
        return _TEXT[self.word]


@dataclass(frozen=True)
class Parsed:
    messages: tuple[dict, ...]
    batch: bool
    request_id: object
    version: str | None


@dataclass(frozen=True)
class FreeForward:
    tool_name: str | None


@dataclass(frozen=True)
class PaidCall:
    tool_name: str
    request_id: object


@dataclass(frozen=True)
class UnsupportedCall:
    notification: bool
    request_id: object


def canon(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold()


def encode_tool_header(name: str) -> str:
    plain = bool(name) and name.isascii() and all(32 <= ord(char) <= 126 for char in name) and name == name.strip()
    if plain:
        return name
    payload = base64.b64encode(name.encode("utf-8")).decode("ascii")
    return f"=?base64?{payload}?="


def decode_mcp_name(value: str) -> str | None:
    match = _B64_NAME.fullmatch(value)
    if match is None:
        return value
    try:
        raw = base64.b64decode(match.group(1), validate=True)
        if base64.b64encode(raw).decode("ascii") != match.group(1):
            return None
        return raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def _reject_constant(_value: str) -> None:
    raise ValueError("invalid number")


def parse_json(text: str) -> object:
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)


def _valid_request_id(value: object) -> bool:
    if isinstance(value, bool) or isinstance(value, float):
        return False
    return isinstance(value, (str, int))


def _valid_response_id(value: object) -> bool:
    if value is None:
        return True
    return _valid_request_id(value)


def _message_kind(message: object) -> str | None:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return None
    has_method = "method" in message
    has_result = "result" in message
    has_error = "error" in message
    if has_method and (has_result or has_error):
        return None
    if has_method:
        if not isinstance(message["method"], str):
            return None
        if "params" in message and not isinstance(message["params"], dict):
            return None
        if "id" in message:
            if not _valid_request_id(message["id"]):
                return None
            return "request"
        return "notification"
    if "id" not in message or has_result == has_error:
        return None
    if not _valid_response_id(message["id"]):
        return None
    return "response"


def _disguised(method: str) -> bool:
    folded = canon(method)
    for name in _WATCHED:
        if folded == canon(name) and method != name:
            return True
    return False


def _tool_problem(message: dict) -> str | None:
    if message.get("method") != "tools/call":
        return None
    if "id" not in message:
        return "invalid_message"
    params = message.get("params")
    if not isinstance(params, dict):
        return "invalid_tool_call"
    name = params.get("name")
    if not isinstance(name, str) or name == "":
        return "invalid_tool_call"
    if "task" in params and params["task"] is not None:
        return "tasks_not_supported"
    return None


def _media_types(values: list[str]) -> set[str]:
    found: set[str] = set()
    for value in values:
        for part in value.split(","):
            media = part.split(";", 1)[0].strip().lower()
            if media:
                found.add(media)
    return found


def _routing(raw_headers: list[tuple[bytes, bytes]]) -> tuple[dict[str, str | None], str | None]:
    found: dict[str, list[str]] = {name: [] for name in _ROUTING}
    for key, value in raw_headers:
        name = key.decode("latin-1").lower()
        if name in found:
            found[name].append(value.decode("latin-1"))
    if any(len(values) > 1 for values in found.values()):
        return {}, "duplicate_routing_header"
    return {
        "version": found["mcp-protocol-version"][0] if found["mcp-protocol-version"] else None,
        "method": found["mcp-method"][0] if found["mcp-method"] else None,
        "name": found["mcp-name"][0] if found["mcp-name"] else None,
    }, None


def _single_id(value: object) -> object:
    if isinstance(value, dict) and "id" in value and _valid_request_id(value["id"]):
        return value["id"]
    return None


def _header_matches(messages: tuple[dict, ...], method_header: str | None, name_header: str | None) -> str | None:
    if method_header is not None:
        if len(messages) != 1 or messages[0].get("method") != method_header:
            return "header_mismatch"
    if name_header is not None:
        if len(messages) != 1:
            return "header_mismatch"
        message = messages[0]
        method = message.get("method")
        field = _NAME_FIELDS.get(method) if isinstance(method, str) else None
        params = message.get("params")
        if field is None or "id" not in message or not isinstance(params, dict):
            return "header_mismatch"
        decoded = decode_mcp_name(name_header)
        if decoded is None or decoded != params.get(field):
            return "header_mismatch"
    return None


def _year_2026(
    messages: tuple[dict, ...],
    version: str | None,
    method_header: str | None,
    name_header: str | None,
) -> str | None:
    if version != "2026-07-28":
        return None
    if len(messages) != 1:
        return "invalid_message"
    message = messages[0]
    if "method" not in message or "id" not in message:
        return None
    if method_header is None:
        return "header_mismatch"
    method = message.get("method")
    if isinstance(method, str) and method in _NAME_FIELDS and name_header is None:
        return "header_mismatch"
    params = message.get("params")
    if not isinstance(params, dict):
        return "missing_request_envelope"
    meta = params.get("_meta")
    if not isinstance(meta, dict) or _META_VERSION not in meta or _META_CAPABILITIES not in meta:
        return "missing_request_envelope"
    if meta.get(_META_VERSION) != "2026-07-28":
        return "header_mismatch"
    return None


def _json_content_type(values: list[str]) -> bool:
    if not values:
        return False
    types = {value.split(";", 1)[0].strip().lower() for value in values}
    return types == {"application/json"}


def inspect_post(
    body: bytes,
    *,
    content_types: list[str],
    accepts: list[str],
    raw_headers: list[tuple[bytes, bytes]],
) -> Parsed | RpcError:
    if not _json_content_type(content_types):
        return RpcError("unsupported_content_type")
    if not {"application/json", "text/event-stream"} <= _media_types(accepts):
        return RpcError("accept_json_and_sse_required")
    routing, duplicate = _routing(raw_headers)
    if duplicate:
        return RpcError(duplicate)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return RpcError("invalid_json")
    if text == "" or text.startswith("\ufeff"):
        return RpcError("invalid_json")
    try:
        parsed = parse_json(text)
    except (ValueError, RecursionError):
        return RpcError("invalid_json")
    if isinstance(parsed, dict):
        messages = (parsed,)
        request_id = _single_id(parsed)
        batch = False
    elif isinstance(parsed, list) and parsed:
        if not all(isinstance(item, dict) for item in parsed):
            return RpcError("invalid_message")
        messages = tuple(parsed)
        request_id = None
        batch = True
    else:
        return RpcError("invalid_message")
    for message in messages:
        if _message_kind(message) is None:
            return RpcError("invalid_message", request_id)
        method = message.get("method")
        if isinstance(method, str) and _disguised(method):
            return RpcError("invalid_method", request_id)
        problem = _tool_problem(message)
        if problem:
            return RpcError(problem, request_id)
    version = routing.get("version")
    if version is not None and version not in PROTOCOL_VERSIONS:
        return RpcError(
            "unsupported_protocol_version",
            request_id,
            {"supported": list(PROTOCOL_VERSIONS), "requested": version},
        )
    mismatch = _header_matches(messages, routing.get("method"), routing.get("name"))
    if mismatch:
        return RpcError(mismatch, request_id)
    envelope = _year_2026(messages, version, routing.get("method"), routing.get("name"))
    if envelope:
        return RpcError(envelope, request_id)
    return Parsed(messages=messages, batch=batch, request_id=request_id, version=version)


def resolve_tool(policy: McpPolicy, route_name: str, name: str) -> str:
    """Return ``free``, ``paid``, or an error word."""

    listed = policy.tool(name)
    if listed is not None:
        return "free" if listed.free else "paid"
    for key, entry in policy.tools:
        if not entry.free and canon(name) == canon(key):
            return "invalid_tool_name"
    if not policy.default.free:
        if _TOOL_NAME.fullmatch(name) is None or len(tool_resource(route_name, name)) > _RESOURCE_MAX:
            return "invalid_tool_name"
    return "free" if policy.default.free else "paid"


def classify(parsed: Parsed, policy: McpPolicy, route_name: str) -> FreeForward | PaidCall | UnsupportedCall | RpcError:
    if parsed.batch:
        for message in parsed.messages:
            method = message.get("method")
            if method in UNSUPPORTED_METHODS:
                return RpcError("invalid_message")
            if method == "tools/call":
                decision = resolve_tool(policy, route_name, message["params"]["name"])
                if decision in {"invalid_tool_name"}:
                    return RpcError(decision)
                if decision == "paid":
                    return RpcError("batch_with_paid_tool")
        return FreeForward(tool_name=None)
    message = parsed.messages[0]
    method = message.get("method")
    if method in UNSUPPORTED_METHODS:
        notification = "id" not in message
        return UnsupportedCall(notification=notification, request_id=None if notification else message["id"])
    if method == "tools/call":
        name = message["params"]["name"]
        decision = resolve_tool(policy, route_name, name)
        if decision == "invalid_tool_name":
            return RpcError(decision, parsed.request_id)
        if decision == "free":
            return FreeForward(tool_name=name)
        return PaidCall(tool_name=name, request_id=message["id"])
    return FreeForward(tool_name=None)


def rejection_body(error: RpcError) -> dict:
    data: dict[str, object] = {"error": error.word}
    if error.extra:
        data.update(error.extra)
    return {
        "jsonrpc": "2.0",
        "id": error.request_id,
        "error": {"code": error.code, "message": error.message, "data": data},
    }


def note_rejection(error: RpcError) -> None:
    log.info("mcp rejected %s", error.word)


def _same_id(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    return left == right


def _client_response(message: object) -> bool:
    if not isinstance(message, dict) or "method" in message or "id" not in message:
        return False
    return "result" in message or "error" in message


def _content_type(headers: object) -> str:
    if isinstance(headers, dict):
        pairs = headers.items()
    else:
        pairs = headers or ()
    for name, value in pairs:
        if str(name).lower() == "content-type":
            return str(value).split(";", 1)[0].strip().lower()
    return ""


def _iter_sse_lines(text: str):
    index = 0
    limit = len(text)
    while index < limit:
        carriage = text.find("\r", index)
        linefeed = text.find("\n", index)
        if carriage == -1 and linefeed == -1:
            yield text[index:]
            return
        if carriage == -1 or (linefeed != -1 and linefeed < carriage):
            yield text[index:linefeed]
            index = linefeed + 1
            continue
        yield text[index:carriage]
        index = carriage + 2 if carriage + 1 < limit and text[carriage + 1] == "\n" else carriage + 1


def _sse_payloads(text: str) -> list[str]:
    payloads: list[str] = []
    data: list[str] = []

    def finish() -> None:
        if not data:
            return
        joined = "\n".join(data)
        data.clear()
        if joined != "":
            payloads.append(joined)

    for line in _iter_sse_lines(text):
        if line == "":
            finish()
            continue
        if line.startswith(":"):
            continue
        if ":" in line:
            field, _, value = line.partition(":")
            if value.startswith(" "):
                value = value[1:]
        else:
            field, value = line, ""
        if field == "data":
            data.append(value)
    finish()
    return payloads


def _tool_result_ok(message: dict) -> bool:
    if "error" in message:
        return False
    result = message.get("result")
    if not isinstance(result, dict):
        return False
    if "isError" in result and result["isError"] is not False:
        return False
    if "resultType" in result and result["resultType"] != "complete":
        return False
    return "task" not in result


def mcp_tool_succeeded(status: int, headers: object, body: bytes, request_id: object) -> bool:
    """True only when the origin returned the tool result for this request id."""

    try:
        if status < 0 or not body:
            return False
        media = _content_type(headers)
        found: list[dict] = []
        if media == "application/json":
            parsed = parse_json(body.decode("utf-8"))
            if not isinstance(parsed, dict):
                return False
            if _client_response(parsed):
                found.append(parsed)
        elif media == "text/event-stream":
            for payload in _sse_payloads(body.decode("utf-8")):
                parsed = parse_json(payload)
                if _client_response(parsed):
                    found.append(parsed)
        else:
            return False
        matched = [item for item in found if _same_id(item.get("id"), request_id)]
        if len(matched) != 1:
            return False
        return _tool_result_ok(matched[0])
    except Exception:
        return False
