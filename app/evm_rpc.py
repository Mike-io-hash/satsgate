"""Read-only Base mainnet checks for EIP-1271 and ERC-6492 payee signatures.

Satsgate does not deploy a contract and does not send a transaction. A smart
wallet is proven with eth_chainId, eth_getCode, and eth_call. The EOA path
never reaches this module.

The deployless ERC-6492 checker is viem's ``erc6492SignatureValidatorByteCode``
(also exported as ``universalSignatureValidatorByteCode``) from
``src/constants/contracts.ts`` at commit ``f134e8e20415986573d88dbf2a1c8cf0327c8b5a``
(https://github.com/wevm/viem/blob/f134e8e20415986573d88dbf2a1c8cf0327c8b5a/src/constants/contracts.ts).
That bytecode is the EIP-6492 ``ValidateSigOffchain`` creation code: the
constructor returns one byte, ``0x01`` or ``0x00``, with ``return(31, 1)``.
SHA-256 of the raw bytes (no ``0x``) is ``ERC6492_BYTECODE_SHA256``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from . import config
from .rate_limit import RateLimiter
from .ssrf import SSRFError, safe_post_json

log = logging.getLogger("satsgate.evm")

BASE_CHAIN_ID = 8453
CALL_TIMEOUT_SECONDS = 4.0
BUDGET_SECONDS = 8.0
ERC6492_MAGIC = bytes.fromhex("6492" * 16)
IS_VALID_SIGNATURE = bytes.fromhex("1626ba7e")
# Left-aligned bytes4 magic inside a 32-byte ABI word.
IS_VALID_SIGNATURE_WORD = "0x1626ba7e" + ("0" * 56)
ERC6492_BYTECODE_SHA256 = "d46b6085a6558eb925573e4e395ccbc669a1db1b7aa49196cbb1a7540db6a470"
ERC6492_BYTECODE = "0x608060405234801561001057600080fd5b5060405161069438038061069483398101604081905261002f9161051e565b600061003c848484610048565b9050806000526001601ff35b60007f64926492649264926492649264926492649264926492649264926492649264926100748361040c565b036101e7576000606080848060200190518101906100929190610577565b60405192955090935091506000906001600160a01b038516906100b69085906105dd565b6000604051808303816000865af19150503d80600081146100f3576040519150601f19603f3d011682016040523d82523d6000602084013e6100f8565b606091505b50509050876001600160a01b03163b60000361016057806101605760405162461bcd60e51b815260206004820152601e60248201527f5369676e617475726556616c696461746f723a206465706c6f796d656e74000060448201526064015b60405180910390fd5b604051630b135d3f60e11b808252906001600160a01b038a1690631626ba7e90610190908b9087906004016105f9565b602060405180830381865afa1580156101ad573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d19190610633565b6001600160e01b03191614945050505050610405565b6001600160a01b0384163b1561027a57604051630b135d3f60e11b808252906001600160a01b03861690631626ba7e9061022790879087906004016105f9565b602060405180830381865afa158015610244573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102689190610633565b6001600160e01b031916149050610405565b81516041146102df5760405162461bcd60e51b815260206004820152603a602482015260008051602061067483398151915260448201527f3a20696e76616c6964207369676e6174757265206c656e6774680000000000006064820152608401610157565b6102e7610425565b5060208201516040808401518451859392600091859190811061030c5761030c61065d565b016020015160f81c9050601b811480159061032b57508060ff16601c14155b1561038c5760405162461bcd60e51b815260206004820152603b602482015260008051602061067483398151915260448201527f3a20696e76616c6964207369676e617475726520762076616c756500000000006064820152608401610157565b60408051600081526020810180835289905260ff83169181019190915260608101849052608081018390526001600160a01b0389169060019060a0016020604051602081039080840390855afa1580156103ea573d6000803e3d6000fd5b505050602060405103516001600160a01b0316149450505050505b9392505050565b600060208251101561041d57600080fd5b508051015190565b60405180606001604052806003906020820280368337509192915050565b6001600160a01b038116811461045857600080fd5b50565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561048c578181015183820152602001610474565b50506000910152565b600082601f8301126104a657600080fd5b81516001600160401b038111156104bf576104bf61045b565b604051601f8201601f19908116603f011681016001600160401b03811182821017156104ed576104ed61045b565b60405281815283820160200185101561050557600080fd5b610516826020830160208701610471565b949350505050565b60008060006060848603121561053357600080fd5b835161053e81610443565b6020850151604086015191945092506001600160401b0381111561056157600080fd5b61056d86828701610495565b9150509250925092565b60008060006060848603121561058c57600080fd5b835161059781610443565b60208501519093506001600160401b038111156105b357600080fd5b6105bf86828701610495565b604086015190935090506001600160401b0381111561056157600080fd5b600082516105ef818460208701610471565b9190910192915050565b828152604060208201526000825180604084015261061e816060850160208701610471565b601f01601f1916919091016060019392505050565b60006020828403121561064557600080fd5b81516001600160e01b03198116811461040557600080fd5b634e487b7160e01b600052603260045260246000fdfe5369676e617475726556616c696461746f72237265636f7665725369676e6572"

# Tests replace this. Production posts through the SSRF guard.
poster: Callable[..., tuple] | None = None
monotonic = time.monotonic

_chain_lock = threading.Lock()
_chain_ok = False

client_limiter = RateLimiter(window_seconds=600, max_requests=10, max_keys=10_000)
global_limiter = RateLimiter(window_seconds=60, max_requests=60, max_keys=4)


class RpcUnavailable(Exception):
    """No answer from Base. The caller fails closed and writes nothing."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class CallRejected(Exception):
    """The contract reverted or returned a value that is not valid for this hash."""


class NotOnBase(Exception):
    """eth_getCode returned empty code and the signature is not ERC-6492."""


def reset_chain_cache() -> None:
    global _chain_ok
    with _chain_lock:
        _chain_ok = False


def allow_smart_check(client_id: int) -> tuple[bool, int]:
    """One slot per verify, not per candidate. The client window is checked first."""
    allowed, retry_after = client_limiter.allow(f"c:{int(client_id)}")
    if not allowed:
        return False, retry_after
    return global_limiter.allow("global")


def is_erc6492(signature: bytes) -> bool:
    return len(signature) >= 32 and signature.endswith(ERC6492_MAGIC)


def is_valid_contract_signature(address: str, digests: tuple[bytes, ...], signature: bytes) -> bool:
    """True when one digest is valid on Base. False when Base answered and said no.

    Raises ``RpcUnavailable`` when Base did not answer, ``NotOnBase`` when the
    address has no code and the signature is not the ERC-6492 wrapper.
    """
    if not digests:
        return False
    started = monotonic()

    def remaining() -> float:
        return BUDGET_SECONDS - (monotonic() - started)

    _ensure_chain(remaining)
    if is_erc6492(signature):
        for digest in digests:
            try:
                result = _eth_call(None, _erc6492_data(address, digest, signature), remaining)
            except CallRejected:
                continue
            if _is_byte_true(result):
                return True
        return False
    code = _eth_get_code(address, remaining)
    if _code_empty(code):
        raise NotOnBase
    for digest in digests:
        try:
            result = _eth_call(address, _is_valid_signature_data(digest, signature), remaining)
        except CallRejected:
            continue
        if result.lower() == IS_VALID_SIGNATURE_WORD:
            return True
    return False


def _ensure_chain(remaining: Callable[[], float]) -> None:
    global _chain_ok
    if _chain_ok:
        return
    with _chain_lock:
        if _chain_ok:
            return
        result = _rpc("eth_chainId", [], remaining)
        try:
            chain_id = int(result, 16)
        except (TypeError, ValueError) as exc:
            raise RpcUnavailable("chain") from exc
        if chain_id != BASE_CHAIN_ID:
            log.warning("smart_wallet_check_unavailable reason=chain")
            raise RpcUnavailable("chain")
        _chain_ok = True


def _eth_get_code(address: str, remaining: Callable[[], float]) -> str:
    return _rpc("eth_getCode", [address, "latest"], remaining)


def _eth_call(to: str | None, data: str, remaining: Callable[[], float]) -> str:
    tx: dict[str, str] = {"data": data}
    if to is not None:
        tx["to"] = to
    try:
        return _rpc("eth_call", [tx, "latest"], remaining)
    except CallRejected:
        raise
    except RpcUnavailable:
        raise


def _rpc(method: str, params: list, remaining: Callable[[], float]) -> str:
    left = remaining()
    if left <= 0:
        log.warning("smart_wallet_check_unavailable reason=budget")
        raise RpcUnavailable("budget")
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        status, body = _post(payload, min(CALL_TIMEOUT_SECONDS, left))
    except RpcUnavailable:
        raise
    if status != 200 or not isinstance(body, dict):
        log.warning("smart_wallet_check_unavailable reason=http")
        raise RpcUnavailable("http")
    error = body.get("error")
    if error:
        if _is_revert(error):
            raise CallRejected
        log.warning("smart_wallet_check_unavailable reason=rpc")
        raise RpcUnavailable("rpc")
    result = body.get("result")
    if not isinstance(result, str) or not result.startswith("0x"):
        log.warning("smart_wallet_check_unavailable reason=rpc")
        raise RpcUnavailable("rpc")
    return result


def _post(payload: dict, timeout: float) -> tuple[int, dict | None]:
    fn = poster
    try:
        if fn is not None:
            result = fn(config.BASE_RPC_URL, payload, {}, timeout)
        else:
            result = safe_post_json(config.BASE_RPC_URL, payload, timeout=timeout)
    except SSRFError as exc:
        log.warning("smart_wallet_check_unavailable reason=%s", exc.code)
        raise RpcUnavailable(exc.code) from None
    except RpcUnavailable:
        raise
    except Exception:
        log.warning("smart_wallet_check_unavailable reason=fetch_failed")
        raise RpcUnavailable("fetch_failed") from None
    if not isinstance(result, tuple) or len(result) != 2:
        log.warning("smart_wallet_check_unavailable reason=http")
        raise RpcUnavailable("http")
    status, body = result
    if body is not None and not isinstance(body, dict):
        log.warning("smart_wallet_check_unavailable reason=http")
        raise RpcUnavailable("http")
    return int(status), body


def _is_revert(error: object) -> bool:
    if not isinstance(error, dict):
        return False
    code = error.get("code")
    if code == 3:
        return True
    message = error.get("message")
    if isinstance(message, str) and "revert" in message.lower():
        return True
    data = error.get("data")
    return isinstance(data, str) and data.startswith("0x08c379a0")


def _code_empty(code: str) -> bool:
    body = code[2:]
    return body == "" or set(body) <= {"0"}


def _is_byte_true(result: str) -> bool:
    return result.lower() == "0x01"


def _pad_bytes(data: bytes) -> bytes:
    pad = (32 - (len(data) % 32)) % 32
    return len(data).to_bytes(32, "big") + data + (b"\x00" * pad)


def _encode_address(address: str) -> bytes:
    return bytes.fromhex(address[2:].rjust(64, "0"))


def _abi_address_bytes32_bytes(address: str, digest: bytes, signature: bytes) -> bytes:
    tail = _pad_bytes(signature)
    head = _encode_address(address) + digest + (96).to_bytes(32, "big")
    return head + tail


def _erc6492_data(address: str, digest: bytes, signature: bytes) -> str:
    raw = bytes.fromhex(ERC6492_BYTECODE[2:]) + _abi_address_bytes32_bytes(address, digest, signature)
    return "0x" + raw.hex()


def _is_valid_signature_data(digest: bytes, signature: bytes) -> str:
    # selector + bytes32 + offset + bytes. The offset is 64, from the start of the args.
    raw = IS_VALID_SIGNATURE + digest + (64).to_bytes(32, "big") + _pad_bytes(signature)
    return "0x" + raw.hex()
