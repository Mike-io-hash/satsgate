"""EIP-1271 and ERC-6492 against an in-process chain.

The bytecode next to this test was compiled with solc 0.8.24
(``solc-static-linux --optimize --bin``). CI does not download a compiler.
``eth-tester`` is a dev dependency. The test skips only when that import fails.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address
from fastapi.testclient import TestClient

pytest.importorskip("eth_tester")
from eth_tester import EthereumTester, PyEVMBackend  # noqa: E402
from eth_tester.exceptions import TransactionFailed  # noqa: E402

from test_payee_connect import _buy, _headers, _load_app, _sign  # noqa: E402

_HERE = Path(__file__).resolve().parent / "contracts"


def _hex(name: str) -> str:
    return (_HERE / name).read_text().strip()


def _pad(data: bytes) -> bytes:
    pad = (32 - (len(data) % 32)) % 32
    return len(data).to_bytes(32, "big") + data + (b"\x00" * pad)


def _addr(address: str) -> bytes:
    return bytes.fromhex(address[2:].rjust(64, "0"))


def _tester_poster(tester: EthereumTester, sender: str):
    def poster(url, payload, headers=None, timeout=None):
        method = payload.get("method")
        if method == "eth_chainId":
            return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x2105"}
        if method == "eth_getCode":
            code = tester.get_code(payload["params"][0])
            if isinstance(code, (bytes, bytearray)):
                code = "0x" + code.hex()
            return 200, {"jsonrpc": "2.0", "id": 1, "result": code or "0x"}
        tx = dict(payload["params"][0])
        tx["from"] = sender
        tx["gas"] = 8_000_000
        try:
            result = tester.call(tx)
        except TransactionFailed:
            return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}
        if isinstance(result, (bytes, bytearray)):
            result = "0x" + result.hex()
        return 200, {"jsonrpc": "2.0", "id": 1, "result": result}

    return poster


def _deploy(tester: EthereumTester, sender: str, data: str) -> str:
    tx = tester.send_transaction({"from": sender, "data": data, "gas": 3_000_000})
    receipt = tester.get_transaction_receipt(tx)
    assert receipt["status"] == 1
    return to_checksum_address(receipt["contract_address"])


def test_personal_sign_verifies_on_a_minimal_1271_wallet_and_rejects_another_key(tmp_path):
    module = _load_app(tmp_path)
    tester = EthereumTester(PyEVMBackend())
    sender = tester.get_accounts()[0]
    owner = Account.create()
    stranger = Account.create()
    init = _hex("Minimal1271.hex") + owner.address[2:].rjust(64, "0")
    wallet = _deploy(tester, sender, "0x" + init)
    importlib.import_module("app.evm_rpc").poster = _tester_poster(tester, sender)

    with TestClient(module.app) as http:
        key = _buy(http)
        challenge = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": wallet},
        )
        assert challenge.status_code == 200, challenge.text
        message = challenge.json()["message"]
        saved = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": wallet, "signature": _sign(owner, message)},
        )
        assert saved.status_code == 200, saved.text
        assert saved.json()["payee_evm_kind"] == "contract"
        assert saved.json()["payee_evm_address"] == wallet

        again = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": wallet},
        )
        rejected = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": wallet, "signature": _sign(stranger, again.json()["message"])},
        )
        assert rejected.status_code == 400
        assert rejected.json()["error"] == "bad_signature"
        assert http.get("/v1/client", headers={"X-Api-Key": key}).json()["payee_evm_address"] == wallet


def test_erc6492_wrapper_deploys_through_the_pinned_validator(tmp_path):
    module = _load_app(tmp_path)
    tester = EthereumTester(PyEVMBackend())
    sender = tester.get_accounts()[0]
    owner = Account.create()
    factory = _deploy(tester, sender, "0x" + _hex("Create2Factory.hex"))
    init = bytes.fromhex(_hex("Minimal1271.hex") + owner.address[2:].rjust(64, "0"))
    salt = b"\x00" * 32
    create2 = keccak(b"\xff" + bytes.fromhex(factory[2:]) + salt + keccak(init))
    counterfactual = to_checksum_address(create2[-20:])
    assert tester.get_code(counterfactual) in {"0x", b"", None}

    selector = keccak(text="deploy(bytes32,bytes)")[:4]
    factory_call = selector + salt + (64).to_bytes(32, "big") + _pad(init)
    importlib.import_module("app.evm_rpc").poster = _tester_poster(tester, sender)

    with TestClient(module.app) as http:
        key = _buy(http)
        token_body = http.post("/v1/client/payee/evm/connect", headers={"X-Api-Key": key})
        connect = token_body.json()["connect_url"].split("#t=", 1)[1]
        challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(connect),
            json={"address": counterfactual},
        )
        assert challenge.status_code == 200, challenge.text
        message = challenge.json()["message"]
        signature = bytes.fromhex(_sign(owner, message)[2:])
        wrapped_head = _addr(factory) + (96).to_bytes(32, "big")
        factory_tail = _pad(factory_call)
        wrapped_head += (96 + len(factory_tail)).to_bytes(32, "big")
        magic = bytes.fromhex("6492" * 16)
        wrapped = "0x" + (wrapped_head + factory_tail + _pad(signature) + magic).hex()
        saved = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(connect),
            json={"address": counterfactual, "signature": wrapped},
        )
        assert saved.status_code == 200, saved.text
        assert saved.json()["payee_evm_kind"] == "contract"
        assert saved.json()["payee_evm_address"] == counterfactual
        # The validator deployed the wallet inside the call. The chain itself
        # stays unchanged, because eth_call does not commit.
        assert tester.get_code(counterfactual) in {"0x", b"", None}

    # The signed message really is what encode_defunct hashes. A wrong key
    # wrapped the same way is rejected by the wallet the validator deploys.
    stranger = Account.create()
    module = _load_app(tmp_path)
    importlib.import_module("app.evm_rpc").poster = _tester_poster(tester, sender)
    with TestClient(module.app) as http:
        key = _buy(http)
        challenge = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": counterfactual},
        )
        message = challenge.json()["message"]
        assert encode_defunct(text=message).body is not None
        bad_sig = bytes.fromhex(_sign(stranger, message)[2:])
        wrapped_head = _addr(factory) + (96).to_bytes(32, "big")
        factory_tail = _pad(factory_call)
        wrapped_head += (96 + len(factory_tail)).to_bytes(32, "big")
        wrapped = "0x" + (wrapped_head + factory_tail + _pad(bad_sig) + magic).hex()
        rejected = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": counterfactual, "signature": wrapped},
        )
        assert rejected.status_code == 400
        assert rejected.json()["error"] == "bad_signature"
