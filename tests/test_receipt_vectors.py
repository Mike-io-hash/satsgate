"""Shared receipt vectors. Express runs the same file with Node crypto."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from satsgate_sdk.receipts import ReceiptError, verify_receipt

_VECTORS = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "receipt_vectors.json"


def _load() -> dict:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _load()["cases"], ids=lambda case: case["name"])
def test_sdk_matches_the_shared_vectors(case):
    data = _load()
    secret = case.get("verify_secret") or data["secret"]
    previous = (data["previous_secret"],) if case.get("previous") else ()
    try:
        receipt = verify_receipt(
            case["token"],
            secret=secret,
            site=case["site"],
            path=case["path"],
            previous_secrets=previous,
            now=data["now"],
            leeway=data["leeway"],
        )
    except ReceiptError as exc:
        assert exc.code == case["expect"]
        return
    assert case["expect"] == "ok"
    assert receipt.site == case["site"]


def test_cross_site_receipts_are_wrong_site_and_a_bad_signature_stays_invalid():
    data = _load()
    by_name = {case["name"]: case for case in data["cases"]}
    left = verify_receipt(
        by_name["wrong_site_reverse"]["token"],
        secret=data["secret"],
        site="my-shop",
        path="/report",
        now=data["now"],
        leeway=data["leeway"],
    )
    assert left.site == "my-shop"
    with pytest.raises(ReceiptError) as other_on_mine:
        verify_receipt(
            by_name["wrong_site"]["token"],
            secret=data["secret"],
            site="my-shop",
            path="/report",
            now=data["now"],
            leeway=data["leeway"],
        )
    assert other_on_mine.value.code == "receipt_wrong_site"
    with pytest.raises(ReceiptError) as mine_on_other:
        verify_receipt(
            by_name["wrong_site_reverse"]["token"],
            secret=data["other_secret"],
            site="other-shop",
            path="/report",
            now=data["now"],
            leeway=data["leeway"],
        )
    assert mine_on_other.value.code == "receipt_wrong_site"
    with pytest.raises(ReceiptError) as bad:
        verify_receipt(
            by_name["bad_signature"]["token"],
            secret=data["secret"],
            site="my-shop",
            path="/report",
            now=data["now"],
            leeway=data["leeway"],
        )
    assert bad.value.code == "receipt_invalid"
