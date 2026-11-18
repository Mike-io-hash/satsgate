"""I-2. An extra file or a rewritten SHA256SUMS does not match the build output."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


def _load():
    import importlib.util

    path = ROOT / "scripts" / "release" / "verify_dist.py"
    spec = importlib.util.spec_from_file_location("verify_dist", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fill(directory: Path, files: dict[str, bytes]) -> dict[str, str]:
    directory.mkdir(parents=True, exist_ok=True)
    mapping = {}
    lines = []
    for name, payload in files.items():
        (directory / name).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        mapping[name] = digest
        lines.append(f"{digest}  ./{name}")
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return mapping


def test_m7_a_directory_without_sums_fails(tmp_path: Path) -> None:
    verify = _load()
    empty = tmp_path / "empty"
    empty.mkdir()
    try:
        verify.verify_root(empty, None)
    except verify.VerifyError as exc:
        assert "SHA256SUMS" in str(exc)
    else:
        raise AssertionError("missing SHA256SUMS was accepted")


def test_i2_extra_wheel_or_rewritten_sums_fail(tmp_path: Path) -> None:
    verify = _load()
    files = {"pkg-0.1.0-py3-none-any.whl": b"wheel", "pkg-0.1.0.tar.gz": b"sdist"}
    clean = tmp_path / "clean"
    mapping = _fill(clean, files)
    assert verify.verify_directory(clean) == mapping
    dest = tmp_path / "dist"
    verify.copy_listed(clean, dest)
    assert sorted(path.name for path in dest.iterdir()) == sorted(files)

    extra = tmp_path / "extra"
    _fill(extra, files)
    (extra / "other-0.1.0-py3-none-any.whl").write_bytes(b"not-in-the-list")
    try:
        verify.verify_directory(extra)
    except verify.VerifyError as exc:
        assert "extra file" in str(exc)
    else:
        raise AssertionError("extra wheel was accepted")

    rewritten = tmp_path / "rewritten"
    _fill(rewritten, files)
    sums = (rewritten / "SHA256SUMS").read_text(encoding="utf-8").replace(mapping["pkg-0.1.0.tar.gz"], "a" * 64)
    (rewritten / "SHA256SUMS").write_text(sums, encoding="utf-8")
    try:
        verify.verify_directory(rewritten)
    except verify.VerifyError as exc:
        assert "hash mismatch" in str(exc)
    else:
        raise AssertionError("rewritten sums were accepted")

    root = tmp_path / "all"
    _fill(root / "one", files)
    try:
        verify.verify_root(root, {"pkg-0.1.0-py3-none-any.whl": "b" * 64, "pkg-0.1.0.tar.gz": mapping["pkg-0.1.0.tar.gz"]})
    except verify.VerifyError as exc:
        assert "build output" in str(exc)
    else:
        raise AssertionError("a substituted build output was accepted")
    assert verify.verify_root(root, mapping) == [mapping]


def test_i2_dir_expect_json_rejects_rewritten_sums(tmp_path: Path) -> None:
    import json

    verify = _load()
    files = {"pkg-0.1.0-py3-none-any.whl": b"wheel", "pkg-0.1.0.tar.gz": b"sdist"}
    directory = tmp_path / "pkg"
    mapping = _fill(directory, files)
    rewritten = dict(mapping)
    rewritten["pkg-0.1.0.tar.gz"] = "a" * 64
    assert verify.main(["--dir", str(directory), "--expect-json", json.dumps(rewritten)]) == 1
    assert verify.main(["--dir", str(directory), "--expect-json", json.dumps(mapping)]) == 0
