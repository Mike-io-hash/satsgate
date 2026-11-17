"""Publicación C package metadata and the SDK connect link (T-C.1, T-C.4.0)."""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from satsgate_sdk import SatsgateClient, create_account
from test_sdk_accounts import _CoreTransport, _bind
from test_x402 import _load_app

ROOT = Path(__file__).resolve().parents[1]
HEADLINE = (
    "Charge AI agents in Lightning and USDC on the same 402. "
    "500 free unlocks per UTC month. "
    "Cobrale a agentes de IA en Lightning y USDC, en el mismo 402."
)
_BASE = "http://testserver"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _projects() -> list[tuple[Path, dict]]:
    found: list[tuple[Path, dict]] = []
    for path in ROOT.rglob("pyproject.toml"):
        if "node_modules" in path.parts or ".venv" in path.parts:
            continue
        found.append((path, tomllib.loads(path.read_text(encoding="utf-8"))["project"]))
    return found


def test_t_c_1_1_exactly_one_umbrella_package() -> None:
    """T-B.5.2's replacement: the only distribution named satsgate is cli/."""
    named = [path for path, project in _projects() if project["name"] == "satsgate"]
    assert named == [ROOT / "cli" / "pyproject.toml"]


def _build(package: Path, out: Path) -> list[Path]:
    proc = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(out), str(package)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    built = list(out.glob("*.tar.gz")) + list(out.glob("*.whl"))
    assert built, package
    return built


def test_t_c_1_2_four_packages_pass_twine_check(tmp_path: Path) -> None:
    packages = (ROOT / "sdk" / "python", ROOT / "proxy", ROOT / "mcp", ROOT / "cli")
    built: list[Path] = []
    for package in packages:
        built.extend(_build(package, tmp_path / package.name))
    check = subprocess.run(
        [sys.executable, "-m", "twine", "check", "--strict", *[str(path) for path in built]],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr


def _metadata(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        name = next(item for item in archive.namelist() if item.endswith(".dist-info/METADATA"))
        return archive.read(name).decode("utf-8")


def test_t_c_1_3_wheels_declare_apache_and_cli_license_matches(tmp_path: Path) -> None:
    """Removing the license from a pyproject makes that wheel's METADATA fail this test."""
    assert (ROOT / "cli" / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    packages = (ROOT / "sdk" / "python", ROOT / "proxy", ROOT / "mcp", ROOT / "cli")
    for package in packages:
        wheels = [path for path in _build(package, tmp_path / package.name) if path.suffix == ".whl"]
        assert wheels
        metadata = _metadata(wheels[0])
        assert "License-Expression: Apache-2.0" in metadata or "License: Apache-2.0" in metadata, package


def test_t_c_1_4_versions_match() -> None:
    """Pinned versions. T-D.1.3 below reuses this instead of copying it."""
    projects = {path: project for path, project in _projects()}
    assert projects[ROOT / "cli" / "pyproject.toml"]["version"] == "0.1.1"
    assert '__version__ = "0.1.1"' in _text(ROOT / "cli" / "src" / "satsgate" / "__init__.py")
    assert projects[ROOT / "sdk" / "python" / "pyproject.toml"]["version"] == "0.10.0"
    assert '__version__ = "0.10.0"' in _text(ROOT / "sdk" / "python" / "src" / "satsgate_sdk" / "__init__.py")
    assert projects[ROOT / "proxy" / "pyproject.toml"]["version"] == "0.14.1"
    assert '__version__ = "0.14.1"' in _text(ROOT / "proxy" / "src" / "satsgate_proxy" / "__init__.py")
    assert 'APP_VERSION = "0.20.3"' in _text(ROOT / "app" / "config.py")
    assert '__version__ = "0.15.2"' in _text(ROOT / "gate" / "src" / "satsgate_gate" / "__init__.py")
    assert projects[ROOT / "mcp" / "pyproject.toml"]["version"] == "0.13.0"
    assert '__version__ = "0.13.0"' in _text(ROOT / "mcp" / "src" / "satsgate_mcp" / "__init__.py")


def test_t_d_1_3_pyproject_version_equals_dunder_version() -> None:
    """T-D.1.3: pyproject version == __version__ for all four packages.

    Extends T-C.1.4. The assertions stay there so the two tests cannot drift.
    """
    test_t_c_1_4_versions_match()


def test_t_c_1_5_proxy_is_a_hard_dependency_and_mcp_is_an_extra() -> None:
    """Moving satsgate-proxy into an extra fails the hard-dependency assertion."""
    project = tomllib.loads(_text(ROOT / "cli" / "pyproject.toml"))["project"]
    deps = project["dependencies"]
    assert any(item.startswith("satsgate-sdk>") or item.startswith("satsgate-sdk=") for item in deps)
    assert any(item.startswith("satsgate-proxy>") or item.startswith("satsgate-proxy=") for item in deps)
    joined = "\n".join(deps)
    assert "satsgate-mcp" not in joined
    assert "nostr-sdk" not in joined
    assert "satsgate-gate" not in joined
    extra = project["optional-dependencies"]["mcp"]
    assert any(item.startswith("satsgate-mcp>") or item.startswith("satsgate-mcp=") for item in extra)
    extras = "\n".join(item for values in project["optional-dependencies"].values() for item in values)
    assert "satsgate-proxy" not in extras
    assert "nostr-sdk" not in extras


def test_t_c_1_6_installed_script_and_module_print_the_version(tmp_path: Path) -> None:
    import satsgate
    from satsgate_proxy import __version__ as proxy_version
    from satsgate_sdk import __version__ as sdk_version

    assert satsgate.__version__ == "0.1.1"
    assert sdk_version == "0.10.0"
    assert proxy_version == "0.14.1"
    if shutil.which("python3") is None:
        pytest.skip("cannot create a venv: python3 is not on PATH")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    for package in (ROOT / "sdk" / "python", ROOT / "proxy", ROOT / "cli"):
        _build(package, wheels)
    venv = tmp_path / "venv"
    created = subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], check=False)
    if created.returncode != 0:
        pytest.skip(f"cannot create a venv: exit {created.returncode}")
    pip = venv / "bin" / "pip"
    python = venv / "bin" / "python"
    script = venv / "bin" / "satsgate"
    installed = subprocess.run(
        [str(pip), "install", "--no-index", "--find-links", str(wheels), "satsgate"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr[-500:]
    module = subprocess.run([str(python), "-m", "satsgate", "--version"], check=False, capture_output=True, text=True)
    command = subprocess.run([str(script), "--version"], check=False, capture_output=True, text=True)
    assert module.returncode == 0, module.stderr
    assert command.returncode == 0, command.stderr
    assert module.stdout == command.stdout
    assert module.stdout.startswith("satsgate 0.1.1\n")
    assert "satsgate-sdk 0.10.0\n" in module.stdout
    assert "satsgate-proxy 0.14.1\n" in module.stdout


def test_t_c_1_7_headline_is_in_the_package_and_the_readme() -> None:
    project = tomllib.loads(_text(ROOT / "cli" / "pyproject.toml"))["project"]
    assert project["description"] == HEADLINE
    assert HEADLINE in _text(ROOT / "cli" / "README.md")
    sdk = tomllib.loads(_text(ROOT / "sdk" / "python" / "pyproject.toml"))["project"]
    assert sdk["description"] == HEADLINE


def test_t_c_4_0_create_connect_link_against_the_core(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    module = _load_app(tmp_path)
    caplog.set_level(logging.DEBUG)
    with TestClient(module.app) as http:
        transport = _CoreTransport(http)
        _bind(monkeypatch, transport)
        opened = create_account(base_url=_BASE)
        client = SatsgateClient(base_url=_BASE, api_key=opened["api_key"])
        try:
            link = client.create_connect_link()
        finally:
            client.close()
    assert link["connect_url"].startswith("https://")
    assert "#t=" in link["connect_url"]
    assert isinstance(link["expires_at"], int)
    assert link["connect_url"] not in caplog.text
    sent = transport.requests[-1]
    assert sent.method == "POST"
    assert sent.url.path == "/v1/client/payee/evm/connect"


def test_t_c_8_1_coinbase_price_sentence_is_rejected() -> None:
    """Adding a spot-price sentence to a public README fails the silence check."""
    from test_publicacion_b import _coinbase_allowed

    bad = "Prices use the Coinbase spot price for your wallet."
    assert _coinbase_allowed(bad) is False
    assert _coinbase_allowed("Live mode uses the Coinbase CDP facilitator.") is True


def test_t_c_8_2_silence_list_includes_the_umbrella() -> None:
    from test_publicacion_b import _silence_files

    files = _silence_files()
    assert ROOT / "cli" / "README.md" in files
    assert any(path.suffix == ".py" and "cli" in path.parts for path in files)
    assert any(path.parent.name == "snippets" for path in files)


def test_t_c_8_3_pack_wording_is_gone_from_the_listed_docs() -> None:
    banned = ("5 sats per credit", "trial plan", "credit pack", "get /v1/topup/{plan_id}", "median")
    paths = (
        ROOT / "proxy" / "README.md",
        ROOT / ".env.example",
        ROOT / "CUSTOMER_QUICKSTART.md",
        ROOT / "docs" / "x402-design.md",
        ROOT / "cli" / "README.md",
    )
    for path in paths:
        lowered = path.read_text(encoding="utf-8").lower()
        for phrase in banned:
            assert phrase not in lowered, f"{phrase} in {path}"


def test_t_c_8_4_init_output_does_not_name_custody_or_a_rate_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from init_harness import RecordingSync, Scripted, invoke

    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500")
    http = TestClient(module.app)
    http.__enter__()
    transport = RecordingSync(http)
    work = tmp_path / "human"
    work.mkdir()
    stdin = Scripted(["merchant@pay.example\n", "n\n", "none\n"], tty=True)
    try:
        code, _body, out, err = invoke(
            work,
            transport,
            stdin=stdin,
            json_mode=False,
            lightning_address=None,
            want_usdc=None,
            framework=None,
            stdout_tty=True,
        )
    finally:
        http.__exit__(None, None, None)
    assert code == 0, out
    text = (out + err).lower()
    for house in ("bitstamp", "kraken", "chainlink", "coingecko", "coinbase"):
        assert house not in text
    custod = text.replace("non-custodial", "")
    assert "custod" not in custod
