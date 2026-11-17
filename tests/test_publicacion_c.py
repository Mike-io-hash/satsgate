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
    projects = {path: project for path, project in _projects()}
    assert projects[ROOT / "cli" / "pyproject.toml"]["version"] == "0.1.0"
    assert '__version__ = "0.1.0"' in _text(ROOT / "cli" / "src" / "satsgate" / "__init__.py")
    assert projects[ROOT / "sdk" / "python" / "pyproject.toml"]["version"] == "0.10.0"
    assert '__version__ = "0.10.0"' in _text(ROOT / "sdk" / "python" / "src" / "satsgate_sdk" / "__init__.py")
    assert projects[ROOT / "proxy" / "pyproject.toml"]["version"] == "0.14.1"
    assert '__version__ = "0.14.1"' in _text(ROOT / "proxy" / "src" / "satsgate_proxy" / "__init__.py")
    assert 'APP_VERSION = "0.20.3"' in _text(ROOT / "app" / "config.py")
    assert '__version__ = "0.15.2"' in _text(ROOT / "gate" / "src" / "satsgate_gate" / "__init__.py")
    assert projects[ROOT / "mcp" / "pyproject.toml"]["version"] == "0.13.0"
    assert '__version__ = "0.13.0"' in _text(ROOT / "mcp" / "src" / "satsgate_mcp" / "__init__.py")


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

    assert satsgate.__version__ == "0.1.0"
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
    if installed.returncode != 0:
        pytest.skip("cannot create a venv: " + installed.stderr[-500:])
    module = subprocess.run([str(python), "-m", "satsgate", "--version"], check=False, capture_output=True, text=True)
    command = subprocess.run([str(script), "--version"], check=False, capture_output=True, text=True)
    assert module.returncode == 0, module.stderr
    assert command.returncode == 0, command.stderr
    assert module.stdout == command.stdout
    assert module.stdout.startswith("satsgate 0.1.0\n")
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
