"""Release B docs, versions, and package metadata (T-B.4 and T-B.5)."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_HOUSES = ("bitstamp", "kraken", "chainlink", "coingecko", "d23_median")
_COINBASE_OK = (
    "coinbase cdp",
    "cdp facilitator",
    "smart wallet",
    "coinbase wallet",
    "wallet sdk",
    "replaysafehash",
    "deposit address",
    "coinbasepreference",
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_t_b_4_1_effective_rate_is_not_a_three_minute_rule() -> None:
    text = _text(ROOT / "docs" / "x402-design.md")
    assert "The rate is stale at 3 minutes" not in text
    rates = text.split("## 6. Rates", 1)[1].split("## 7.", 1)[0]
    assert "3,600" in rates
    assert "180" in rates
    lowered = rates.lower()
    for house in (*_HOUSES, "coinbase"):
        assert house not in lowered, house


def test_t_b_4_2_readme_does_not_call_the_quote_a_median() -> None:
    text = _text(ROOT / "README.md")
    assert "the last median" not in text.lower()
    assert "live median" not in text.lower()


def _silence_files() -> list[Path]:
    files = [
        ROOT / "README.md",
        ROOT / "CUSTOMER_QUICKSTART.md",
        ROOT / "BETA.md",
        ROOT / ".env.example",
        ROOT / "docker-compose.yml",
        ROOT / "sdk" / "python" / "README.md",
        ROOT / "proxy" / "README.md",
        ROOT / "mcp" / "README.md",
    ]
    files.append(ROOT / "cli" / "README.md")
    files.extend(path for path in (ROOT / "cli" / "src").rglob("*") if path.is_file() and path.suffix in {".py", ".md", ".js"})
    files.extend(path for path in (ROOT / "cli" / "src" / "satsgate" / "snippets").glob("*") if path.is_file())
    files.extend(path for path in (ROOT / "docs").rglob("*") if path.is_file())
    files.append(ROOT / "CHANGELOG.md")
    files.extend(path for path in (ROOT / "web").rglob("*") if path.is_file() and "node_modules" not in path.parts)
    return files


def _coinbase_allowed(line: str) -> bool:
    """A coinbase line passes only through an allowlisted phrase, and not as a price."""
    import re

    lowered = line.lower()
    if "coinbase" not in lowered:
        return True
    normalized = re.sub(r"[^a-z0-9]+", " ", lowered)
    if re.search(r"\b(?:price|rate)\b", normalized) or any(word in normalized for word in ("quote", "spot")):
        return False
    return any(token in normalized for token in _COINBASE_OK)


def _kraken_is_the_connect_deposit_warning(path: Path, line: str) -> bool:
    if "web/connect" not in path.as_posix():
        return False
    lowered = line.lower()
    return "kraken" in lowered and "deposit address" in lowered


def test_t_d_7_3_price_and_rate_are_whole_words() -> None:
    """`separate` and `pricing` are not the words price and rate. A spot price still fails."""
    assert _coinbase_allowed("Coinbase Smart Wallet stays separate from the account.")
    assert _coinbase_allowed("The Coinbase wallet pricing note is only a label.")
    assert not _coinbase_allowed("Prices use the Coinbase spot price.")


def test_t_b_4_3_public_text_does_not_name_rate_sources() -> None:
    for path in _silence_files():
        for line in _text(path).splitlines():
            lowered = line.lower()
            for house in _HOUSES:
                if house == "kraken" and _kraken_is_the_connect_deposit_warning(path, line):
                    continue
                assert house not in lowered, f"{house} in {path}: {line}"
            assert _coinbase_allowed(line), f"coinbase in {path}: {line}"


def test_t_b_4_4_versions_match() -> None:
    proxy_project = tomllib.loads(_text(ROOT / "proxy" / "pyproject.toml"))
    proxy_init = _text(ROOT / "proxy" / "src" / "satsgate_proxy" / "__init__.py")
    assert proxy_project["project"]["version"] == "0.14.2"
    assert '__version__ = "0.14.2"' in proxy_init

    sdk_project = tomllib.loads(_text(ROOT / "sdk" / "python" / "pyproject.toml"))
    sdk_init = _text(ROOT / "sdk" / "python" / "src" / "satsgate_sdk" / "__init__.py")
    assert sdk_project["project"]["version"] == "0.10.1"
    assert '__version__ = "0.10.1"' in sdk_init

    mcp_project = tomllib.loads(_text(ROOT / "mcp" / "pyproject.toml"))
    mcp_init = _text(ROOT / "mcp" / "src" / "satsgate_mcp" / "__init__.py")
    assert mcp_project["project"]["version"] == "0.13.1"
    assert '__version__ = "0.13.1"' in mcp_init

    assert 'APP_VERSION = "0.20.3"' in _text(ROOT / "app" / "config.py")
    assert '__version__ = "0.15.2"' in _text(ROOT / "gate" / "src" / "satsgate_gate" / "__init__.py")


def test_t_b_4_5_headline_stays_and_readmes_drop_pack_urls() -> None:
    from test_pricing_topup import test_t_5_11_and_12_terms_and_headline

    test_t_5_11_and_12_terms_and_headline()
    for path in (
        ROOT / "sdk" / "python" / "README.md",
        ROOT / "proxy" / "README.md",
        ROOT / "mcp" / "README.md",
    ):
        text = _text(path)
        assert "GET /v1/topup/{plan_id}" not in text, path
    for line in _text(ROOT / "mcp" / "README.md").splitlines():
        lowered = line.lower()
        if "sgr_" in lowered and "balance" in lowered:
            assert "403" not in lowered, line


def test_t_b_5_1_three_packages_pass_twine_check(tmp_path: Path) -> None:
    packages = (ROOT / "sdk" / "python", ROOT / "proxy", ROOT / "mcp")
    built: list[Path] = []
    for package in packages:
        out = tmp_path / package.name
        proc = subprocess.run(
            [sys.executable, "-m", "build", "--outdir", str(out), str(package)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        built.extend(out.glob("*.tar.gz"))
        built.extend(out.glob("*.whl"))
    check = subprocess.run(
        [sys.executable, "-m", "twine", "check", "--strict", *[str(path) for path in built]],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr


# T-B.5.2 (no distribution named satsgate) is replaced by T-C.1.1.
