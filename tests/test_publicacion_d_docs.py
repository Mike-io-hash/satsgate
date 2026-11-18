"""T-D.9.1, T-D.10.1, and the published-text checks that this pull request can lock."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> dict:
    text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    text = re.sub(r'(?m)^on:', '"on":', text, count=1)
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def _environments(workflow: dict) -> set[str]:
    found: set[str] = set()
    for job in workflow["jobs"].values():
        env = job.get("environment")
        if isinstance(env, str):
            found.add(env)
    return found


def test_t_d_9_1_guide_names_the_workflow_and_the_environments() -> None:
    guide = (ROOT / "docs" / "publishing.md").read_text(encoding="utf-8")
    names = _environments(_workflow("publish.yml")) | _environments(_workflow("ghcr.yml"))
    assert names == {"testpypi", "pypi", "ghcr"}
    for name in names:
        assert name in guide
    assert "publish.yml" in guide
    assert "ghcr.yml" in guide


def test_t_d_10_1_caddy_recreate_is_forced() -> None:
    for path in (ROOT / "docs").rglob("*.md"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "superseded" in line.lower():
                continue
            lowered = line.lower()
            assert "caddy reload" not in lowered, f"{path}: {line}"
            if "caddy" in lowered and "up -d" in lowered:
                assert "--force-recreate" in lowered, f"{path}: {line}"


def test_t_d_11_2_published_install_text_replaced_the_forthcoming_lines() -> None:
    banned = ("not on PyPI yet", "until Publicación D", "PyPI publication is forthcoming")
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".md", ".yml", ".yaml"}:
            continue
        if "node_modules" in path.parts or path.name == "CHANGELOG.md":
            continue
        text = path.read_text(encoding="utf-8")
        for phrase in banned:
            assert phrase not in text, f"{phrase} in {path}"


_CURRENT = {"0.20.3", "0.15.2", "0.14.1", "0.13.0", "0.10.0", "0.1.1"}
_VERSION_FILES = (
    "README.md",
    "CUSTOMER_QUICKSTART.md",
    "gate/README.md",
    "proxy/README.md",
    "mcp/README.md",
    "sdk/python/README.md",
    "cli/README.md",
)
_VERSION_PATTERNS = (
    re.compile(r"[Vv]ersion \*\*(\d+\.\d+\.\d+)\*\*"),
    re.compile(r"\bis \*\*(\d+\.\d+\.\d+)\*\*"),
    re.compile(r'"version": "(\d+\.\d+\.\d+)"'),
    re.compile(r"Core is \**(\d+\.\d+\.\d+)\**"),
)


def _outside_history(text: str) -> str:
    kept: list[str] = []
    skipping = False
    for line in text.splitlines():
        if line.startswith("#"):
            title = line.lstrip("#").strip().lower()
            skipping = "history" in title or "changelog" in title
        if not skipping:
            kept.append(line)
    return "\n".join(kept)


def test_t_d_11_1_current_component_versions() -> None:
    for rel in _VERSION_FILES:
        text = _outside_history((ROOT / rel).read_text(encoding="utf-8"))
        for pattern in _VERSION_PATTERNS:
            for found in pattern.findall(text):
                assert found in _CURRENT, f"{found} in {rel}"
    gate = (ROOT / "gate" / "README.md").read_text(encoding="utf-8")
    assert '"version": "0.15.2"' in gate
    assert "0.15.0" not in gate


def test_t_d_11_4_new_public_text_stays_plain() -> None:
    parts = [
        (ROOT / "docs" / "publishing.md").read_text(encoding="utf-8"),
        (ROOT / "proxy" / "Dockerfile").read_text(encoding="utf-8"),
        (ROOT / ".github" / "workflows" / "ghcr.yml").read_text(encoding="utf-8"),
        (ROOT / "sdk" / "python" / "README.md").read_text(encoding="utf-8"),
        (ROOT / "proxy" / "README.md").read_text(encoding="utf-8"),
        (ROOT / "mcp" / "README.md").read_text(encoding="utf-8"),
        (ROOT / "cli" / "README.md").read_text(encoding="utf-8"),
    ]
    for rel in ("sdk/python/pyproject.toml", "proxy/pyproject.toml", "mcp/pyproject.toml", "cli/pyproject.toml"):
        parts.append((ROOT / rel).read_text(encoding="utf-8"))
    blob = "\n".join(parts).lower()
    for banned in ("anonymous", "wavelength", "battle-tested", "battle tested"):
        assert banned not in blob


def test_m8_proxy_tag_waits_to_approve_the_image() -> None:
    guide = (ROOT / "docs" / "publishing.md").read_text(encoding="utf-8")
    assert "Approve the `ghcr` environment only after `verify-pypi` is green." in guide
    workflow = _workflow("ghcr.yml")
    assert workflow["concurrency"]["group"] == "ghcr-${{ github.ref }}"
    assert workflow["concurrency"]["cancel-in-progress"] is False


def test_m9_setup_node_is_the_current_release() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1" in text
    assert "49933ea5288caeca8642d1e84afbd3f7d6820020" not in text


def test_m11_changelog_names_the_terms_and_the_ledger_check() -> None:
    entry = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split("## [0.20.3]", 1)[0]
    assert "docs/terms/2026-11-13.md" in entry
    assert "paywall_verify" in entry


def test_i5_proxy_and_mcp_publish_an_install_section() -> None:
    proxy = (ROOT / "proxy" / "README.md").read_text(encoding="utf-8")
    mcp = (ROOT / "mcp" / "README.md").read_text(encoding="utf-8")
    assert "## Install" in proxy
    assert "pip install satsgate-proxy" in proxy
    assert "uvx --env-file .env satsgate-proxy --config" in proxy
    assert "docker pull ghcr.io/mike-io-hash/satsgate-proxy:0.14.1" in proxy
    assert "## Install" in mcp
    assert "pip install satsgate-mcp" in mcp
    assert "satsgate-mcp" in mcp


def test_t_d_11_3_usdc_readmes_name_base_only() -> None:
    for rel in (
        "README.md",
        "proxy/README.md",
        "mcp/README.md",
        "gate/README.md",
        "sdk/python/README.md",
        "cli/README.md",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        if "USDC" in text:
            assert "USDC payments: Base network only" in text, rel
