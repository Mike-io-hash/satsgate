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


def test_t_d_11_1_current_component_versions() -> None:
    gate = (ROOT / "gate" / "README.md").read_text(encoding="utf-8")
    assert "Version **0.15.2**" in gate
    assert "Version **0.15.0**" not in gate
    assert "Core is **0.18.0**" not in gate
    assert "0.20.3 or later" in gate
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    current = readme.split("### x402 on Base Sepolia", 1)[0]
    assert '"version": "0.20.3"' in current
    assert "version 0.11.0" not in current
    assert "Core is 0.20.2" not in current


def test_t_d_11_4_new_public_text_stays_plain() -> None:
    parts = [
        (ROOT / "docs" / "publishing.md").read_text(encoding="utf-8"),
        (ROOT / "proxy" / "Dockerfile").read_text(encoding="utf-8"),
        (ROOT / ".github" / "workflows" / "ghcr.yml").read_text(encoding="utf-8"),
    ]
    for rel in ("sdk/python/pyproject.toml", "proxy/pyproject.toml", "mcp/pyproject.toml", "cli/pyproject.toml"):
        parts.append((ROOT / rel).read_text(encoding="utf-8"))
    blob = "\n".join(parts).lower()
    for banned in ("anonymous", "wavelength", "battle-tested", "battle tested"):
        assert banned not in blob


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
