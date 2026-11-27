"""T-RL: the package release train for the proxy, the buyer MCP, and satsgate."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_CURRENT_DOCS = (
    "README.md",
    "CUSTOMER_QUICKSTART.md",
    "docs/api.md",
    "proxy/README.md",
    "mcp/README.md",
    "cli/README.md",
    "gate/README.md",
    "sdk/python/README.md",
)


def _check_tag():
    path = ROOT / "scripts" / "release" / "check_tag.py"
    spec = importlib.util.spec_from_file_location("check_tag_rl", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_tag_rl"] = module
    spec.loader.exec_module(module)
    return module


def test_rl_1_1_release_tags_match_the_tree() -> None:
    check_tag = _check_tag()
    expected = {
        "proxy-v0.15.1": ("satsgate-proxy", "0.15.1"),
        "mcp-v0.14.1": ("satsgate-mcp", "0.14.1"),
        "satsgate-v0.1.4": ("satsgate", "0.1.4"),
        "sdk-v0.10.1": ("satsgate-sdk", "0.10.1"),
    }
    for tag, (dist, version) in expected.items():
        fields = check_tag.evaluate(tag, ROOT)
        assert fields["dist_name"] == dist
        assert fields["version"] == version


def test_rl_1_2_satsgate_pins_the_new_minors() -> None:
    import tomllib

    project = tomllib.loads((ROOT / "cli" / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == ["satsgate-sdk>=0.10.1,<0.11", "satsgate-proxy>=0.15.1,<0.16"]
    assert project["optional-dependencies"]["mcp"] == ["satsgate-mcp>=0.14.1,<0.15"]


def test_rl_1_3_current_docs_do_not_call_released_features_unreleased() -> None:
    for rel in _CURRENT_DOCS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "not in a published release" not in text, rel
        assert "describes the code on the main branch" not in text, rel


def test_rl_1_4_changelog_promotes_the_unreleased_entry() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    unreleased = text.split("## [Unreleased]\n", 1)[1]
    rest = unreleased.lstrip("\n")
    assert rest.startswith("## [Terms] - 2026-11-27\n")
    after_terms = rest.split("## [Terms] - 2026-11-27\n", 1)[1]
    package_at = after_terms.find("## [Package patch releases] - ")
    assert package_at != -1
    assert "## [" not in after_terms[:package_at]
    entry = unreleased.split("## [0.20.4]", 1)[0]
    assert "not in a published release" not in entry
    assert "`satsgate-proxy` 0.15.1" in entry
    assert "`satsgate-mcp` 0.14.1" in entry
    assert "`satsgate` 0.1.4" in entry
