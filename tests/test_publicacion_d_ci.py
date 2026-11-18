"""T-D.3.2, T-D.4.2 and T-D.5.1. The workflow files are the protection."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# Files the root-context Dockerfiles COPY. gate/ is its own context.
_KEEP = (
    "requirements.txt",
    "app/__init__.py",
    "app/main.py",
    "proxy/src/satsgate_proxy/__init__.py",
    "proxy/pyproject.toml",
    "proxy/README.md",
    "proxy/LICENSE",
    "proxy/snippets/fastapi_verify.py",
    "proxy/satsgate-proxy.example.yaml",
)
_DROP = (
    ".env",
    "proxy/.env",
    "proxy/src/.env",
    "app/.env",
    ".env.local",
    "foo.sqlite3",
    "app/db.sqlite3",
    "data/geoip/x.mmdb",
    ".git/config",
    "backups/db.sqlite3",
    "node_modules/leftpad/index.js",
    "cli/.satsgate/account.env",
    "web/connect/dist/index.html",
)
_KEEP_EXTRA = (".env.example", "proxy/.env.example")


def _load_workflow(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'(?m)^on:', '"on":', text, count=1)
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def _pattern_body(pattern: str) -> str:
    pieces: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            pieces.append("(?:.*/)?")
            index += 3
            continue
        if pattern.startswith("**", index):
            pieces.append(".*")
            index += 2
            continue
        char = pattern[index]
        if char == "*":
            pieces.append("[^/]*")
        elif char == "?":
            pieces.append("[^/]")
        else:
            pieces.append(re.escape(char))
        index += 1
    return "".join(pieces)


def _matches(pattern: str, path: str) -> bool:
    """Docker context match. A pattern without a slash or ``**`` matches only at the root."""
    directory = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    body = _pattern_body(pattern)
    if "**" not in pattern and "/" not in pattern:
        if "/" in path:
            return False
        return re.fullmatch(body, path) is not None
    if directory:
        return re.fullmatch(body, path) is not None or re.fullmatch(body + "/.+", path) is not None
    return re.fullmatch(body, path) is not None


def _ignored(path: str, lines: list[str]) -> bool:
    ignored = False
    prefixes = ["/".join(path.split("/")[: end]) for end in range(1, path.count("/") + 2)]
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        pattern = line[1:] if negate else line
        if any(_matches(pattern, prefix) for prefix in prefixes):
            ignored = not negate
    return ignored


def _ignore_lines() -> list[str]:
    return (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()


def test_t_d_3_2_workflow_lint_is_hash_pinned() -> None:
    """Deleting the actionlint/zizmor step, or the hash pin, fails this test."""
    requirements = (ROOT / "scripts" / "release" / "requirements-lint.txt").read_text(encoding="utf-8")
    assert "zizmor==1.32.0" in requirements
    assert "actionlint-py==1.7.12.25" in requirements
    assert requirements.count("--hash=sha256:") >= 2
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--require-hashes" in workflow
    assert "scripts/release/requirements-lint.txt" in workflow
    assert re.search(r"(?m)^\s+actionlint\s*$", workflow)
    assert re.search(r"(?m)^\s+zizmor --offline --min-severity medium \.github/workflows\s*$", workflow)


def test_t_d_4_2_dockerignore_keeps_image_inputs() -> None:
    """Dropping .env or *.sqlite3, or ignoring a COPYed path, fails this test."""
    lines = _ignore_lines()
    active = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    assert "**/.env" in active
    assert "**/*.sqlite3" in active
    for path in _KEEP:
        assert not _ignored(path, lines), path
    for path in (*_DROP,):
        assert _ignored(path, lines), path
    for path in _KEEP_EXTRA:
        assert not _ignored(path, lines), path
    gate_ignore = ROOT / "gate" / ".dockerignore"
    if gate_ignore.is_file():
        gate_lines = gate_ignore.read_text(encoding="utf-8").splitlines()
        assert not _ignored("requirements.txt", gate_lines)
        assert not _ignored("src/satsgate_gate/__init__.py", gate_lines)


def test_t_d_5_1_ci_permissions_and_pins() -> None:
    """@v4 on a step, or permissions: write-all, fails this test."""
    path = ROOT / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    workflow = _load_workflow(path)
    assert workflow["permissions"] == {"contents": "read"}
    web = workflow["jobs"]["web"]
    assert web.get("permissions", workflow["permissions"]).get("actions") != "write"
    assert "actions: write" not in path.read_text(encoding="utf-8").split("web:", 1)[1]
    assert "pull_request_target" not in text
    checkouts = 0
    uses = 0
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            raw = step.get("uses")
            if not raw:
                continue
            uses += 1
            ref = raw.split("@", 1)[1]
            assert re.fullmatch(r"[0-9a-f]{40}", ref), raw
            if raw.startswith("actions/checkout@"):
                checkouts += 1
                assert step["with"]["persist-credentials"] is False
    assert checkouts >= 1
    assert uses >= 1
    assert "scripts/release/requirements-lint.txt" in text
    assert "actionlint" in text
    assert "zizmor" in text
