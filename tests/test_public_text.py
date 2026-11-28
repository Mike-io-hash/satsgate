"""Public text guard: style, placeholders, internal names.

T-DM.1 through T-DM.9. ``tests/fixtures/openapi-0.20.3.json`` is the historical
production snapshot of core 0.20.3. The OpenAPI test pins the exact 0.20.5
delta against that snapshot: ``info.version`` and the two route descriptions.
An unknown core version fails instead of skipping.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tokenize
import tomllib
import warnings
import zipfile
from pathlib import Path

import pytest

from release_build import PACKAGES, build_package

ROOT = Path(__file__).resolve().parents[1]
BASE = "c66646745328eb4c6a1bd33c6668a4b549298af3"
RULES_PATH = ROOT / "tests" / "data" / "public_text_rules.json"
GOLDEN = ROOT / "tests" / "fixtures" / "openapi-0.20.3.json"
README_TOKENS = ROOT / "tests" / "fixtures" / "readme-base-tokens.json"
HEADLINE = (
    "Charge AI agents in Lightning and USDC on the same 402. "
    "Payments go straight to your wallet. 500 free unlocks a month."
)
UNION = (
    "README.md",
    "docs/api.md",
    "docs/self-hosting.md",
    "CHANGELOG.md",
    "CUSTOMER_QUICKSTART.md",
)
# Heading text from the base README that this patch no longer repeats.
DROPPED = {
    "Prepaid balance (milisatoshis)": "Spelling corrected to millisatoshis.",
    "x402 on Base Sepolia (0.12.0)": "Recorded in the 0.12.0 changelog entry.",
    "Hosted gate x402 (gate 0.12.0)": "Recorded in the 0.12.0 changelog entry.",
    "Hosted sites (closed beta)": "The hosted gate is open; the heading is now Hosted sites.",
}
README_HEADINGS = (
    "Who it is for",
    "Why Satsgate",
    "Quickstart",
    "How it works",
    "Hosted gate (x402)",
    "Pricing",
    "USDC payments: Base network only",
    "Buyer side: `satsgate-mcp`",
    "Packages",
    "Status",
    "Security and trust",
    "Documentation",
    "Contributing and support",
    "License",
)
INSTALL_BANS = (
    "pip install -e",
    "PYTHONPATH=",
    "pip install -r mcp/requirements.txt",
    "docker compose -f proxy/docker-compose.yml up --build",
)
MISALIGN = (
    "milisat",
    "merchant's own node",
    "There is no sats-to-USD conversion",
    "loses one credit",
    "takes one credit",
    "Satsgate credits",
    "when the operator sets",
)
WORDING_FILES = {
    "README.md",
    "CUSTOMER_QUICKSTART.md",
    "gate/README.md",
    "proxy/README.md",
    "mcp/README.md",
    "sdk/python/README.md",
    "cli/README.md",
    "docs/api.md",
    "docs/self-hosting.md",
}
WORDING_PATTERNS = (
    r"empty credit balance",
    r"the credit and the use",
    r"\ba credit is taken\b",
    r"credits are never refunded",
    r"no merchant credit",
    r"credits are not spent",
    r"spends the credit",
    r"client's credits",
    r"credits were already charged",
    r"one merchant credit",
    r"\ba satsgate credit\b",
    r"lightning credit",
    r"the credit is taken",
    r"operator cdp",
    r"operator switch",
    r"operator has enabled",
    r"when the operator sets",
    r"after the operator has",
)
FROZEN_PARTS = ("docs/terms/2026-11-13.md", "tests/fixtures/terms-")
COMMENT_ROOTS = ("app", "cli", "sdk", "proxy", "mcp", "gate", "scripts", "web/connect/src")
ACCENTS = set("áéíóúÁÉÍÓÚñÑ¿¡")
OPENAPI_ENV = {
    "SATSGATE_ENV": "production",
    "SATSGATE_DEV_MODE": "0",
    "SATSGATE_WALLET_MODE": "lnaddr",
    "SATSGATE_LIGHTNING_ADDRESS": "merchant@pay.example",
    "SATSGATE_MACAROON_SECRET": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "SATSGATE_ADMIN_TOKEN": "0123456789abcdef0123456789abcdef",
    "SATSGATE_GATE_TOKEN": "",
    "SATSGATE_GATE_PEERS": "",
    "SATSGATE_TRUSTED_PROXIES": "",
}


def _rules() -> dict:
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))


def _tracked(root: Path = ROOT) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [item.decode() for item in proc.stdout.split(b"\0") if item]


def _frozen(rel: str) -> bool:
    return any(rel == part or rel.startswith(part) for part in FROZEN_PARTS)


def _allow(rules: dict, rel: str, line: int) -> bool:
    for item in rules["allowlist"]:
        if item["file"] == rel and int(item["line"]) == line:
            return True
    return False


def _docstring_lines(text: str) -> set[int]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    found: set[int] = set()

    def take(node: ast.AST) -> None:
        body = getattr(node, "body", None)
        if not body:
            return
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant):
            if isinstance(first.value.value, str):
                found.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))

    take(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            take(node)
    return found


def _py_units(text: str, *, strings: bool, names: bool) -> list[tuple[int, str]]:
    docs = _docstring_lines(text)
    units: list[tuple[int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    except tokenize.TokenError:
        return [(1, text)]
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            units.append((tok.start[0], tok.string))
        elif tok.type == tokenize.STRING and (strings or tok.start[0] in docs):
            units.append((tok.start[0], tok.string))
        elif names and tok.type == tokenize.NAME and tok.string in {"def"}:
            continue
    if names:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    units.append((node.lineno, node.name))
    return units


def _js_units(text: str, *, strings: bool) -> list[tuple[int, str]]:
    units: list[tuple[int, str]] = []
    i = 0
    line = 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            units.append((line, text[i: n if end < 0 else end]))
            i = n if end < 0 else end
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            chunk = text[i:] if end < 0 else text[i : end + 2]
            units.append((line, chunk))
            line += chunk.count("\n")
            i = n if end < 0 else end + 2
            continue
        if strings and ch in {"'", '"', "`"}:
            quote = ch
            start_line = line
            j = i + 1
            while j < n:
                if text[j] == "\n":
                    line += 1
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            units.append((start_line, text[i:j]))
            i = j
            continue
        i += 1
    for match in re.finditer(r"\bfunction\s+([A-Za-z0-9_]+)", text):
        units.append((text.count("\n", 0, match.start()) + 1, match.group(1)))
    return units


def _lines(text: str) -> list[tuple[int, str]]:
    return list(enumerate(text.splitlines(), start=1))


def _units(rel: str, text: str) -> list[tuple[int, str]]:
    if rel == "tests/data/public_text_rules.json" or _frozen(rel):
        return []
    if rel.endswith(".py") and (rel.startswith("tests/") or rel.startswith("web/connect/test/")):
        return _py_units(text, strings=True, names=True)
    if rel.endswith((".js", ".mjs")) and rel.startswith("web/connect/test/"):
        return _js_units(text, strings=True)
    if rel.endswith(".py") and (rel.startswith(COMMENT_ROOTS) or rel.split("/", 1)[0] in COMMENT_ROOTS):
        return _py_units(text, strings=False, names=False)
    if rel.startswith("web/connect/src/") and rel.endswith((".js", ".mjs")):
        return _js_units(text, strings=False)
    if rel.endswith(".md"):
        return _lines(text)
    if rel == "proxy/Dockerfile" or rel.startswith(".github/workflows/") or rel.startswith(".github/ISSUE_TEMPLATE/"):
        return _lines(text)
    if Path(rel).name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        description = data.get("description")
        if not isinstance(description, str):
            return []
        line_no = next((index for index, line in enumerate(text.splitlines(), 1) if '"description"' in line), 1)
        return [(line_no, description)]
    if rel.endswith(".toml"):
        try:
            project = tomllib.loads(text).get("project", {})
        except tomllib.TOMLDecodeError:
            return []
        units = []
        if "description" in project:
            units.append((1, str(project["description"])))
        if "readme" in project:
            units.append((1, str(project["readme"])))
        return units
    return []


def _under_comment_root(rel: str) -> bool:
    return rel.startswith(tuple(part + "/" for part in COMMENT_ROOTS)) or rel.split("/", 1)[0] in COMMENT_ROOTS


def _in_url(line: str, start: int) -> bool:
    left = max(line.rfind(" ", 0, start), line.rfind("(", 0, start), line.rfind("<", 0, start))
    right_candidates = [line.find(mark, start) for mark in (" ", ")", ">")]
    right_candidates = [item for item in right_candidates if item >= 0]
    right = min(right_candidates) if right_candidates else len(line)
    token = line[left + 1 : right]
    return "://" in token


def _style_hits(rel: str, text: str, rules: dict, *, digests: set[str]) -> list[tuple[str, str, int]]:
    hits: list[tuple[str, str, int]] = []
    denylist = [token.lower() for token in rules["denylist"]]
    phrases = [phrase.lower() for phrase in rules["banned_phrases"]]
    for lineno, chunk in _units(rel, text):
        if _allow(rules, rel, lineno):
            continue
        if any(char in chunk for char in ACCENTS):
            hits.append(("characters", rel, lineno))
        lowered = chunk.lower()
        for token in denylist:
            if re.search(rf"\b{re.escape(token)}\b", lowered, flags=re.ASCII):
                hits.append(("denylist", rel, lineno))
                break
        if re.search(r"\bMike\b(?!-io-hash)", chunk) or re.search(r"\bIa\b", chunk):
            hits.append(("internal", rel, lineno))
        if re.search(r"\bP-[A-D]\d+\b", chunk) or "Publicaci" in chunk or re.search(r"bit[aá]cora", chunk, re.I):
            hits.append(("internal", rel, lineno))
        for match in re.finditer(r"\bD-\d{2,3}\b", chunk):
            if not _in_url(chunk, match.start()):
                hits.append(("internal", rel, lineno))
                break
        if re.search(r"\bR\d-\d\b", chunk):
            hits.append(("internal", rel, lineno))
        if re.search(r"\bMCP-\d\b", chunk):
            hits.append(("internal", rel, lineno))
        for phrase in phrases:
            if phrase in lowered:
                hits.append(("banned", rel, lineno))
                break
    for digest in digests:
        for match in re.finditer(r"0x[0-9a-fA-F]{40}", text):
            hashed = hashlib.sha256(match.group(0).lower().encode()).hexdigest()
            if hashed == digest:
                lineno = text.count("\n", 0, match.start()) + 1
                hits.append(("address", rel, lineno))
        for match in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
            hashed = hashlib.sha256(match.group(0).lower().encode()).hexdigest()
            if hashed == digest:
                lineno = text.count("\n", 0, match.start()) + 1
                hits.append(("address", rel, lineno))
    return hits


def _path_hits(paths: list[str], rules: dict) -> list[tuple[str, str, int]]:
    hits = []
    for rel in paths:
        for part in Path(rel).parts:
            lowered = part.lower()
            if any(fragment in lowered for fragment in rules["path_fragments"]):
                hits.append(("path", rel, 0))
    return hits


def scan(root: Path = ROOT, *, extra_digests: set[str] | None = None) -> list[tuple[str, str, int]]:
    rules = _rules()
    digests = set(rules["address_digests"])
    if extra_digests:
        digests.update(extra_digests)
    paths = _tracked(root)
    hits: list[tuple[str, str, int]] = []
    hits.extend(_path_hits(paths, rules))
    lock_names = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
    for rel in paths:
        if rel in {
            "tests/data/public_text_rules.json",
            "tests/test_public_text.py",
            "tests/fixtures/openapi-0.20.3.json",
        } or _frozen(rel):
            continue
        if Path(rel).name in lock_names or "node_modules/" in rel:
            continue
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        hits.extend(_style_hits(rel, text, rules, digests=digests))
    return hits


def _format(hits: list[tuple[str, str, int]]) -> str:
    visible = []
    for rule, rel, lineno in hits:
        if rule == "address":
            visible.append(f"{rel}:{lineno} address")
        else:
            visible.append(f"{rel}:{lineno} {rule}")
    return "\n".join(visible[:40])


def _git_bytes(spec: str) -> bytes | None:
    proc = subprocess.run(["git", "show", spec], cwd=ROOT, capture_output=True)
    if proc.returncode != 0:
        return None
    return proc.stdout


def _unique(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def _token_payload(text: str) -> dict[str, list[str]]:
    raw = _required_tokens(text)
    return {key: _unique(values) for key, values in raw.items()}


def _base_tokens() -> dict[str, list[str]]:
    """Tokens from the base README. A shallow checkout falls back to the committed JSON."""
    saved = json.loads(README_TOKENS.read_text(encoding="utf-8"))
    live = _git_bytes(f"{BASE}:README.md")
    if live is not None:
        assert _token_payload(live.decode()) == saved
    return saved


def _union_text() -> str:
    return "\n".join((ROOT / rel).read_text(encoding="utf-8") for rel in UNION)


def _headings(text: str) -> list[str]:
    found = []
    for line in text.splitlines():
        if line.startswith("## ") or line.startswith("### "):
            found.append(line.lstrip("#").strip())
    return found


def _fence_first_lines(text: str) -> list[str]:
    found: list[str] = []
    state = "out"
    for line in text.splitlines():
        if state == "out":
            if line.startswith("```"):
                state = "body"
            continue
        if state == "body":
            if line.startswith("```"):
                state = "out"
                continue
            found.append(line)
            state = "skip"
            continue
        if line.startswith("```"):
            state = "out"
    return found


def _required_tokens(text: str) -> dict[str, list[str]]:
    paths = re.findall(r"/v1/[a-z0-9_/{}.-]+", text)
    paths += re.findall(r"/\.well-known/[A-Za-z0-9_./-]+", text)
    return {
        "heading": _headings(text),
        "env": re.findall(r"SATSGATE_[A-Z0-9_]+", text),
        "path": paths,
        "fence": _fence_first_lines(text),
    }


def _missing(tokens: dict[str, list[str]], blob: str) -> list[str]:
    missing = []
    for kind, values in tokens.items():
        for value in dict.fromkeys(values):
            if value in blob or value in DROPPED:
                continue
            missing.append(f"{kind}: {value}")
    return missing


def github_slugs(text: str) -> list[str]:
    seen: dict[str, int] = {}
    slugs = []
    for line in text.splitlines():
        if not line.startswith("#"):
            continue
        title = line.lstrip("#").strip().lower()
        slug = re.sub(r"[^\w\s-]", "", title, flags=re.ASCII)
        slug = re.sub(r"\s+", "-", slug).strip("-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        slugs.append(slug if count == 0 else f"{slug}-{count}")
    return slugs


def _contributor_exempt(lines: list[str], index: int) -> bool:
    for line in reversed(lines[:index]):
        if line.startswith("#"):
            return "contributor" in line.lower()
    return False


def _install_hits(root: Path = ROOT, paths: list[str] | None = None) -> list[str]:
    hits = []
    rels = paths if paths is not None else _tracked(root)
    for rel in rels:
        if not rel.endswith(".md") and not rel.endswith(".py"):
            continue
        if rel in {"CONTRIBUTING.md", "docs/self-hosting.md", "tests/test_public_text.py"}:
            continue
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if rel.endswith(".md") and _contributor_exempt(lines, index):
                continue
            for banned in INSTALL_BANS:
                if banned in line:
                    hits.append(f"{rel}:{index + 1} {banned}")
    return hits


def _misalign_hits() -> list[str]:
    hits = []
    rules = _rules()
    for rel in _tracked():
        if rel in {"tests/data/public_text_rules.json", "tests/test_public_text.py", "tests/fixtures/openapi-0.20.3.json"}:
            continue
        if _frozen(rel):
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        for lineno, chunk in _units(rel, text):
            if _allow(rules, rel, lineno):
                continue
            for phrase in MISALIGN:
                if phrase in chunk:
                    hits.append(f"{rel}:{lineno} {phrase}")
                    break
            if rel in WORDING_FILES:
                lowered = chunk.lower()
                for pattern in WORDING_PATTERNS:
                    if re.search(pattern, lowered):
                        hits.append(f"{rel}:{lineno} {pattern}")
                        break
    return hits


def _canonical(schema: dict) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _load_production_openapi(db_path: Path) -> dict:
    saved = {key: value for key, value in os.environ.items() if key.startswith("SATSGATE_")}
    for key in saved:
        os.environ.pop(key, None)
    os.environ.update(OPENAPI_ENV)
    os.environ["SATSGATE_DB_PATH"] = str(db_path)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    try:
        import app.main as main

        return main.app.openapi()
    finally:
        for key in list(os.environ):
            if key.startswith("SATSGATE_"):
                os.environ.pop(key, None)
        os.environ.update(saved)


def _metadata_text(path: Path) -> str:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            name = next(item for item in archive.namelist() if item.endswith(".dist-info/METADATA"))
            return archive.read(name).decode("utf-8")
    with tarfile.open(path) as archive:
        member = next(item for item in archive.getmembers() if item.name.endswith("/PKG-INFO"))
        extracted = archive.extractfile(member)
        assert extracted is not None
        return extracted.read().decode("utf-8")


def _summary_and_description(metadata: str) -> str:
    header, _, body = metadata.partition("\n\n")
    summary = ""
    for line in header.splitlines():
        if line.lower().startswith("summary:"):
            summary = line.split(":", 1)[1].strip()
    return summary + "\n" + body


def test_t_dm_1_1_headline_is_the_same_everywhere() -> None:
    places: dict[str, str] = {}
    for rel in ("cli/pyproject.toml", "sdk/python/pyproject.toml", "proxy/pyproject.toml", "mcp/pyproject.toml"):
        places[rel] = tomllib.loads((ROOT / rel).read_text(encoding="utf-8"))["project"]["description"]
    for rel in ("cli/README.md", "sdk/python/README.md", "proxy/README.md", "mcp/README.md"):
        places[rel] = _first_paragraph((ROOT / rel).read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    bold = next(line for line in readme if line.startswith("**") and line.endswith("**"))
    places["README.md"] = bold.strip("*")
    dockerfile = (ROOT / "proxy" / "Dockerfile").read_text(encoding="utf-8")
    places["proxy/Dockerfile"] = re.search(
        r'org\.opencontainers\.image\.description="([^"]*)"',
        dockerfile,
    ).group(1)
    workflow = (ROOT / ".github" / "workflows" / "ghcr.yml").read_text(encoding="utf-8")
    places["ghcr.yml"] = re.search(r"org\.opencontainers\.image\.description=(.+)", workflow).group(1).strip()
    assert set(places.values()) == {HEADLINE}, places


def test_t_dm_1_1_one_changed_word_is_not_equal() -> None:
    altered = HEADLINE.replace("wallet", "purse")
    assert altered != HEADLINE


def _first_paragraph(text: str) -> str:
    lines = text.splitlines()
    index = 0
    while index < len(lines) and (not lines[index].strip() or lines[index].startswith("#") or lines[index].startswith("[")):
        index += 1
    paragraph = []
    while index < len(lines) and lines[index].strip():
        paragraph.append(lines[index].strip())
        index += 1
    return " ".join(paragraph)


def test_t_dm_2_1_real_tree_is_clean() -> None:
    hits = scan()
    assert hits == [], _format(hits)


@pytest.mark.parametrize(
    "sample_key",
    ["accent", "token", "internal_name", "review_id", "banned_word", "part_code"],
)
def test_t_dm_2_1_mutation_sample_is_rejected(sample_key: str) -> None:
    sample = _rules()["mutation_samples"][sample_key]
    hits = _style_hits("README.md", sample + "\n", _rules(), digests=set())
    assert hits, sample_key


def test_t_dm_2_1_address_override_is_rejected() -> None:
    address = "0x" + ("ab" * 20)
    digest = hashlib.sha256(address.lower().encode()).hexdigest()
    quiet = _style_hits("README.md", address + "\n", _rules(), digests=set(_rules()["address_digests"]))
    assert not [hit for hit in quiet if hit[0] == "address"]
    flagged = _style_hits("README.md", address + "\n", _rules(), digests={digest})
    assert [hit for hit in flagged if hit[0] == "address"]


def test_t_dm_2_2_built_metadata_passes_the_guard(tmp_path: Path) -> None:
    rules = _rules()
    digests = set(rules["address_digests"])
    for package in PACKAGES:
        out = tmp_path / package.name
        built = build_package(package, out)
        assert built.returncode == 0, built.stderr[-500:]
        for dist in list(out.glob("*.whl")) + list(out.glob("*.tar.gz")):
            text = _summary_and_description(_metadata_text(dist))
            hits = _style_hits(dist.name, text, rules, digests=digests)
            assert hits == [], dist.name


def test_t_dm_3_1_reference_move_keeps_the_base_tokens() -> None:
    for reason in DROPPED.values():
        assert reason.strip()
    missing = _missing(_base_tokens(), _union_text())
    assert missing == [], "\n".join(missing)


def test_t_dm_3_1_a_removed_setting_is_reported() -> None:
    tokens = {"env": ["SATSGATE_ENV"]}
    assert _missing(tokens, "nothing here") == ["env: SATSGATE_ENV"]


def test_t_dm_3_2_readme_shape() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert len(text.splitlines()) < 260
    assert HEADLINE in text
    assert "Tested end-to-end on mainnet with small amounts" in text
    assert "Per-tool pricing for remote MCP servers" in text
    assert "TypeScript SDK" in text
    assert "closed beta" not in text.lower()
    for url in (
        "https://satsgate.org/terms",
        "https://pypi.org/project/satsgate/",
        "https://github.com/Mike-io-hash/satsgate/pkgs/container/satsgate-proxy",
        "https://api.satsgate.org/openapi.json",
    ):
        assert url in text
    positions = []
    for heading in README_HEADINGS:
        found = next(
            index
            for index, line in enumerate(text.splitlines())
            if line.lstrip("#").strip() == heading
        )
        positions.append(found)
    assert positions == sorted(positions)


def test_t_dm_3_3_anchors_and_relative_links() -> None:
    assert "hosted-gate-x402" in github_slugs((ROOT / "README.md").read_text(encoding="utf-8"))
    assert "rotate-the-account-key" in github_slugs((ROOT / "CUSTOMER_QUICKSTART.md").read_text(encoding="utf-8"))
    renamed = (ROOT / "README.md").read_text(encoding="utf-8").replace("### Hosted gate (x402)", "### Gate receipt")
    assert "hosted-gate-x402" not in github_slugs(renamed)
    link = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for rel in _tracked():
        if not rel.endswith(".md") or _frozen(rel):
            continue
        text = (ROOT / rel).read_text(encoding="utf-8")
        for target in link.findall(text):
            target = target.strip().split()[0]
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path_part, _, anchor = target.partition("#")
            if path_part in {"", "#"}:
                destination = ROOT / rel
            else:
                destination = (ROOT / rel).parent / path_part
            assert destination.is_file(), f"{rel} -> {target}"
            if anchor:
                assert anchor in github_slugs(destination.read_text(encoding="utf-8")), f"{rel} -> {target}"


def test_t_dm_4_1_checkout_commands_stay_in_contributor_docs() -> None:
    assert _install_hits() == []


def test_t_dm_4_1_a_public_checkout_command_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("pip install -e sdk/python\n", encoding="utf-8")
    hits = _install_hits(tmp_path, ["README.md"])
    assert hits == ["README.md:1 pip install -e"]


def test_t_dm_4_2_twine_and_readme_renderer(tmp_path: Path) -> None:
    from readme_renderer.markdown import render

    built_paths: list[Path] = []
    for package in PACKAGES:
        out = tmp_path / package.name
        result = build_package(package, out)
        assert result.returncode == 0, result.stderr[-500:]
        built_paths.extend(out.glob("*.whl"))
        built_paths.extend(out.glob("*.tar.gz"))
    check = subprocess.run(
        [sys.executable, "-m", "twine", "check", "--strict", *[str(path) for path in built_paths]],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr
    for rel in ("cli/README.md", "sdk/python/README.md", "proxy/README.md", "mcp/README.md"):
        source = (ROOT / rel).read_text(encoding="utf-8")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            html = render(source)
        assert html, rel
        assert not caught, [str(item.message) for item in caught]
        assert HEADLINE in html


def test_t_dm_5_1_old_phrases_stay_out() -> None:
    assert _misalign_hits() == []


def _app_version() -> str:
    text = (ROOT / "app" / "config.py").read_text(encoding="utf-8")
    return re.search(r'^APP_VERSION = "([^"]+)"', text, re.M).group(1)


_CORE_VERSION = "0.20.5"
_VERSION_REFRESH = "core version changed: refresh the OpenAPI snapshot and its expected delta"
_OPENAPI_SHA256 = "f93c71e3b43da7f9fe3acaabefeaa3ce559c09e7cb998713518f84fdc1f4ff8b"
_FORECAST_OLD = "Pace of recent paid unlocks, in milisatoshis. Never names a pack."
_FORECAST_NEW = "Pace of recent paid unlocks, in millisatoshis. Never names a pack."
_TOPUP_OLD = (
    "Top up any amount of sats. Minimum is SATSGATE_TOPUP_MIN_SATS.\n\n"
    "No key: the invoice can create the account when it is paid. A restricted\n"
    "key cannot top up. The credited milisatoshis include the per-top-up bonus."
)
_TOPUP_NEW = (
    "Top up any amount of sats. Minimum is SATSGATE_TOPUP_MIN_SATS.\n\n"
    "No key: the invoice can create the account when it is paid. A restricted\n"
    "key cannot top up. The credited millisatoshis include the per-top-up bonus."
)
_OPENAPI_DELTA = (
    (("info", "version"), "0.20.3", "0.20.5"),
    (("paths", "/v1/usage/forecast", "get", "description"), _FORECAST_OLD, _FORECAST_NEW),
    (("paths", "/v1/topup/lightning", "post", "description"), _TOPUP_OLD, _TOPUP_NEW),
)
_SPELLING_EXEMPT = {
    "docs/terms/2026-11-13.md": "Frozen terms.",
    "tests/fixtures/terms-2026-11-13-index.html": "Frozen terms.",
    "tests/fixtures/openapi-0.20.3.json": "Historical production snapshot.",
    "tests/fixtures/readme-base-tokens.json": "Historical README heading tokens.",
    "tests/test_public_text.py": "This guard names the pattern it rejects.",
}
_MISSPELLING = re.compile("milisat", re.IGNORECASE)


def _require_current_core() -> None:
    assert _app_version() == _CORE_VERSION, _VERSION_REFRESH


def _at(document: dict, path: tuple[str, ...]):
    cursor = document
    for key in path:
        cursor = cursor[key]
    return cursor


def _put(document: dict, path: tuple[str, ...], value: str) -> None:
    cursor = document
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value


def test_t_m1_2_openapi_delta_is_exact(tmp_path: Path) -> None:
    """T-M1.2. The live schema matches the 0.20.3 snapshot plus the pinned delta."""
    _require_current_core()
    assert hashlib.sha256(GOLDEN.read_bytes()).hexdigest() == _OPENAPI_SHA256
    assert len(_OPENAPI_DELTA) == 3
    fixture = json.loads(GOLDEN.read_text(encoding="utf-8"))
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    for path, old, new in _OPENAPI_DELTA:
        assert _at(fixture, path) == old, path
        _put(expected, path, new)
    live = _load_production_openapi(tmp_path / "openapi.sqlite3")
    assert _canonical(live) == _canonical(expected)


def test_t_m1_4_spelling_scan() -> None:
    """T-M1.4. The raw pattern is absent from tracked text except the listed files."""
    for rel, reason in _SPELLING_EXEMPT.items():
        assert reason.strip() == reason and "\n" not in reason
        assert "*" not in rel and not rel.endswith("/")
    hits = []
    for rel in _tracked():
        if rel in _SPELLING_EXEMPT:
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _MISSPELLING.search(line):
                hits.append(f"{rel}:{lineno}")
    assert hits == [], "\n".join(hits)


def test_t_dm_8_1_publishers_are_added_one_at_a_time() -> None:
    text = (ROOT / "docs" / "publishing.md").read_text(encoding="utf-8").lower()
    assert "one at a time" in text
    assert "one pending publisher" in text
    for phrase in ("add four pending", "add the four", "add the same four"):
        assert phrase not in text


def test_t_dm_9_1_mcp_help_and_version() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "mcp" / "src")
    # Keep stdin open. A server that waits for a client must hit the timeout.
    help_proc = subprocess.Popen(
        [sys.executable, "-m", "satsgate_mcp", "--help"],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        help_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        help_proc.kill()
        help_proc.wait(timeout=5)
        raise
    help_out = help_proc.stdout.read() if help_proc.stdout is not None else ""
    help_err = help_proc.stderr.read() if help_proc.stderr is not None else ""
    assert help_proc.returncode == 0, help_err
    assert "SATSGATE_MCP_NWC_URI" in help_out
    assert "nostr+walletconnect://" not in help_out
    version = subprocess.run(
        [sys.executable, "-m", "satsgate_mcp", "--version"],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        stdin=subprocess.DEVNULL,
    )
    assert version.returncode == 0
    assert version.stdout.startswith("satsgate-mcp ")
    unknown = subprocess.run(
        [sys.executable, "-m", "satsgate_mcp", "--not-a-flag"],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        stdin=subprocess.DEVNULL,
    )
    assert unknown.returncode == 2
    assert "usage:" in unknown.stderr
    server = subprocess.Popen(
        [sys.executable, "-m", "satsgate_mcp"],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            server.wait(timeout=1)
    finally:
        server.kill()
        server.wait(timeout=5)
