#!/usr/bin/env python3
"""Build the public terms page from docs/hosted-gate-terms.md.

The markdown is the source of truth. This script writes the current page and
a dated snapshot. A dated directory that already exists is not overwritten
when the new render would change it. --check compares that output to the
on-disk dist and exits non-zero when they differ. It does not write.

Allowed markdown: one # heading, ## headings, paragraphs, `code`, and **bold**.
Images, raw HTML, tables, links, lists, and other constructs fail the build.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "docs" / "hosted-gate-terms.md"
DEFAULT_TERMS = ROOT / "docs" / "terms"
DEFAULT_DEST = ROOT / "web" / "terms" / "dist"
_TERMS_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.md$")
CURRENT_CANONICAL = "https://satsgate.org/terms"
TITLE = "Satsgate terms of use"

_DATE_LINE = re.compile(r"^Effective date: (\d{4}-\d{2}-\d{2})\.$")
_CODE = re.compile(r"`([^`\n]+)`")
_BOLD = re.compile(r"\*\*([^*\n]+)\*\*")
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_LINK = re.compile(r"(?<!!)\[[^\]]+\]\([^)]+\)")
_RAW_HTML = re.compile(r"</?[A-Za-z!]|<!--|<!DOCTYPE", re.IGNORECASE)
_TABLE_RULE = re.compile(r"^\s*\|.*\|\s*$|^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
_FENCE = re.compile(r"^\s*```")
_BAD_HEADING = re.compile(r"^#{3,}\s")
_LIST = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+\S")
_QUOTE = re.compile(r"^\s*>")
_RULE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")

TERMS_CSS = """\
html {
  color-scheme: light;
}

body {
  margin: 0;
  background: #fbfbf9;
  color: #1c1917;
  font-family: system-ui, sans-serif;
  font-size: 1.0625rem;
  line-height: 1.6;
}

main {
  max-width: 40rem;
  margin: 0 auto;
  padding: 1.25rem 1rem 3rem;
}

h1 {
  font-size: 1.7rem;
  line-height: 1.25;
  margin: 0 0 1rem;
}

h2 {
  font-size: 1.15rem;
  line-height: 1.3;
  margin: 1.75rem 0 0.4rem;
}

p {
  margin: 0.65rem 0;
}

a {
  color: #1d4e89;
}

code {
  font-family: ui-monospace, monospace;
  font-size: 0.92em;
  overflow-wrap: anywhere;
}

@media (max-width: 40rem) {
  body {
    font-size: 1rem;
  }

  main {
    padding: 1rem 0.9rem 2.5rem;
  }
}
"""


class BuildError(Exception):
    """The markdown cannot be rendered, or a frozen snapshot would change."""


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _reject_unexpected(text: str) -> None:
    if _IMAGE.search(text):
        raise BuildError("images are not allowed in the terms markdown")
    if _LINK.search(text):
        raise BuildError("markdown links are not allowed in the terms markdown")
    if _RAW_HTML.search(text):
        raise BuildError("raw HTML is not allowed in the terms markdown")
    for line_no, line in enumerate(text.splitlines(), 1):
        if _TABLE_RULE.match(line) or (line.strip().startswith("|") and "|" in line.strip()[1:]):
            raise BuildError(f"line {line_no}: tables are not allowed in the terms markdown")
        if _FENCE.match(line):
            raise BuildError(f"line {line_no}: fenced code is not allowed in the terms markdown")
        if _BAD_HEADING.match(line):
            raise BuildError(f"line {line_no}: only # and ## headings are allowed")
        if _LIST.match(line):
            raise BuildError(f"line {line_no}: lists are not allowed in the terms markdown")
        if _QUOTE.match(line):
            raise BuildError(f"line {line_no}: blockquotes are not allowed in the terms markdown")
        if _RULE.match(line):
            raise BuildError(f"line {line_no}: horizontal rules are not allowed in the terms markdown")
        if "<" in line or ">" in line:
            raise BuildError(f"line {line_no}: raw HTML is not allowed in the terms markdown")


def _render_inline(text: str) -> str:
    if text.count("`") % 2 != 0:
        raise BuildError("unclosed `code` span in the terms markdown")
    pieces: list[str] = []
    cursor = 0
    for match in _CODE.finditer(text):
        pieces.append(("text", text[cursor : match.start()]))
        pieces.append(("code", match.group(1)))
        cursor = match.end()
    pieces.append(("text", text[cursor:]))
    rendered: list[str] = []
    for kind, chunk in pieces:
        if kind == "code":
            rendered.append(f"<code>{_escape(chunk)}</code>")
            continue
        if chunk.count("**") % 2 != 0:
            raise BuildError("unclosed **bold** span in the terms markdown")
        bold_cursor = 0
        for bold in _BOLD.finditer(chunk):
            rendered.append(_escape(chunk[bold_cursor : bold.start()]))
            rendered.append(f"<strong>{_escape(bold.group(1))}</strong>")
            bold_cursor = bold.end()
        rendered.append(_escape(chunk[bold_cursor:]))
    return "".join(rendered)


def parse_document(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Return the effective date and the heading and paragraph blocks."""
    _reject_unexpected(text)
    blocks: list[tuple[str, str]] = []
    paragraph: list[str] = []

    def flush() -> None:
        if paragraph:
            blocks.append(("p", " ".join(paragraph)))
            paragraph.clear()

    for line_no, line in enumerate(text.splitlines(), 1):
        if line.strip() == "":
            flush()
            continue
        if line.startswith("## "):
            flush()
            heading = line[3:].strip()
            if not heading:
                raise BuildError(f"line {line_no}: empty heading")
            blocks.append(("h2", heading))
            continue
        if line.startswith("# "):
            flush()
            heading = line[2:].strip()
            if not heading:
                raise BuildError(f"line {line_no}: empty heading")
            blocks.append(("h1", heading))
            continue
        if line.startswith("#"):
            raise BuildError(f"line {line_no}: malformed heading")
        paragraph.append(line.strip())
    flush()

    if sum(1 for kind, _ in blocks if kind == "h1") != 1:
        raise BuildError("the terms need exactly one # heading")
    dates = [match.group(1) for kind, content in blocks if kind == "p" and (match := _DATE_LINE.match(content))]
    if any(kind == "p" and content.startswith("Effective date:") and _DATE_LINE.match(content) is None for kind, content in blocks):
        raise BuildError("effective date must look like 'Effective date: YYYY-MM-DD.'")
    if len(dates) != 1:
        raise BuildError("the terms need exactly one effective-date line")
    return dates[0], blocks


def render_html(blocks: list[tuple[str, str]], *, canonical: str, css_href: str, archive: bool) -> str:
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_escape(TITLE)}</title>",
        f'<link rel="canonical" href="{_escape(canonical)}">',
        f'<link rel="stylesheet" href="{_escape(css_href)}">',
        "</head>",
        "<body>",
        "<main>",
    ]
    for kind, content in blocks:
        inner = _render_inline(content)
        if kind == "h1":
            parts.append(f"<h1>{inner}</h1>")
        elif kind == "h2":
            parts.append(f"<h2>{inner}</h2>")
        else:
            parts.append(f"<p>{inner}</p>")
    if archive:
        parts.append('<p>Archived copy. <a href="https://satsgate.org/terms">Current terms</a>.</p>')
    parts.extend(["</main>", "</body>", "</html>", ""])
    return "\n".join(parts)


def render_site(text: str) -> dict[str, str]:
    """Return dist-relative paths and the exact file bytes for this source."""
    date, blocks = parse_document(text)
    current = render_html(blocks, canonical=CURRENT_CANONICAL, css_href="/terms/terms.css", archive=False)
    dated_canonical = f"{CURRENT_CANONICAL}/{date}"
    dated = render_html(
        blocks,
        canonical=dated_canonical,
        css_href=f"/terms/{date}/terms.css",
        archive=True,
    )
    return {
        "index.html": current,
        "terms.css": TERMS_CSS,
        f"{date}/index.html": dated,
        f"{date}/terms.css": TERMS_CSS,
    }


def _on_disk(dest: Path) -> dict[str, str]:
    if not dest.exists():
        return {}
    found: dict[str, str] = {}
    for path in sorted(dest.rglob("*")):
        if path.is_file():
            found[path.relative_to(dest).as_posix()] = path.read_text(encoding="utf-8")
    return found


def load_frozen(terms_dir: Path) -> dict[str, str]:
    """Dated markdown sources. The filename date is the effective date."""
    if not terms_dir.is_dir():
        raise BuildError(f"missing frozen terms directory {terms_dir}")
    found: dict[str, str] = {}
    for path in sorted(terms_dir.glob("*.md")):
        match = _TERMS_FILE.match(path.name)
        if match is None:
            raise BuildError(f"unexpected terms source {path.name}")
        found[match.group(1)] = path.read_text(encoding="utf-8")
    if not found:
        raise BuildError(f"no frozen terms sources in {terms_dir}")
    return found


def render_sources(current: str, frozen: dict[str, str]) -> dict[str, str]:
    """Current page from the live source, every dated snapshot from its frozen source."""
    current_date, current_blocks = parse_document(current)
    if frozen.get(current_date) != current:
        raise BuildError(f"docs/terms/{current_date}.md must be identical to the current terms")
    files = {
        "index.html": render_html(current_blocks, canonical=CURRENT_CANONICAL, css_href="/terms/terms.css", archive=False),
        "terms.css": TERMS_CSS,
    }
    for date, text in sorted(frozen.items()):
        snap_date, blocks = parse_document(text)
        if snap_date != date:
            raise BuildError(f"docs/terms/{date}.md says effective date {snap_date}")
        files[f"{date}/index.html"] = render_html(
            blocks,
            canonical=f"{CURRENT_CANONICAL}/{date}",
            css_href=f"/terms/{date}/terms.css",
            archive=True,
        )
        files[f"{date}/terms.css"] = TERMS_CSS
    return files


def check_dest(dest: Path, files: dict[str, str], *, strict: bool = False) -> int:
    """Compare the renderable set. Unknown on-disk files fail only with --strict."""
    actual = _on_disk(dest)
    stale = sorted(rel for rel in files if actual.get(rel) != files[rel])
    unknown = sorted(set(actual) - set(files))
    if stale:
        print("build_terms: dist is stale: " + ", ".join(stale), file=sys.stderr)
        return 1
    if unknown:
        print("build_terms: dist has unknown files: " + ", ".join(unknown), file=sys.stderr)
        if strict:
            return 1
    return 0


def _frozen_dates(files: dict[str, str]) -> list[str]:
    found: list[str] = []
    for rel in files:
        parent, _, name = rel.partition("/")
        if name and parent not in found and _DATE_LINE.match(f"Effective date: {parent}."):
            found.append(parent)
    return found


def write_dest(dest: Path, files: dict[str, str]) -> None:
    """Write dist. Refuse to replace a dated snapshot whose bytes would change."""
    dates = _frozen_dates(files)
    if not dates:
        raise BuildError("internal: rendered site has no dated snapshot")
    for date in dates:
        prefix = f"{date}/"
        for rel, content in files.items():
            if not rel.startswith(prefix):
                continue
            path = dest / rel
            if not path.is_file():
                continue
            existing = path.read_text(encoding="utf-8")
            if existing != content:
                raise BuildError(f"refusing to overwrite frozen terms snapshot {rel}")
    for rel, content in files.items():
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file() and path.read_text(encoding="utf-8") == content:
            continue
        path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the public terms HTML from the markdown source.")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if dist is missing or stale. Do not write.")
    parser.add_argument("--strict", action="store_true", help="Also fail when dist has files this repo cannot render.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--terms-dir", type=Path, default=None)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = parser.parse_args(argv)
    try:
        text = args.source.read_text(encoding="utf-8")
        use_frozen = args.terms_dir is not None or args.source.resolve() == DEFAULT_SOURCE.resolve()
        if use_frozen:
            files = render_sources(text, load_frozen(args.terms_dir or DEFAULT_TERMS))
        else:
            files = render_site(text)
        if args.check:
            return check_dest(args.dest, files, strict=args.strict)
        write_dest(args.dest, files)
    except BuildError as exc:
        print(f"build_terms: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"build_terms: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
