"""T-D.8.1 and T-D.8.2. Dated terms sources rebuild, and the 2026-11-13 page stays put."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_terms.py"
GOLDEN_HTML = ROOT / "tests" / "fixtures" / "terms-2026-11-13-index.html"
GOLDEN_CSS = ROOT / "tests" / "fixtures" / "terms-2026-11-13.css"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], check=False, capture_output=True, text=True)


def test_t_d_8_2_rendered_2026_11_13_matches_the_golden(tmp_path: Path) -> None:
    dest = tmp_path / "dist"
    built = _run("--dest", str(dest))
    assert built.returncode == 0, built.stderr
    assert (dest / "2026-11-13" / "index.html").read_bytes() == GOLDEN_HTML.read_bytes()
    assert (dest / "2026-11-13" / "terms.css").read_bytes() == GOLDEN_CSS.read_bytes()


def test_t_d_8_1_a_later_date_keeps_the_frozen_snapshot(tmp_path: Path) -> None:
    current = (ROOT / "docs" / "hosted-gate-terms.md").read_text(encoding="utf-8")
    frozen = (ROOT / "docs" / "terms" / "2026-11-13.md").read_text(encoding="utf-8")
    later = current.replace("Effective date: 2026-11-13.", "Effective date: 2026-12-01.", 1)
    source = tmp_path / "hosted-gate-terms.md"
    terms = tmp_path / "terms"
    terms.mkdir()
    source.write_text(later, encoding="utf-8")
    (terms / "2026-11-13.md").write_text(frozen, encoding="utf-8")
    (terms / "2026-12-01.md").write_text(later, encoding="utf-8")
    dest = tmp_path / "dist"

    def build(*extra: str) -> subprocess.CompletedProcess[str]:
        return _run("--source", str(source), "--terms-dir", str(terms), "--dest", str(dest), *extra)

    built = build()
    assert built.returncode == 0, built.stderr
    old = (dest / "2026-11-13" / "index.html").read_bytes()
    assert old == GOLDEN_HTML.read_bytes()
    assert (dest / "2026-11-13" / "terms.css").read_bytes() == GOLDEN_CSS.read_bytes()
    checked = build("--check")
    assert checked.returncode == 0, checked.stderr
    (dest / "notes.txt").write_text("not rendered by this repo\n", encoding="utf-8")
    loose = build("--check")
    assert loose.returncode == 0, loose.stderr
    strict = build("--check", "--strict")
    assert strict.returncode != 0
    assert "unknown" in strict.stderr
    shutil.rmtree(dest)
    again = build()
    assert again.returncode == 0, again.stderr
    assert (dest / "2026-11-13" / "index.html").read_bytes() == old
    assert (dest / "2026-12-01" / "index.html").read_bytes()
    assert b"2026-12-01" in (dest / "2026-12-01" / "index.html").read_bytes()
