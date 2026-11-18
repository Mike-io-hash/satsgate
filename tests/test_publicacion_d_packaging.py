"""T-D.1.1 and T-D.1.2. T-D.1.3 lives in test_publicacion_c.py and reuses T-C.1.4."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

from release_build import PACKAGES, ROOT, build_package

_LINK = re.compile(r"\]\(([^)]*)\)")
_PYPI_READMES = (
    ROOT / "sdk" / "python" / "README.md",
    ROOT / "proxy" / "README.md",
    ROOT / "mcp" / "README.md",
    ROOT / "cli" / "README.md",
)


def _wheels(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.whl"))


def test_t_d_1_1_wheels_carry_the_spdx_license_file(tmp_path: Path) -> None:
    """Removing license-files from a package drops this test.

    The wheel must contain *.dist-info/licenses/LICENSE, byte-identical to the
    root LICENSE, and the build log must not warn that the license form is deprecated.
    """
    license_bytes = (ROOT / "LICENSE").read_bytes()
    built: list[Path] = []
    for package in PACKAGES:
        project = tomllib.loads((package / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        # setuptools>=77 still ships LICENSE from its default pattern when this
        # field is omitted, so removing license-files fails here.
        assert project["license-files"] == ["LICENSE"]
        assert "License :: OSI Approved :: Apache Software License" not in project["classifiers"]
        assert "Development Status :: 4 - Beta" in project["classifiers"]
        proc = build_package(package, tmp_path / package.name)
        assert proc.returncode == 0, proc.stderr[-2000:]
        for line in (proc.stdout + "\n" + proc.stderr).splitlines():
            lowered = line.lower()
            assert not ("deprecat" in lowered and "licen" in lowered), line
        artifacts = list((tmp_path / package.name).glob("*.tar.gz")) + _wheels(tmp_path / package.name)
        assert artifacts, package
        built.extend(artifacts)
        wheels = _wheels(tmp_path / package.name)
        assert len(wheels) == 1, package
        with zipfile.ZipFile(wheels[0]) as archive:
            meta_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            metadata = archive.read(meta_name).decode("utf-8")
            licenses = [name for name in archive.namelist() if name.endswith(".dist-info/licenses/LICENSE")]
            assert licenses, package
            assert all(archive.read(name) == license_bytes for name in licenses)
        assert "License-Expression: Apache-2.0" in metadata
        assert "License :: OSI Approved" not in metadata
    check = subprocess.run(
        [sys.executable, "-m", "twine", "check", "--strict", *[str(path) for path in built]],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr


def test_t_d_1_2_pypi_readmes_have_no_relative_links() -> None:
    """A relative ]( target, including [x](./README.md), fails this test."""
    for path in _PYPI_READMES:
        for target in _LINK.findall(path.read_text(encoding="utf-8")):
            assert target.startswith(("http", "#", "mailto:")), f"{path}: {target}"
