"""T-D.4.1. The proxy image cannot be pushed from a pull request."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ghcr.yml"
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _load(path: Path) -> dict:
    text = re.sub(r'(?m)^on:', '"on":', path.read_text(encoding="utf-8"), count=1)
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def _tags():
    path = ROOT / "scripts" / "release" / "proxy_tags.py"
    spec = importlib.util.spec_from_file_location("proxy_tags", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.tag_lines


def test_proxy_tags_mark_latest_only_for_the_highest_version() -> None:
    tag_lines = _tags()
    assert tag_lines("0.14.1", []) == [
        "type=raw,value=0.14.1",
        "type=raw,value=0.14",
        "type=raw,value=latest",
    ]
    assert "type=raw,value=latest" in tag_lines("0.14.1", ["proxy-v0.14.0", "v0.2.0"])
    assert "type=raw,value=latest" not in tag_lines("0.14.1", ["proxy-v0.14.2"])


def test_t_d_4_1_ghcr_workflow_pushes_only_from_the_tag_job() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = _load(WORKFLOW)
    assert workflow["on"]["push"]["tags"] == ["proxy-v*"]
    assert "pull_request" in workflow["on"]
    assert workflow["permissions"] == {}
    assert "workflow_dispatch" not in text
    assert "pull_request_target" not in text
    jobs = workflow["jobs"]
    image = jobs["image"]
    build = jobs["build"]
    assert image["environment"] == "ghcr"
    assert image["permissions"]["packages"] == "write"
    writers = [
        name
        for name, job in jobs.items()
        if isinstance(job.get("permissions"), dict) and job["permissions"].get("packages") == "write"
    ]
    assert writers == ["image"]
    assert "docker/login-action@" not in yaml.safe_dump(build)
    for step in build["steps"]:
        if "with" in step and "push" in step["with"]:
            assert step["with"]["push"] is False
    for job in jobs.values():
        for step in job.get("steps") or []:
            raw = step.get("uses")
            if raw:
                assert _SHA.fullmatch(raw.split("@", 1)[1]), raw
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
