"""T-D.3.1. publish.yml cannot publish from a pull request or a failed rehearsal."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _load(path: Path) -> dict:
    text = re.sub(r'(?m)^on:', '"on":', path.read_text(encoding="utf-8"), count=1)
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def _uses(workflow: dict) -> list[str]:
    found: list[str] = []
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            if "uses" in step:
                found.append(step["uses"])
    return found


def test_t_d_3_1_publish_workflow_cannot_upload_from_a_pull_request() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = _load(WORKFLOW)
    assert set(workflow["on"]) == {"push", "pull_request"}
    assert workflow["on"]["push"]["tags"] == ["sdk-v*", "proxy-v*", "mcp-v*", "satsgate-v*"]
    paths = set(workflow["on"]["pull_request"]["paths"])
    assert {
        "sdk/python/**",
        "proxy/**",
        "mcp/**",
        "cli/**",
        "scripts/release/**",
        ".github/workflows/publish.yml",
    } <= paths
    for forbidden in ("workflow_dispatch", "pull_request_target", "schedule"):
        assert forbidden not in text
    assert "release" not in workflow["on"]
    assert workflow["permissions"] == {}
    assert workflow["concurrency"]["group"] == "publish-${{ github.ref }}"
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert "actions/cache" not in text
    assert re.search(r"(?im)^\s*cache\s*:", text) is None
    assert "secrets." not in text

    jobs = workflow["jobs"]
    token_jobs = []
    for name, job in jobs.items():
        permissions = job.get("permissions") or {}
        if isinstance(permissions, dict) and permissions.get("id-token") == "write":
            token_jobs.append(name)
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
    assert token_jobs == ["publish-testpypi", "publish-pypi"]

    for raw in _uses(workflow):
        assert _SHA.fullmatch(raw.split("@", 1)[1]), raw

    testpypi = jobs["publish-testpypi"]
    pypi = jobs["publish-pypi"]
    assert testpypi["environment"] == "testpypi"
    assert pypi["environment"] == "pypi"
    assert "startsWith(github.ref, 'refs/tags/')" in testpypi["if"]
    assert "needs.plan.outputs.rehearse == 'true'" in testpypi["if"]
    assert "inputs." not in jobs["plan"].get("if", "")
    assert "workflow_dispatch" not in jobs["plan"].get("if", "")
    needed = set(pypi["needs"])
    assert {"smoke-local", "plan", "smoke-testpypi"} <= needed
    expr = pypi["if"]
    assert "always()" in expr
    assert "needs.smoke-local.result == 'success'" in expr
    assert "needs.plan.result == 'success'" in expr
    assert "needs.plan.outputs.rehearse == 'false'" in expr
    assert "needs.smoke-testpypi.result == 'skipped'" in expr
    assert "needs.plan.outputs.rehearse == 'true'" in expr
    assert "needs.smoke-testpypi.result == 'success'" in expr
    assert "needs.smoke-testpypi.result == 'failure'" not in expr
    assert "needs.smoke-testpypi.result == 'cancelled'" not in expr
    assert "id-token" not in json.dumps(jobs["build"].get("permissions"))


def test_package_matrix_matches_the_tree() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "release" / "package_matrix.py")],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    rows = json.loads(proc.stdout)
    assert [row["dist_name"] for row in rows] == [
        "satsgate-sdk",
        "satsgate-proxy",
        "satsgate-mcp",
        "satsgate",
    ]
    assert rows[0]["version"] == "0.10.0"
    assert rows[1]["version"] == "0.14.1"
    assert rows[2]["version"] == "0.13.0"
    legacy = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "release" / "package_matrix.py"), "--tag", "v0.2.0"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert legacy.returncode != 0
