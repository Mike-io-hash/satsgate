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


_TOKEN = re.compile(
    r"&&|\|\||==|!=|!|\(|\)|,|'(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\"|[A-Za-z_][A-Za-z0-9_.-]*"
)


def _tokens(expr: str) -> list[str]:
    found = _TOKEN.findall(expr)
    if "".join(found) != re.sub(r"\s+", "", expr):
        raise AssertionError(f"unparsed publish if: {expr}")
    return found


class _If:
    def __init__(self, expr: str, env: dict[str, str]) -> None:
        self.tokens = _tokens(expr)
        self.i = 0
        self.env = env

    def parse(self) -> bool:
        value = self._or()
        if self.i != len(self.tokens):
            raise AssertionError(self.tokens[self.i :])
        return value

    def _or(self) -> bool:
        value = self._and()
        while self._at("||"):
            right = self._and()
            value = value or right
        return value

    def _and(self) -> bool:
        value = self._primary()
        while self._at("&&"):
            right = self._primary()
            value = value and right
        return value

    def _at(self, token: str) -> bool:
        if self.i < len(self.tokens) and self.tokens[self.i] == token:
            self.i += 1
            return True
        return False

    def _primary(self) -> bool:
        if self._at("("):
            value = self._or()
            if not self._at(")"):
                raise AssertionError("missing )")
            return value
        if self._at("!"):
            return not self._primary()
        name = self.tokens[self.i]
        self.i += 1
        if name == "cancelled":
            if not (self._at("(") and self._at(")")):
                raise AssertionError("cancelled")
            return self.env.get("run") == "cancelled"
        if name == "always":
            if not (self._at("(") and self._at(")")):
                raise AssertionError("always")
            return True
        if name == "startsWith":
            # The table below is the tag case, so startsWith(github.ref, 'refs/tags/') is true.
            if not self._at("("):
                raise AssertionError("startsWith")
            while self.tokens[self.i] != ")":
                self.i += 1
            self.i += 1
            return True
        if self.tokens[self.i] not in {"==", "!="}:
            raise AssertionError(name)
        op = self.tokens[self.i]
        self.i += 1
        right = self.tokens[self.i].strip("'\"")
        self.i += 1
        left = self.env[name]
        return left == right if op == "==" else left != right


def _publish_allowed(expr: str) -> None:
    results = ("success", "failure", "cancelled", "skipped")
    for smoke_local in results:
        for plan in results:
            for smoke in results:
                for rehearse in ("true", "false"):
                    env = {
                        "needs.build.result": "success",
                        "needs.smoke-local.result": smoke_local,
                        "needs.plan.result": plan,
                        "needs.smoke-testpypi.result": smoke,
                        "needs.plan.outputs.rehearse": rehearse,
                    }
                    got = _If(expr, env).parse()
                    allowed = (
                        smoke_local == "success"
                        and plan == "success"
                        and (
                            (rehearse == "false" and smoke == "skipped")
                            or (rehearse == "true" and smoke == "success")
                        )
                    )
                    assert got is allowed, env


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
    assert set(testpypi["needs"]) == {"build", "smoke-local", "plan"}
    assert testpypi["environment"] == "testpypi"
    assert pypi["environment"] == "pypi"
    assert "startsWith(github.ref, 'refs/tags/')" in testpypi["if"]
    assert "needs.plan.outputs.rehearse == 'true'" in testpypi["if"]
    assert "inputs." not in jobs["plan"].get("if", "")
    assert "workflow_dispatch" not in jobs["plan"].get("if", "")
    needed = set(pypi["needs"])
    assert {"smoke-local", "plan", "smoke-testpypi"} <= needed
    expr = pypi["if"]
    assert "!cancelled()" in expr
    assert "always()" not in expr
    assert "needs.smoke-local.result == 'success'" in expr
    assert "needs.plan.result == 'success'" in expr
    assert "needs.plan.outputs.rehearse == 'false'" in expr
    assert "needs.smoke-testpypi.result == 'skipped'" in expr
    assert "needs.plan.outputs.rehearse == 'true'" in expr
    assert "needs.smoke-testpypi.result == 'success'" in expr
    assert "needs.smoke-testpypi.result == 'failure'" not in expr
    assert "needs.smoke-testpypi.result == 'cancelled'" not in expr
    assert jobs["build"].get("permissions") == {"contents": "read"}
    assert "id-token" not in json.dumps(jobs["build"].get("permissions"))
    for name, job in jobs.items():
        permissions = job.get("permissions", {})
        assert isinstance(permissions, dict), name
        assert "write-all" not in permissions.values()
    _publish_allowed(pypi["if"])


def test_i_r4_1_a_cancelled_run_does_not_publish_or_verify() -> None:
    jobs = _load(WORKFLOW)["jobs"]
    for rehearse, smoke in (("true", "success"), ("false", "skipped")):
        env = {
            "needs.build.result": "success",
            "needs.smoke-local.result": "success",
            "needs.plan.result": "success",
            "needs.smoke-testpypi.result": smoke,
            "needs.publish-testpypi.result": "success",
            "needs.plan.outputs.rehearse": rehearse,
            "needs.publish-pypi.result": "success",
            "run": "cancelled",
        }
        assert _If(jobs["smoke-testpypi"]["if"], env).parse() is False
        assert _If(jobs["publish-pypi"]["if"], env).parse() is False
        assert _If(jobs["verify-pypi"]["if"], env).parse() is False
        env["run"] = ""
        assert _If(jobs["publish-pypi"]["if"], env).parse() is True
        assert _If(jobs["verify-pypi"]["if"], env).parse() is True
        if rehearse == "true":
            assert _If(jobs["smoke-testpypi"]["if"], env).parse() is True


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
    assert rows[0]["version"] == "0.10.1"
    assert rows[1]["version"] == "0.15.0"
    assert rows[2]["version"] == "0.14.0"
    legacy = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "release" / "package_matrix.py"), "--tag", "v0.2.0"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert legacy.returncode != 0
