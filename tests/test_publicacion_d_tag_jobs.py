"""B-2. The OIDC publish jobs stage files without a checkout or the repo."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github" / "workflows" / "publish.yml",
    ROOT / ".github" / "workflows" / "ghcr.yml",
    ROOT / ".github" / "workflows" / "ci.yml",
)


def _load(path: Path) -> dict:
    text = re.sub(r'(?m)^on:', '"on":', path.read_text(encoding="utf-8"), count=1)
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return loaded


def _publish() -> dict:
    return _load(ROOT / ".github" / "workflows" / "publish.yml")


def _stage_run(workflow: dict, name: str) -> str:
    job = workflow["jobs"][name]
    uses = [str(step.get("uses", "")) for step in job["steps"]]
    assert not any(item.startswith("actions/checkout@") for item in uses), name
    check = next(step for step in job["steps"] if step.get("name") == "Check the hashes and stage the distributions")
    upload = next(i for i, step in enumerate(job["steps"]) if "gh-action-pypi-publish@" in str(step.get("uses", "")))
    assert job["steps"].index(check) < upload
    assert check["env"]["BUILD_SUMS"] == "${{ needs.build.outputs.sums }}"
    script = check["run"]
    assert "scripts/" not in script
    assert "verify_dist.py" not in script
    assert "python3 - <<'PY'" in script
    return script


def _python_body(script: str) -> str:
    marker = "python3 - <<'PY'\n"
    start = script.index(marker) + len(marker)
    end = script.index("\nPY", start)
    return script[start:end]


def _run(body: str, workspace: Path, sums: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["BUILD_SUMS"] = sums
    return subprocess.run(
        [sys.executable, "-c", body],
        cwd=workspace,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _incoming(workspace: Path, files: dict[str, bytes], *, sums: dict[str, str] | None = None) -> dict[str, str]:
    incoming = workspace / "incoming"
    incoming.mkdir()
    mapping = {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()}
    if sums is not None:
        mapping = sums
    for name, payload in files.items():
        (incoming / name).write_bytes(payload)
    lines = [f"{digest}  ./{name}" for name, digest in mapping.items()]
    (incoming / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()}


def test_b2_publish_jobs_stage_from_the_build_output_without_a_checkout(tmp_path: Path) -> None:
    workflow = _publish()
    first = _stage_run(workflow, "publish-testpypi")
    second = _stage_run(workflow, "publish-pypi")
    assert first == second
    body = _python_body(first)
    files = {"pkg-0.1.0-py3-none-any.whl": b"wheel-bytes", "pkg-0.1.0.tar.gz": b"sdist-bytes"}

    good = tmp_path / "good"
    good.mkdir()
    mapping = _incoming(good, files)
    passed = _run(body, good, __import__("json").dumps(mapping))
    assert passed.returncode == 0, passed.stderr
    assert sorted(path.name for path in (good / "dist").iterdir()) == sorted(files)

    def fail(name: str, workspace: Path, sums: str) -> None:
        result = _run(body, workspace, sums)
        assert result.returncode != 0, name

    tampered = tmp_path / "tampered"
    tampered.mkdir()
    original = _incoming(tampered, files)
    wheel = tampered / "incoming" / "pkg-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel-BYTES")
    fail("tampered byte", tampered, __import__("json").dumps(original))

    extra = tmp_path / "extra"
    extra.mkdir()
    listed = _incoming(extra, files)
    (extra / "incoming" / "other-0.1.0-py3-none-any.whl").write_bytes(b"extra")
    fail("extra file", extra, __import__("json").dumps(listed))

    missing = tmp_path / "missing"
    missing.mkdir()
    both = _incoming(missing, files)
    (missing / "incoming" / "pkg-0.1.0.tar.gz").unlink()
    fail("missing file", missing, __import__("json").dumps(both))

    rewritten = tmp_path / "rewritten"
    rewritten.mkdir()
    kept = _incoming(rewritten, files)
    (rewritten / "incoming" / "SHA256SUMS").write_text(
        "\n".join(f"{'a' * 64}  ./{name}" for name in kept) + "\n",
        encoding="utf-8",
    )
    fail("rewritten sums", rewritten, __import__("json").dumps(kept))

    empty = tmp_path / "empty"
    empty.mkdir()
    _incoming(empty, files)
    fail("empty map", empty, "{}")


def test_i6_each_hop_is_wired_in_the_parsed_steps() -> None:
    workflow = _publish()
    jobs = workflow["jobs"]
    for name in ("publish-testpypi", "publish-pypi"):
        steps = jobs[name]["steps"]
        check = next(step for step in steps if step.get("name") == "Check the hashes and stage the distributions")
        upload = next(i for i, step in enumerate(steps) if "gh-action-pypi-publish@" in str(step.get("uses", "")))
        assert steps.index(check) < upload
        assert "needs.build.outputs.sums" in check["env"]["BUILD_SUMS"]
        assert "SHA256SUMS does not match the build output" in check["run"]
    smoke = next(step["run"] for step in jobs["smoke-local"]["steps"] if "verify_dist.py" in step.get("run", ""))
    assert "--expect-json" in smoke
    assert "needs.build.outputs.sums" in jobs["smoke-local"]["steps"][-1]["env"]["BUILD_SUMS"]
    build = next(step["run"] for step in jobs["build"]["steps"] if step.get("name") == "Build with the hash-pinned tools")
    assert '"${buildpy}" -m build' in build
    assert "python -m build" not in build
    assert "--require-hashes -r scripts/release/requirements-build.txt" in build
    assert "requirements.txt" not in build
    test_step = next(step["run"] for step in jobs["build"]["steps"] if step.get("name") == "Test in a separate environment")
    assert "test-venv" in test_step
    assert "build-venv" not in test_step


def test_b2_repo_steps_have_a_checkout_and_python_steps_have_setup_python() -> None:
    for path in WORKFLOWS:
        workflow = _load(path)
        for name, job in workflow["jobs"].items():
            steps = job.get("steps") or []
            uses = [str(step.get("uses", "")) for step in steps]
            runs = "\n".join(step.get("run", "") for step in steps if isinstance(step.get("run"), str))
            has_checkout = any(item.startswith("actions/checkout@") for item in uses)
            has_python = any(item.startswith("actions/setup-python@") for item in uses)
            if "scripts/" in runs:
                assert has_checkout, f"{path.name}:{name} runs repo code without a checkout"
            for match in re.finditer(r"(?<![\w])python(?!3)", runs):
                before = runs[max(0, match.start() - 24) : match.start()]
                if before.rstrip().endswith("--entrypoint"):
                    continue
                assert has_python, f"{path.name}:{name} calls python without setup-python"
                break
    workflow = _publish()
    for name in ("publish-testpypi", "publish-pypi"):
        uses = [str(step.get("uses", "")) for step in workflow["jobs"][name]["steps"]]
        assert not any(item.startswith("actions/checkout@") for item in uses)
