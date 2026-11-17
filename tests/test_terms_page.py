"""Public terms page: markdown build, freshness, and a live Caddy (T-B.1).

T-B.1.6 starts the production Caddyfile. A Python static server is not a
substitute, and the test is not skippable. It uses the caddy:2 image when
Docker is available, otherwise a local caddy binary serving the same file.
"""

from __future__ import annotations

import http.client
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_terms.py"
SOURCE = ROOT / "docs" / "hosted-gate-terms.md"
CADDYFILE = ROOT / "Caddyfile"
DIST = ROOT / "web" / "terms" / "dist"

MODEL_B_PHRASES = (
    "not money",
    "not redeemable",
    "credit to the prepaid balance",
    "500 free",
    "does not expire",
    "00:00:00 utc",
    "does not take custody",
    "cuba",
    "iran",
    "north korea",
    "24 hours",
    "origin failed after a receipt",
)
BANNED = ("draft", "lawyer has reviewed", "pending legal review", "set at deploy", "satsgate_terms_version")
VENDOR_CONTENT = (
    "The vendor is solely responsible for the content, services, and conduct "
    "of any site or route they connect to Satsgate. Satsgate does not review, "
    "host, or deliver that content. After payment, the buyer redeems a receipt "
    "at the vendor's own origin."
)
NO_DUTY = (
    "Satsgate has no duty to monitor vendor content or activity. "
    "It may disable a site or account used for illegal or sanctioned activity."
)
TERMS_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
)
GITHUB = "https://github.com/Mike-io-hash/satsgate"
_VALID_FIXTURE = "# Terms fixture\n\nEffective date: 2026-11-13.\n\nA plain paragraph.\n"


def _run_build(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], check=False, capture_output=True, text=True)


def _build_to(dest: Path, source: Path | None = None) -> subprocess.CompletedProcess[str]:
    args = ["--dest", str(dest)]
    if source is not None:
        args.extend(["--source", str(source)])
    return _run_build(*args)


def _assert_page(html: str) -> None:
    lowered = html.lower()
    assert "2026-11-13" in html
    assert '<html lang="en">' in html
    assert "<title>Satsgate terms of use</title>" in html
    assert "<script" not in lowered
    for phrase in MODEL_B_PHRASES:
        assert phrase in lowered, phrase
    for banned in BANNED:
        assert banned not in lowered, banned


def test_t_b_1_1_build_contains_date_and_model_b_phrases(tmp_path: Path) -> None:
    dest = tmp_path / "dist"
    built = _build_to(dest)
    assert built.returncode == 0, built.stderr
    current = (dest / "index.html").read_text(encoding="utf-8")
    dated = (dest / "2026-11-13" / "index.html").read_text(encoding="utf-8")
    _assert_page(current)
    _assert_page(dated)
    assert '<link rel="canonical" href="https://satsgate.org/terms">' in current
    assert '<link rel="canonical" href="https://satsgate.org/terms/2026-11-13">' in dated


def test_t_b_1_2_vendor_sentences_in_markdown_and_html(tmp_path: Path) -> None:
    markdown = SOURCE.read_text(encoding="utf-8")
    assert VENDOR_CONTENT in markdown
    assert NO_DUTY in markdown
    dest = tmp_path / "dist"
    built = _build_to(dest)
    assert built.returncode == 0, built.stderr
    for path in (dest / "index.html", dest / "2026-11-13" / "index.html"):
        html = path.read_text(encoding="utf-8")
        assert VENDOR_CONTENT in html
        assert NO_DUTY in html


def test_t_b_1_3_check_fails_when_dist_is_stale() -> None:
    """Run the --check command. A no-op flag that always exits 0 goes red."""
    built = _run_build()
    assert built.returncode == 0, built.stderr
    fresh = _run_build("--check")
    assert fresh.returncode == 0, fresh.stderr
    index = DIST / "index.html"
    original = index.read_text(encoding="utf-8")
    try:
        index.write_text(original + "\n<!-- stale -->\n", encoding="utf-8")
        stale = _run_build("--check")
        assert stale.returncode != 0
        assert "stale" in index.read_text(encoding="utf-8")
    finally:
        restored = _run_build()
        assert restored.returncode == 0, restored.stderr
    again = _run_build("--check")
    assert again.returncode == 0, again.stderr


@pytest.mark.parametrize(
    "bad",
    [
        "![logo](logo.png)\n",
        "<p>raw html</p>\n",
        "<img src=\"x\">\n",
        "[secret](https://evil.example/terms)\n",
        "| col |\n| --- |\n| cell |\n",
    ],
)
def test_t_b_1_4_unexpected_markdown_fails_the_build(tmp_path: Path, bad: str) -> None:
    source = tmp_path / "terms.md"
    dest = tmp_path / "dist"
    source.write_text(_VALID_FIXTURE + bad, encoding="utf-8")
    failed = _build_to(dest, source)
    assert failed.returncode != 0
    assert not (dest / "index.html").exists()
    assert "evil.example" not in failed.stdout
    clean = tmp_path / "clean.md"
    clean_dest = tmp_path / "clean-dist"
    clean.write_text(_VALID_FIXTURE, encoding="utf-8")
    ok = _build_to(clean_dest, clean)
    assert ok.returncode == 0, ok.stderr
    assert (clean_dest / "index.html").is_file()


def test_t_b_1_5_dated_snapshot_is_not_overwritten(tmp_path: Path) -> None:
    source = tmp_path / "terms.md"
    dest = tmp_path / "dist"
    first = "# Terms fixture\n\nEffective date: 2026-11-13.\n\nFirst wording of the terms.\n"
    source.write_text(first, encoding="utf-8")
    created = _build_to(dest, source)
    assert created.returncode == 0, created.stderr
    dated = dest / "2026-11-13" / "index.html"
    frozen = dated.read_text(encoding="utf-8")
    assert "First wording of the terms." in frozen

    source.write_text(first.replace("First wording", "Second wording"), encoding="utf-8")
    refused = _build_to(dest, source)
    assert refused.returncode != 0
    assert "frozen" in refused.stderr
    assert dated.read_text(encoding="utf-8") == frozen

    clean = tmp_path / "clean"
    source.write_text(first, encoding="utf-8")
    first_write = _build_to(clean, source)
    assert first_write.returncode == 0, first_write.stderr
    assert (clean / "2026-11-13" / "index.html").is_file()

    later = "# Terms fixture\n\nEffective date: 2026-12-01.\n\nA later version of the terms.\n"
    source.write_text(later, encoding="utf-8")
    advanced = _build_to(dest, source)
    assert advanced.returncode == 0, advanced.stderr
    assert dated.read_text(encoding="utf-8") == frozen
    assert "A later version of the terms." in (dest / "2026-12-01" / "index.html").read_text(encoding="utf-8")
    assert "A later version of the terms." in (dest / "index.html").read_text(encoding="utf-8")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _caddy_binary() -> str | None:
    found = shutil.which("caddy")
    if found:
        return found
    candidate = Path.home() / ".local" / "bin" / "caddy"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def _docker_ready() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    probe = subprocess.run([docker, "info"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return probe.returncode == 0


def _wrapper(port: int, import_path: str) -> str:
    # Bare hostnames in the production file listen on the HTTPS port even
    # with auto_https off. The harness points that port at the ephemeral one.
    return (
        "{\n"
        "\tauto_https off\n"
        f"\thttp_port {port}\n"
        f"\thttps_port {port}\n"
        "\tdefault_bind 127.0.0.1\n"
        "\tadmin off\n"
        "}\n\n"
        f"import {import_path}\n"
    )


def _get(port: int, path: str) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers={"Host": "satsgate.org", "Accept-Encoding": "identity"})
        response = conn.getresponse()
        body = response.read()
        headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, headers, body
    finally:
        conn.close()


class _Caddy:
    def __init__(self, port: int, terms: Path, connect: Path) -> None:
        self.port = port
        self.terms = terms
        self.connect = connect
        self.proc: subprocess.Popen[str] | None = None
        self.log_path: Path | None = None
        self.container: str | None = None
        self.mounts: list[Path] = []
        self.workdir: Path | None = None

    def start(self) -> None:
        self.workdir = self.terms.parent / "caddy-work"
        self.workdir.mkdir()
        self.log_path = self.workdir / "caddy.log"
        if _docker_ready():
            self._start_docker()
        else:
            self._start_binary()
        self._wait_until_ready()

    def _start_docker(self) -> None:
        assert self.workdir is not None
        wrapper = self.workdir / "Caddyfile"
        wrapper.write_text(_wrapper(self.port, "/etc/caddy/Caddyfile.prod"), encoding="utf-8")
        self.container = f"satsgate-terms-{self.port}"
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--name",
            self.container,
            "-v",
            f"{CADDYFILE}:/etc/caddy/Caddyfile.prod:ro",
            "-v",
            f"{wrapper}:/etc/caddy/Caddyfile:ro",
            "-v",
            f"{self.terms}:/srv/terms:ro",
            "-v",
            f"{self.connect}:/srv/connect:ro",
            "-e",
            "SATSGATE_HOSTNAME=api.satsgate.org",
            "-e",
            "SATSGATE_SITE_HOSTNAME=satsgate.org",
            "-e",
            "SATSGATE_REOWN_PROJECT_ID=test-reown-project",
            "caddy:2",
            "caddy",
            "run",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ]
        log = self.log_path.open("w", encoding="utf-8") if self.log_path else subprocess.DEVNULL
        self.proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)

    def _bind(self, name: str, src: Path) -> None:
        dst = Path("/srv") / name
        mkdir = subprocess.run(["sudo", "-n", "mkdir", "-p", str(dst)], check=False, capture_output=True, text=True)
        if mkdir.returncode != 0:
            pytest.fail(f"T-B.1.6 is mandatory and not skippable: cannot prepare {dst}: {mkdir.stderr.strip()}")
        subprocess.run(
            ["sudo", "-n", "umount", str(dst)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mounted = subprocess.run(
            ["sudo", "-n", "mount", "--bind", str(src), str(dst)],
            check=False,
            capture_output=True,
            text=True,
        )
        if mounted.returncode != 0:
            pytest.fail(f"T-B.1.6 is mandatory and not skippable: bind mount failed: {mounted.stderr.strip()}")
        self.mounts.append(dst)

    def _start_binary(self) -> None:
        binary = _caddy_binary()
        if binary is None:
            pytest.fail("T-B.1.6 is mandatory and not skippable: need the caddy:2 image or a caddy binary")
        assert self.workdir is not None and self.log_path is not None
        self._bind("terms", self.terms)
        self._bind("connect", self.connect)
        wrapper = self.workdir / "Caddyfile"
        wrapper.write_text(_wrapper(self.port, str(CADDYFILE)), encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "SATSGATE_HOSTNAME": "api.satsgate.org",
            "SATSGATE_SITE_HOSTNAME": "satsgate.org",
            "SATSGATE_REOWN_PROJECT_ID": "test-reown-project",
        }
        log = self.log_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [binary, "run", "--config", str(wrapper), "--adapter", "caddyfile"],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

    def _wait_until_ready(self) -> None:
        deadline = time.time() + (90 if self.container else 15)
        last_error = ""
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                pytest.fail("Caddy exited before serving /terms\n" + self._log_tail())
            try:
                status, _, _ = _get(self.port, "/terms")
            except OSError as exc:
                last_error = str(exc)
                time.sleep(0.2)
                continue
            if status == 200:
                return
            last_error = f"status {status}"
            time.sleep(0.2)
        pytest.fail(f"Caddy did not serve /terms ({last_error})\n" + self._log_tail())

    def _log_tail(self) -> str:
        if self.log_path is None or not self.log_path.is_file():
            return ""
        text = self.log_path.read_text(encoding="utf-8", errors="replace")
        return text[-4000:]

    def stop(self) -> None:
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        for dst in reversed(self.mounts):
            subprocess.run(["sudo", "-n", "umount", str(dst)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.mounts.clear()


def _assert_security_headers(headers: dict[str, str], *, cache: str) -> None:
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "no-referrer"
    assert headers.get("x-content-type-options") == "nosniff"
    assert "camera=()" in headers.get("permissions-policy", "")
    assert "max-age=31536000" in headers.get("strict-transport-security", "")
    assert headers.get("content-security-policy") == TERMS_CSP
    assert "unsafe-inline" not in headers.get("content-security-policy", "")
    assert headers.get("cache-control") == cache
    assert "set-cookie" not in headers
    assert headers.get("content-type", "").startswith("text/html")
    assert "charset=utf-8" in headers.get("content-type", "").lower()


def test_t_b_1_6_live_caddy_serves_terms(tmp_path: Path) -> None:
    """Live Caddy against the production Caddyfile. Not skippable."""
    caddyfile = CADDYFILE.read_text(encoding="utf-8")
    terms_at = caddyfile.find("@terms path /terms /terms/ /terms/*")
    catch_all = caddyfile.find("redir https://github.com/Mike-io-hash/satsgate 301")
    assert terms_at != -1
    assert catch_all != -1
    assert terms_at < catch_all
    assert "handle /connect" in caddyfile
    assert "handle_path /demo/*" in caddyfile
    assert "path /terms*" not in caddyfile
    assert "root * /srv/terms" in caddyfile
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "./web/terms/dist:/srv/terms:ro" in compose
    assert "SATSGATE_TERMS_URL:-https://satsgate.org" not in compose
    assert "web/terms/dist/" in (ROOT / ".gitignore").read_text(encoding="utf-8")

    dest = tmp_path / "dist"
    built = _build_to(dest)
    assert built.returncode == 0, built.stderr
    connect = tmp_path / "connect"
    connect.mkdir()
    (connect / "index.html").write_text("connect-stub", encoding="utf-8")

    port = _free_port()
    server = _Caddy(port, dest, connect)
    try:
        server.start()
        current_status, current_headers, current_body = _get(port, "/terms")
        slash_status, _, slash_body = _get(port, "/terms/")
        assert current_status == 200
        assert slash_status == 200
        assert current_body == slash_body
        current_text = current_body.decode("utf-8")
        _assert_page(current_text)
        _assert_security_headers(current_headers, cache="no-store")
        assert '<link rel="canonical" href="https://satsgate.org/terms">' in current_text

        dated_status, dated_headers, dated_body = _get(port, "/terms/2026-11-13")
        dated_slash_status, _, dated_slash_body = _get(port, "/terms/2026-11-13/")
        assert dated_status == 200
        assert dated_slash_status == 200
        assert dated_body == dated_slash_body
        dated_text = dated_body.decode("utf-8")
        _assert_page(dated_text)
        _assert_security_headers(dated_headers, cache="public, max-age=31536000")
        assert '<link rel="canonical" href="https://satsgate.org/terms/2026-11-13">' in dated_text
        assert "https://satsgate.org/terms" in dated_text

        # T-C.9.1: a dated 404 must not keep the year-long cache.
        future_status, future_headers, _future_body = _get(port, "/terms/2099-01-01")
        extra_status, extra_headers, _extra_body = _get(port, "/terms/2026-11-13/x")
        assert future_status == 404
        assert extra_status == 404
        assert "max-age=31536000" not in future_headers.get("cache-control", "")
        assert "max-age=31536000" not in extra_headers.get("cache-control", "")
        assert future_headers.get("cache-control") == "no-store"
        assert extra_headers.get("cache-control") == "no-store"

        missing_status, missing_headers, missing_body = _get(port, "/terms/does-not-exist")
        assert missing_status == 404
        assert missing_headers.get("location") is None
        missing_text = missing_body.decode("utf-8", errors="replace")
        assert "Satsgate terms of use" not in missing_text
        assert "not money" not in missing_text.lower()
        assert GITHUB not in missing_text
        assert missing_body != current_body

        for path in ("/some-other-path", "/termsfoo"):
            status, headers, body = _get(port, path)
            assert status == 301, path
            assert headers.get("location") == GITHUB
            assert body != current_body

        connect_status, _, connect_body = _get(port, "/connect")
        assert connect_status == 200
        assert connect_body == b"connect-stub"
        assert b"Satsgate terms of use" not in connect_body
    finally:
        server.stop()


def test_t_b_1_7_html_has_no_script_or_third_party_urls(tmp_path: Path) -> None:
    dest = tmp_path / "dist"
    built = _build_to(dest)
    assert built.returncode == 0, built.stderr
    files = [dest / "index.html", dest / "terms.css", dest / "2026-11-13" / "index.html", dest / "2026-11-13" / "terms.css"]
    for path in files:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        assert "<script" not in lowered
        assert "http://" not in lowered
        assert "url(" not in lowered
        for url in re.findall(r"https://[^\s\"'<>]+", text):
            host = urlparse(url).hostname or ""
            assert host == "satsgate.org" or host.endswith(".satsgate.org"), url
