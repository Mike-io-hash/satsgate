"""`satsgate init`. The console script parses arguments and calls `run_init`."""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import sys
from dataclasses import dataclass, field
from importlib.resources import files as resource_files
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

from satsgate_proxy import __version__ as proxy_version
from satsgate_proxy.app import build_app
from satsgate_proxy.config import ConfigError, Settings, key_fingerprint, load_settings
from satsgate_sdk import SatsgateClient, SatsgateError, create_account
from starlette.testclient import TestClient

from satsgate import files

DEFAULT_API = "https://api.satsgate.org"
_LOCAL_HTTP = frozenset({"localhost", "127.0.0.1", "::1"})
_HTTP_LOGGERS = ("httpx", "httpcore", "httpx2", "httpcore2")
START_COMMAND = "uvx --env-file .env satsgate-proxy --config satsgate-proxy.yaml"
FROM_SOURCE = (
    "From a checkout, until the packages are published: "
    "pip install -e sdk/python -e proxy && set -a && . ./.env && set +a && "
    "python -m satsgate_proxy --config satsgate-proxy.yaml"
)
_SNIPPETS = {
    "fastapi": (("satsgate_fastapi_verify.py", "fastapi_verify.py"),),
    "express": (("satsgate_express_verify.js", "express_verify.js"),),
    "nginx": (
        ("satsgate_nginx_verify.js", "nginx_verify.js"),
        ("satsgate_nginx.conf", "nginx.conf"),
    ),
}


@dataclass
class InitOptions:
    """Flags for one `satsgate init` run. `want_usdc` None means the human is asked."""

    api_url: str | None = None
    lightning_address: str | None = None
    want_usdc: bool | None = None
    json_mode: bool = False
    docker: bool = False
    framework: str | None = None
    path: str = "/paid/**"
    upstream: str = "http://127.0.0.1:3000"
    public_url: str = "http://127.0.0.1:8080"
    yaml_out: str | None = None
    new_account: bool = False
    replace_lightning_address: bool = False
    cwd: Path | None = None


@dataclass
class _Run:
    api_url: str = ""
    exit_code: int = 0
    status: str = "ready"
    warnings: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    account: dict[str, Any] | None = None
    payee: str | None = None
    error: dict[str, Any] | None = None
    restricted: bool = True
    client_id: int | None = None
    account_key: str = ""
    api_key: str = ""
    origin_secret: str = ""
    reused_account: bool = False
    terms_url: str | None = None
    evm_verified: bool = False
    x402: bool = False
    connect_url: str = ""
    connect_file: str | None = None
    connect_expires: int | None = None
    route: dict[str, Any] | None = None
    test_402: dict[str, Any] | None = None
    start_command: str | None = None
    next_steps: list[str] = field(default_factory=list)


class _Console:
    def __init__(self, stdin: TextIO, stdout: TextIO, stderr: TextIO, *, human: bool) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.human = human

    def say(self, text: str) -> None:
        stream = self.stdout if self.human else self.stderr
        stream.write(text.rstrip("\n") + "\n")

    def ask(self, prompt: str) -> str:
        self.stderr.write(prompt)
        self.stderr.flush()
        return self.stdin.readline()


def looks_like_lightning_address(addr: str) -> bool:
    """Same shape the core accepts in `_looks_like_lightning_address`."""
    if not addr or "@" not in addr or "://" in addr or "/" in addr:
        return False
    user, domain = addr.split("@", 1)
    return bool(user and domain and "." in domain)


def validate_api_url(url: str) -> str | None:
    parts = urlsplit(url.strip())
    host = parts.hostname
    if parts.username or parts.password or parts.query or parts.fragment:
        return "API URL must be https, or http on localhost"
    if parts.path not in {"", "/"}:
        return "API URL must be https, or http on localhost"
    if parts.scheme == "https" and host:
        return None
    if parts.scheme == "http" and host in _LOCAL_HTTP:
        return None
    return "API URL must be https, or http on localhost"


def key_preview(value: str) -> str:
    if value.startswith("sgr_"):
        prefix = "sgr_"
    elif value.startswith("sg_"):
        prefix = "sg_"
    else:
        prefix = ""
    return f"{prefix}…{value[-4:]}"


def _tty(stream: TextIO) -> bool:
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except Exception:
        return False


def _quiet_http() -> dict[str, int]:
    previous: dict[str, int] = {}
    for name in _HTTP_LOGGERS:
        logger = logging.getLogger(name)
        previous[name] = logger.level
        logger.setLevel(logging.WARNING)
    return previous


def _restore_http(previous: dict[str, int]) -> None:
    for name, level in previous.items():
        logging.getLogger(name).setLevel(level)


def _split_transport(transport: Any) -> tuple[Any, Any]:
    if transport is None:
        return None, None
    sdk = getattr(transport, "sdk", None)
    proxy = getattr(transport, "proxy", None)
    if sdk is None and proxy is None:
        return transport, None
    return sdk, proxy


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _fail(run: _Run, *, code: str, step: str, message: str, exit_code: int, status: str | None = None) -> None:
    run.exit_code = exit_code
    run.status = status or ("failed" if exit_code == 1 else "usage" if exit_code == 2 else code)
    run.error = {"code": code, "step": step, "message": message}
    if exit_code == 4:
        run.status = "rate_limited"


def _payload(run: _Run) -> dict[str, Any]:
    error = dict(run.error) if run.error else None
    body: dict[str, Any] = {
        "schema_version": 1,
        "ok": run.exit_code == 0,
        "status": run.status,
        "exit_code": run.exit_code,
        "api_url": run.api_url,
        "account": run.account,
        "payee_lightning_address": run.payee,
        "usdc": {
            "enabled": run.x402,
            "connect_link_file": run.connect_file,
            "expires_at": run.connect_expires,
        },
        "files": run.files,
        "route": run.route,
        "test_402": run.test_402,
        "start_command": run.start_command,
        "next_steps": list(run.next_steps),
        "warnings": list(run.warnings),
        "error": error,
    }
    if error and "retry_after_seconds" in error:
        body["retry_after_seconds"] = error["retry_after_seconds"]
    return body


def _emit(console: _Console, run: _Run) -> None:
    if console.human:
        if run.exit_code == 0:
            console.say("Ready.")
        elif run.error:
            console.say(run.error["message"])
        return
    console.stdout.write(json.dumps(_payload(run)) + "\n")


def _mark(run: _Run, root: Path, path: Path, state: str, *, restricted: bool) -> None:
    run.files[_rel(root, path)] = state
    if not restricted:
        if "permissions_not_restricted" not in run.warnings:
            run.warnings.append("permissions_not_restricted")
        run.restricted = False


def _account_path(root: Path) -> Path:
    return root / ".satsgate" / "account.env"


def _yaml_path(root: Path, options: InitOptions) -> Path:
    name = options.yaml_out or "satsgate-proxy.yaml"
    path = Path(name)
    if not path.is_absolute():
        path = root / path
    return path


def render_yaml(
    *,
    api_url: str,
    upstream: str,
    route_path: str,
    x402: bool = False,
    public_base: str = "",
) -> str:
    """Template for the proxy config. Secrets stay in .env."""
    server = "server:\n  host: 127.0.0.1\n  port: 8080\n"
    if x402:
        server += f"  public_base: {json.dumps(public_base)}\n"
    extra = "    x402: true\n    x402_mode: test\n" if x402 else ""
    return (
        "# satsgate-proxy config written by `satsgate init`.\n"
        "# Lightning has no test network. A paid request moves real sats\n"
        "# to this merchant's Lightning Address.\n"
        f"# Start: {START_COMMAND}\n"
        "# Secrets live in .env (SATSGATE_API_KEY and SATSGATE_ORIGIN_SECRET).\n"
        "core:\n"
        f"  base_url: {json.dumps(api_url)}\n"
        "  api_key_env: SATSGATE_API_KEY\n"
        "upstream:\n"
        f"  base_url: {json.dumps(upstream)}\n"
        "origin:\n"
        "  secret_env: SATSGATE_ORIGIN_SECRET\n"
        f"{server}"
        "routes:\n"
        "  - name: first\n"
        "    methods: [GET]\n"
        f"    path: {json.dumps(route_path)}\n"
        "    price_sats: 10\n"
        "    access: per_request\n"
        "    scope: route\n"
        f"{extra}"
    )


def render_compose() -> str:
    """Local image build. Secrets stay in env_file, not in this file."""
    return (
        "# satsgate-proxy for this project. Secrets are read from .env.\n"
        "services:\n"
        "  satsgate-proxy:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: proxy/Dockerfile\n"
        f"    image: satsgate-proxy:{proxy_version}\n"
        "    env_file: .env\n"
        "    read_only: true\n"
        '    user: "65532:65532"\n'
        "    ports:\n"
        '      - "127.0.0.1:8080:8080"\n'
        "    volumes:\n"
        "      - ./satsgate-proxy.yaml:/etc/satsgate/proxy.yaml:ro\n"
    )


def probe_path(route_path: str) -> str:
    if route_path.endswith("/**"):
        prefix = route_path[:-3]
        if not prefix.endswith("/"):
            prefix += "/"
        return prefix + "check"
    return route_path


def _read_account_key(path: Path) -> str | None:
    if not path.exists():
        return None
    values = files.parse_env(files.read_text(path))
    value = values.get(files.ACCOUNT_KEY, "").strip()
    return value or None


def _write_account(run: _Run, root: Path, key: str) -> None:
    directory = root / ".satsgate"
    files.refuse_symlink(directory)
    dir_ok = files.ensure_dir(directory, 0o700)
    ignore = directory / ".gitignore"
    ignore_text = "*\n"
    if ignore.exists() and not ignore.is_symlink() and ignore.read_text(encoding="utf-8") == ignore_text:
        _mark(run, root, ignore, "unchanged", restricted=dir_ok)
    else:
        ignore_ok = files.atomic_write(ignore, ignore_text, mode=0o600)
        _mark(run, root, ignore, "created", restricted=dir_ok and ignore_ok)
    path = directory / "account.env"
    text = f"{files.ACCOUNT_KEY}={key}\n"
    ok = files.atomic_write(path, text, mode=0o600)
    _mark(run, root, path, "created", restricted=dir_ok and ok)
    if not dir_ok:
        run.restricted = False
        if "permissions_not_restricted" not in run.warnings:
            run.warnings.append("permissions_not_restricted")


def _client(api_url: str, key: str, transport: Any) -> SatsgateClient:
    return SatsgateClient(base_url=api_url, api_key=key, transport=transport)


def _error_code(exc: SatsgateError) -> str:
    data = exc.data or {}
    code = data.get("error")
    if isinstance(code, str) and code:
        return code
    return "request_failed"


def _validate_saved_key(run: _Run, api_url: str, key: str, transport: Any) -> dict | None:
    client = _client(api_url, key, transport)
    try:
        return client.get_client()
    except SatsgateError as exc:
        if exc.status_code in {401, 403}:
            _fail(
                run,
                code="account_key_rejected",
                step="read_account",
                message="The saved account key was rejected. Refusing to open another account.",
                exit_code=3,
                status="account_key_rejected",
            )
            return None
        _fail(run, code=_error_code(exc), step="read_account", message=str(exc), exit_code=1, status="failed")
        return None
    finally:
        client.close()


def _open_account(run: _Run, api_url: str, transport: Any, root: Path) -> str | None:
    try:
        opened = create_account(base_url=api_url, transport=transport)
    except SatsgateError as exc:
        if exc.status_code == 429:
            data = exc.data or {}
            retry = data.get("retry_after_seconds")
            _fail(
                run,
                code=_error_code(exc),
                step="create_account",
                message="Signup is rate-limited. Wait and run satsgate init again. It was not retried.",
                exit_code=4,
            )
            if run.error is not None:
                run.error["retry_after_seconds"] = retry
            return None
        _fail(run, code=_error_code(exc), step="create_account", message=str(exc), exit_code=1, status="failed")
        return None
    except Exception as exc:
        _fail(run, code="network", step="create_account", message=exc.__class__.__name__, exit_code=1, status="failed")
        return None
    key = str(opened["api_key"])
    run.client_id = int(opened["client_id"])
    terms = opened.get("terms_url")
    if isinstance(terms, str) and terms:
        run.terms_url = terms
    _write_account(run, root, key)
    return key


def _confirm_new_account(console: _Console, options: InitOptions, exists: bool) -> bool:
    if not exists:
        return True
    if not options.new_account and console.human:
        answer = console.ask("An account key is already saved. Open a new account? [y/N] ")
        return answer.strip().lower() in {"y", "yes"}
    return bool(options.new_account)


def _set_payee(run: _Run, client: SatsgateClient, address: str, *, replace: bool) -> bool:
    try:
        body = client.get_client()
    except SatsgateError as exc:
        _fail(run, code=_error_code(exc), step="set_payee", message=str(exc), exit_code=1, status="failed")
        return False
    current = (body.get("payee_lightning_address") or "").strip()
    run.client_id = int(body.get("client_id") or run.client_id or 0)
    if current == address:
        run.payee = current
        return True
    if current and not replace:
        _fail(
            run,
            code="payee_differs",
            step="set_payee",
            message="The account already has a different Lightning Address.",
            exit_code=3,
            status="payee_differs",
        )
        run.payee = current
        return False
    try:
        saved = client.set_payee(address)
    except SatsgateError as exc:
        _fail(run, code=_error_code(exc), step="set_payee", message=str(exc), exit_code=1, status="failed")
        run.payee = current or None
        return False
    run.payee = str(saved.get("payee_lightning_address") or address)
    return True


def _resolve_api_key(
    run: _Run,
    client: SatsgateClient,
    current: str | None,
    transport: Any,
    *,
    allow_replace: bool,
) -> str | None:
    if current:
        probe = _client(client.base_url, current, transport)
        try:
            probe.balance()
            return current
        except SatsgateError as exc:
            if exc.status_code not in {401, 403}:
                _fail(run, code=_error_code(exc), step="create_api_key", message=str(exc), exit_code=1, status="failed")
                return None
            if not allow_replace:
                _fail(
                    run,
                    code="env_conflict",
                    step="write_env",
                    message="SATSGATE_API_KEY in .env does not match a usable key.",
                    exit_code=3,
                    status="env_conflict",
                )
                return None
        finally:
            probe.close()
    try:
        created = client.create_api_key(label="satsgate-init proxy", resource_prefix="route:")
    except SatsgateError as exc:
        _fail(run, code=_error_code(exc), step="create_api_key", message=str(exc), exit_code=1, status="failed")
        return None
    key = created.get("api_key")
    if not isinstance(key, str) or not key.startswith("sgr_"):
        _fail(
            run,
            code="bad_api_key",
            step="create_api_key",
            message="The core did not return a restricted key.",
            exit_code=1,
            status="failed",
        )
        return None
    return key


def _prepare_env(
    run: _Run,
    root: Path,
    console: _Console,
    api_key: str,
    origin_secret: str,
) -> bool:
    path = root / ".env"
    files.refuse_symlink(path)
    updates = {files.API_KEY: api_key, files.ORIGIN_SECRET: origin_secret}
    existing = ""
    created = not path.exists()
    previous_mode = 0o600
    if path.exists():
        existing = files.read_text(path)
        previous_mode = files.mode_of(path)
        if previous_mode & 0o077:
            if "env_is_group_readable" not in run.warnings:
                run.warnings.append("env_is_group_readable")
            if console.human:
                answer = console.ask("Restrict .env to owner-only? [y/N] ")
                if answer.strip().lower() in {"y", "yes"}:
                    previous_mode = 0o600
    replace: set[str] = set()
    conflicts_first = files.merge_env(existing, updates, replace=set())[1]
    if conflicts_first:
        if not console.human:
            _fail(
                run,
                code="env_conflict",
                step="write_env",
                message="A SATSGATE_* value in .env differs. It was not changed.",
                exit_code=3,
                status="env_conflict",
            )
            return False
        for key in conflicts_first:
            answer = console.ask(f"Replace {key} in .env? [y/N] ")
            if answer.strip().lower() not in {"y", "yes"}:
                _fail(
                    run,
                    code="env_conflict",
                    step="write_env",
                    message=f"{key} in .env differs. It was not changed.",
                    exit_code=3,
                    status="env_conflict",
                )
                return False
            replace.add(key)
    merged, conflicts = files.merge_env(existing, updates, replace=replace)
    if conflicts:
        _fail(run, code="env_conflict", step="write_env", message="A SATSGATE_* value in .env differs.", exit_code=3, status="env_conflict")
        return False
    if merged == existing and not created:
        _mark(run, root, path, "unchanged", restricted=True)
        return True
    mode = 0o600 if created else previous_mode
    ok = files.atomic_write(path, merged, mode=mode)
    state = "created" if created else "updated"
    _mark(run, root, path, state, restricted=ok if created else True)
    if created and not ok:
        run.restricted = False
    return True


def _git_warning(run: _Run, root: Path, console: _Console) -> None:
    if not files.inside_work_tree(root) or files.env_is_ignored(root):
        return
    if "env_not_gitignored" not in run.warnings:
        run.warnings.append("env_not_gitignored")
    if not console.human:
        return
    answer = console.ask("Append .env to .gitignore? [y/N] ")
    if answer.strip().lower() not in {"y", "yes"}:
        return
    path = root / ".gitignore"
    files.refuse_symlink(path)
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = {line.strip() for line in current.splitlines()}
    if ".env" in lines:
        return
    text = current + ("" if current.endswith("\n") or not current else "\n") + ".env\n"
    files.atomic_write(path, text, mode=0o644)
    _mark(run, root, path, "updated" if current else "created", restricted=True)


def _place_file(
    run: _Run,
    root: Path,
    path: Path,
    console: _Console,
    text: str,
    *,
    step: str,
    mode: int = 0o644,
    allow_update_from: str | None = None,
) -> Path | None:
    files.refuse_symlink(path)
    if path.exists():
        current = files.read_text(path)
        if current == text:
            _mark(run, root, path, "unchanged", restricted=True)
            return path
        if allow_update_from is not None and current == allow_update_from:
            files.atomic_write(path, text, mode=mode)
            _mark(run, root, path, "updated", restricted=True)
            return path
        if not console.human:
            _fail(
                run,
                code="file_exists",
                step=step,
                message=f"{path.name} already exists and was not overwritten.",
                exit_code=3,
                status="file_exists",
            )
            return None
        answer = console.ask(f"{path.name} exists and will not be overwritten. New path, or empty to stop: ")
        chosen = answer.strip()
        if not chosen:
            _fail(
                run,
                code="file_exists",
                step=step,
                message=f"{path.name} already exists and was not overwritten.",
                exit_code=3,
                status="file_exists",
            )
            return None
        return _place_file(run, root, Path(chosen) if Path(chosen).is_absolute() else root / chosen, console, text, step=step, mode=mode)
    files.atomic_write(path, text, mode=mode)
    _mark(run, root, path, "created", restricted=True)
    return path


def _place_yaml(
    run: _Run,
    root: Path,
    options: InitOptions,
    console: _Console,
    text: str,
    *,
    plain: str,
) -> Path | None:
    path = _yaml_path(root, options)
    placed = _place_file(
        run,
        root,
        path,
        console,
        text,
        step="write_yaml",
        allow_update_from=plain if plain != text else None,
    )
    if placed is None and console.human and run.exit_code == 0:
        return None
    return placed


def _validate_yaml(path: Path, api_key: str, origin_secret: str) -> Settings:
    previous = {name: os.environ.get(name) for name in (files.API_KEY, files.ORIGIN_SECRET)}
    os.environ[files.API_KEY] = api_key
    os.environ[files.ORIGIN_SECRET] = origin_secret
    try:
        return load_settings(path)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _deliver_connect(run: _Run, root: Path, console: _Console, url: str, expires: int) -> None:
    """Human TTY prints the link once. Every other mode writes a 0600 file and does not print it."""
    run.connect_expires = int(expires)
    if console.human and _tty(console.stdout):
        console.say(url)
        answer = console.ask("Open the connect link in a browser? [y/N] ")
        if answer.strip().lower() in {"y", "yes"}:
            import webbrowser

            webbrowser.open(url)
        return
    path = root / ".satsgate" / "connect-link.txt"
    files.refuse_symlink(path)
    ok = files.atomic_write(path, url if url.endswith("\n") else url + "\n", mode=0o600)
    run.connect_file = _rel(root, path)
    _mark(run, root, path, "created", restricted=ok)


def _probe(
    run: _Run,
    settings: Settings,
    proxy_transport: Any,
    sdk_transport: Any,
    route_path: str,
) -> bool:
    """One unpaid 402 through the in-memory proxy. No verify, no settle, no payment."""
    app = build_app(settings, transport=proxy_transport)
    with TestClient(app) as http:
        response = http.get(probe_path(route_path))
    challenge = response.headers.get("www-authenticate", "")
    if response.status_code == 402 and challenge.startswith("L402 "):
        amount = response.json().get("amount_sats")
        if int(amount) != 10:
            _fail(run, code="test_402", step="test_402", message="The test challenge was not 10 sats.", exit_code=1, status="failed")
            return False
        rail_x402 = False
        if run.x402:
            encoded = response.headers.get("payment-required", "")
            try:
                document = json.loads(base64.b64decode(encoded))
                network = document["accepts"][0]["network"]
            except (ValueError, KeyError, IndexError, TypeError):
                network = ""
            if network != "eip155:84532":
                _fail(
                    run,
                    code="x402_network",
                    step="test_402",
                    message="The USDC test offer was not on Base Sepolia.",
                    exit_code=1,
                    status="failed",
                )
                return False
            rail_x402 = True
        run.test_402 = {"ok": True, "rail_lightning": True, "rail_x402": rail_x402, "debited": False}
        return True
    if response.status_code == 502:
        diagnostic = _client(settings.core_base_url, settings.api_key, sdk_transport)
        try:
            try:
                diagnostic.paywall_challenge(resource="route:first", amount_sats=10)
                code = "paywall_unavailable"
            except SatsgateError as exc:
                code = _error_code(exc)
        finally:
            diagnostic.close()
        run.test_402 = {"ok": False, "rail_lightning": False, "rail_x402": False, "debited": False}
        _fail(
            run,
            code=code,
            step="test_402",
            message="The test 402 failed. No payment was sent.",
            exit_code=1,
            status="failed",
        )
        return False
    _fail(
        run,
        code="test_402",
        step="test_402",
        message=f"The test request returned HTTP {response.status_code}.",
        exit_code=1,
        status="failed",
    )
    return False


def _copy_snippets(run: _Run, root: Path, console: _Console, framework: str) -> bool:
    pairs = _SNIPPETS.get(framework, ())
    planned: list[tuple[Path, str]] = []
    for dest_name, source_name in pairs:
        text = (resource_files("satsgate") / "snippets" / source_name).read_text(encoding="utf-8")
        planned.append((root / dest_name, text))
    for path, text in planned:
        if path.is_symlink():
            _fail(run, code="symlink_refused", step="snippet", message=f"{path.name} is a symlink.", exit_code=3, status="symlink_refused")
            return False
        if path.exists() and files.read_text(path) != text:
            _fail(
                run,
                code="file_exists",
                step="snippet",
                message=f"{path.name} already exists and was not overwritten.",
                exit_code=3,
                status="file_exists",
            )
            return False
    for path, text in planned:
        if _place_file(run, root, path, console, text, step="snippet") is None:
            return False
    return True


def _fill_next_steps(run: _Run, options: InitOptions) -> None:
    steps = [
        f"Start the proxy: {START_COMMAND}",
        FROM_SOURCE,
        "Add the origin check. Set SATSGATE_ORIGIN_SECRET on the origin from .env. "
        "A client that can reach the origin directly must fail closed.",
        "The packaged Caddy snippet is a note. It does not check the signature by itself.",
    ]
    if run.x402:
        steps.append(
            "Pay once on Base Sepolia from a buyer agent (for example satsgate-mcp-pay, "
            "with the key on the buyer's machine). Test mode is free."
        )
        steps.append(f"Buyers need a public URL. server.public_base is {options.public_url}.")
    else:
        steps.append("To try USDC, run satsgate init again with --want-usdc.")
    if run.connect_expires is not None:
        steps.append("Open the connect link, connect the wallet, then run satsgate init again.")
    if run.terms_url:
        steps.append(f"Terms: {run.terms_url}")
    if options.docker:
        steps.append("docker compose -f docker-compose.satsgate.yml up")
    run.next_steps = steps
    run.start_command = START_COMMAND


def _finish_success(run: _Run, console: _Console) -> None:
    if run.account_key:
        run.account = {
            "client_id": run.client_id,
            "key_preview": key_preview(run.account_key),
            "fingerprint": key_fingerprint(run.account_key),
            "reused": run.reused_account,
        }
    if console.human and run.account:
        console.say(f"Account {run.account['key_preview']} fp {run.account['fingerprint']}")
        if run.api_key:
            console.say(f"Proxy key {key_preview(run.api_key)} fp {key_fingerprint(run.api_key)}")
        if run.payee:
            console.say(f"Lightning Address {run.payee}")
        if run.terms_url:
            console.say(f"Terms {run.terms_url}")
        for step in run.next_steps:
            console.say(step)


def _execute(options: InitOptions, console: _Console, transport: Any, run: _Run) -> None:
    root = Path(options.cwd) if options.cwd is not None else Path.cwd()
    sdk_transport, proxy_transport = _split_transport(transport)
    raw_url = (options.api_url or os.environ.get("SATSGATE_API_URL") or DEFAULT_API).strip()
    problem = validate_api_url(raw_url)
    run.api_url = raw_url
    if problem:
        _fail(run, code="bad_api_url", step="validate", message=problem, exit_code=2, status="usage")
        return
    for path in (_account_path(root), root / ".env", _yaml_path(root, options)):
        if path.is_symlink():
            _fail(
                run,
                code="symlink_refused",
                step="validate",
                message=f"{path.name} is a symlink and was not written.",
                exit_code=3,
                status="symlink_refused",
            )
            return
    address = (options.lightning_address or "").strip()
    if console.human and not address:
        address = console.ask("Lightning Address: ").strip()
    if not address:
        _fail(
            run,
            code="missing_lightning_address",
            step="validate",
            message="Lightning Address is required. Pass --lightning-address.",
            exit_code=2,
            status="usage",
        )
        return
    if not looks_like_lightning_address(address):
        _fail(
            run,
            code="invalid_lightning_address",
            step="validate",
            message="Lightning Address is not a user@domain name.",
            exit_code=2,
            status="usage",
        )
        return
    run.payee = address
    want = options.want_usdc
    if console.human and want is None:
        answer = console.ask("Accept USDC test mode? [y/N] ")
        want = answer.strip().lower() in {"y", "yes"}
    elif want is None:
        want = False
    framework = options.framework
    if console.human and framework is None:
        framework = console.ask("Origin snippet [fastapi/express/nginx/none]: ").strip().lower() or "none"
    elif framework is None:
        framework = "none"
    if framework not in {"fastapi", "express", "nginx", "none"}:
        _fail(
            run,
            code="bad_framework",
            step="validate",
            message="--framework must be fastapi, express, nginx, or none.",
            exit_code=2,
            status="usage",
        )
        return
    options.framework = framework
    options.want_usdc = want

    account_file = _account_path(root)
    saved_key = _read_account_key(account_file) if account_file.exists() else None
    open_new = _confirm_new_account(console, options, saved_key is not None)
    if saved_key and not open_new:
        saved_key_use: str | None = saved_key
        run.reused_account = True
    else:
        saved_key_use = None

    if saved_key_use:
        body = _validate_saved_key(run, raw_url, saved_key_use, sdk_transport)
        if run.exit_code != 0:
            return
        run.account_key = saved_key_use
        run.client_id = int((body or {}).get("client_id") or 0)
        _mark(run, root, account_file, "unchanged", restricted=True)
        ignore = root / ".satsgate" / ".gitignore"
        if ignore.exists():
            _mark(run, root, ignore, "unchanged", restricted=True)
    else:
        created = _open_account(run, raw_url, sdk_transport, root)
        if created is None:
            return
        run.account_key = created
        run.reused_account = False

    replace_payee = bool(options.replace_lightning_address)
    client = _client(raw_url, run.account_key, sdk_transport)
    try:
        peeked = client.get_client()
        terms = peeked.get("terms_url")
        if isinstance(terms, str) and terms:
            run.terms_url = terms
        run.evm_verified = bool(peeked.get("payee_evm_verified"))
        run.x402 = run.evm_verified
        stored = (peeked.get("payee_lightning_address") or "").strip()
        if stored and stored != address and not replace_payee and console.human:
            answer = console.ask("Replace the saved Lightning Address? [y/N] ")
            replace_payee = answer.strip().lower() in {"y", "yes"}
        if not _set_payee(run, client, address, replace=replace_payee or not stored or stored == address):
            return
        env_path = root / ".env"
        current_env = files.parse_env(files.read_text(env_path)) if env_path.exists() and not env_path.is_symlink() else {}
        existing_api = current_env.get(files.API_KEY) or None
        api_key = _resolve_api_key(
            run,
            client,
            existing_api,
            sdk_transport,
            allow_replace=console.human,
        )
        if api_key is None:
            return
        run.api_key = api_key
        origin = current_env.get(files.ORIGIN_SECRET, "").strip()
        if not origin:
            origin = secrets.token_hex(32)
        run.origin_secret = origin
        if not _prepare_env(run, root, console, api_key, origin):
            return
        _git_warning(run, root, console)
        if options.want_usdc and not run.evm_verified:
            try:
                link = client.create_connect_link()
            except SatsgateError as exc:
                _fail(run, code=_error_code(exc), step="connect", message=str(exc), exit_code=1, status="failed")
                return
            _deliver_connect(run, root, console, str(link["connect_url"]), int(link["expires_at"]))
        plain = render_yaml(api_url=raw_url, upstream=options.upstream, route_path=options.path)
        yaml_text = render_yaml(
            api_url=raw_url,
            upstream=options.upstream,
            route_path=options.path,
            x402=run.x402,
            public_base=options.public_url,
        )
        yaml_path = _place_yaml(run, root, options, console, yaml_text, plain=plain)
        if yaml_path is None:
            return
        try:
            settings = _validate_yaml(yaml_path, api_key, origin)
        except ConfigError as exc:
            _fail(run, code="invalid_yaml", step="write_yaml", message=str(exc), exit_code=1, status="failed")
            return
        if not _probe(run, settings, proxy_transport, sdk_transport, options.path):
            return
        if not _copy_snippets(run, root, console, options.framework or "none"):
            return
        if options.docker:
            compose = _place_file(
                run,
                root,
                root / "docker-compose.satsgate.yml",
                console,
                render_compose(),
                step="write_compose",
            )
            if compose is None:
                return
        run.route = {
            "name": "first",
            "path": options.path,
            "price_sats": 10,
            "access": "per_request",
            "resource": "route:first",
            "x402": run.x402,
            "key_preview": key_preview(api_key),
            "fingerprint": key_fingerprint(api_key),
        }
        _fill_next_steps(run, options)
        _finish_success(run, console)
    finally:
        client.close()


def run_init(
    options: InitOptions,
    *,
    transport: Any = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run init. `transport` is injected into every HTTP client this function creates."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    human = _tty(stdin) and not options.json_mode
    console = _Console(stdin, stdout, stderr, human=human)
    run = _Run()
    previous = _quiet_http()
    try:
        _execute(options, console, transport, run)
    except files.FileRefusal as exc:
        _fail(run, code=exc.code, step="write", message=str(exc), exit_code=3, status=exc.code)
    except Exception as exc:
        if run.exit_code == 0:
            _fail(run, code="failed", step="init", message=exc.__class__.__name__, exit_code=1, status="failed")
    finally:
        _restore_http(previous)
    _emit(console, run)
    return run.exit_code
