"""Core 0.20.1 is the version, the changelog, and the health check."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from test_x402 import _load_app

_ROOT = Path(__file__).resolve().parents[1]


def test_t_5_5_1_version_matches_health_and_changelog(tmp_path) -> None:
    module = _load_app(tmp_path)
    assert module.config.APP_VERSION == "0.20.1"
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [0.20.1]" in changelog
    with TestClient(module.app) as http:
        health = http.get("/health")
        assert health.status_code == 200
        assert health.json()["version"] == "0.20.1"
    gate = (_ROOT / "gate" / "src" / "satsgate_gate" / "__init__.py").read_text(encoding="utf-8")
    assert '__version__ = "0.15.2"' in gate


def test_t_5_5_2_env_files_do_not_name_the_removed_vendor() -> None:
    for name in (".env.example", "docker-compose.yml"):
        text = (_ROOT / name).read_text(encoding="utf-8")
        assert "COINGECKO" not in text


def test_t_5_5_3_model_b_floor_math_is_unchanged() -> None:
    from app.pricing import floor_msat_at_rate, item_msat_from_usd, sats_ceil_from_usd

    den = 10**8
    assert item_msat_from_usd(10_000, 80_070 * den, den) == 12_489
    assert floor_msat_at_rate(80_070 * den, den) == 1_248
    assert sats_ceil_from_usd(1_000_000, 80_070 * den, den) == 1_249
