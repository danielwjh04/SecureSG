"""Tests for the entrypoint app builder and uvicorn launch."""

import logging
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

import secureSG.main as main_mod
from secureSG.config.settings import Settings
from secureSG.exceptions import ModelLoadError, SecureSGError
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment
from secureSG.warden.embeddings import EmbeddingProvider, Vector


class _StubProvider(ModelProvider):
    async def assess(self, content: str, task: AssessmentTask) -> SemanticAssessment:
        return SemanticAssessment(task=task, p_unsafe=0.0)

    async def generate(self, prompt: str, *, grammar: str | None = None) -> str:
        return ""


class _StubEmbedder(EmbeddingProvider):
    async def embed(self, texts: list[str]) -> list[Vector]:
        return [[1.0, 0.0] for _ in texts]


def _raise_model_load(_settings: Settings) -> object:
    raise ModelLoadError("unavailable")


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        db_path=tmp_path / "audit.db",
        mcp_backend_url="http://mcp.local/rpc",
    )


def test_build_app_requires_backend_url(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, db_path=tmp_path / "audit.db")
    with pytest.raises(SecureSGError):
        main_mod.build_app(settings)


def test_build_app_falls_back_to_deterministic_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(main_mod, "load_guard_provider", _raise_model_load)
    monkeypatch.setattr(main_mod, "load_embedding_provider", _raise_model_load)
    with caplog.at_level(logging.WARNING):
        app = main_mod.build_app(_settings(tmp_path))
    assert app is not None
    messages = " ".join(record.getMessage() for record in caplog.records).lower()
    assert "deterministic-only" in messages
    assert "drift" in messages


def test_build_app_wires_models_when_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_mod, "load_guard_provider", lambda s: _StubProvider())
    monkeypatch.setattr(main_mod, "load_embedding_provider", lambda s: _StubEmbedder())
    assert main_mod.build_app(_settings(tmp_path)) is not None


def test_build_app_mounts_dashboard_when_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_mod, "load_guard_provider", _raise_model_load)
    monkeypatch.setattr(main_mod, "load_embedding_provider", _raise_model_load)
    app = main_mod.build_app(_settings(tmp_path))
    assert "/dashboard/summary" in app.openapi()["paths"]


def test_build_app_omits_dashboard_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_mod, "load_guard_provider", _raise_model_load)
    monkeypatch.setattr(main_mod, "load_embedding_provider", _raise_model_load)
    settings = Settings(
        _env_file=None,
        db_path=tmp_path / "audit.db",
        mcp_backend_url="http://mcp.local/rpc",
        dashboard_enabled=False,
    )
    app = main_mod.build_app(settings)
    assert "/dashboard/summary" not in app.openapi()["paths"]


def test_mount_spa_serves_index_when_dist_exists(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>spa root</title>")
    app = FastAPI()
    main_mod._mount_spa(app, dist)
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "spa root" in response.text


def test_mount_spa_skips_when_dist_absent(tmp_path: Path) -> None:
    app = FastAPI()
    main_mod._mount_spa(app, tmp_path / "absent")
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 404


def test_main_runs_uvicorn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(app: object, *, host: str, port: int) -> None:
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setattr(main_mod, "load_guard_provider", _raise_model_load)
    monkeypatch.setattr(main_mod, "load_embedding_provider", _raise_model_load)
    monkeypatch.setenv("SECURESG_MCP_BACKEND_URL", "http://mcp.local/rpc")
    monkeypatch.setenv("SECURESG_DB_PATH", str(tmp_path / "audit.db"))
    main_mod.main()
    settings = Settings()
    assert captured["host"] == settings.proxy_host
    assert captured["port"] == settings.proxy_port
