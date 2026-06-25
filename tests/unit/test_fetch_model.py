"""Tests for the guard-weights fetch script (no network, no huggingface_hub)."""

from pathlib import Path

from scripts.fetch_model import fetch_model
from secureSG.config.settings import Settings


def test_fetch_model_uses_configured_coordinates(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_downloader(*, repo_id: str, filename: str, local_dir: str) -> str:
        captured["repo_id"] = repo_id
        captured["filename"] = filename
        captured["local_dir"] = local_dir
        return str(Path(local_dir) / filename)

    settings = Settings(_env_file=None, model_dir=tmp_path)
    path = fetch_model(settings, downloader=fake_downloader)

    assert captured["repo_id"] == settings.model_repo_id
    assert captured["filename"] == settings.model_filename
    assert captured["local_dir"] == str(tmp_path)
    assert path == tmp_path / settings.model_filename
