"""One-time downloader for the GuardFormer GGUF weights via huggingface-hub.

The HuggingFace coordinates and target directory are configuration (settings),
not literals. ``huggingface_hub`` is imported lazily so importing this module
(and unit-testing it with an injected downloader) needs neither the dependency
nor the network. Run it with ``python -m scripts.fetch_model``.
"""

from collections.abc import Callable
from pathlib import Path
from typing import cast

from secureSG.config.settings import Settings

Downloader = Callable[..., str]


def _default_downloader() -> Downloader:  # pragma: no cover
    # reason: imports the optional huggingface_hub dependency; tests inject a fake.
    from huggingface_hub import hf_hub_download

    return cast(Downloader, hf_hub_download)


def fetch_model(settings: Settings, *, downloader: Downloader | None = None) -> Path:
    """Download the guard GGUF into the configured weights dir and return its path.

    Time complexity: O(download size). Space complexity: O(download size).
    """
    download = downloader if downloader is not None else _default_downloader()
    location = download(
        repo_id=settings.model_repo_id,
        filename=settings.model_filename,
        local_dir=str(settings.model_dir),
    )
    return Path(location)


def main() -> None:  # pragma: no cover
    # reason: CLI entry point, exercised manually rather than in the unit suite.
    settings = Settings()
    path = fetch_model(settings)
    print(f"Downloaded guard weights to {path}")
    print(f"Set SECURESG_MODEL_PATH={path}")


if __name__ == "__main__":  # pragma: no cover
    main()
