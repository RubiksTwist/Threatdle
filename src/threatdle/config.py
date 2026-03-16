"""Application configuration and path helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tomllib
from typing import Any


@dataclass(frozen=True)
class AppPaths:
    root_dir: Path
    data_dir: Path
    snapshots_dir: Path
    processed_dir: Path
    overrides_dir: Path
    db_path: Path
    sources_path: Path


def get_paths(root_dir: Path | None = None) -> AppPaths:
    resolved_root = (
        root_dir
        or (Path(os.environ["THREATDLE_ROOT"]).resolve() if os.environ.get("THREATDLE_ROOT") else Path.cwd().resolve())
    )
    data_dir = resolved_root / "data"
    processed_dir = data_dir / "processed"
    snapshots_dir = data_dir / "snapshots"
    overrides_dir = data_dir / "overrides"
    db_path = processed_dir / "threatdle.db"
    return AppPaths(
        root_dir=resolved_root,
        data_dir=data_dir,
        snapshots_dir=snapshots_dir,
        processed_dir=processed_dir,
        overrides_dir=overrides_dir,
        db_path=db_path,
        sources_path=resolved_root / "sources.toml",
    )


def load_sources_config(root_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    paths = get_paths(root_dir=root_dir)
    with paths.sources_path.open("rb") as handle:
        payload = tomllib.load(handle)
    return {key: dict(value) for key, value in payload.items()}
