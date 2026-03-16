"""Common ingest helpers."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path


def now_utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_json_file(path: str | Path) -> object:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def compute_sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def compute_sha256_file(path: str | Path) -> str:
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_logical_hash(paths: list[Path], base_dir: Path) -> str:
    hasher = hashlib.sha256()
    for path in sorted(paths, key=lambda item: str(item.relative_to(base_dir)).replace("\\", "/")):
        relative = str(path.relative_to(base_dir)).replace("\\", "/")
        hasher.update(relative.encode("utf-8"))
        hasher.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        hasher.update(b"\0")
    return hasher.hexdigest()
