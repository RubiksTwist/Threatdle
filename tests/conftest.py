from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatdle.cli import run_init_db
from threatdle.db.connection import get_connection


@pytest.fixture
def fixture_dir() -> Path:
    return ROOT / "tests" / "fixtures"


@pytest.fixture
def app_root(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "sources.toml").write_text((ROOT / "sources.toml").read_text(encoding="utf-8"), encoding="utf-8")
    return root


@pytest.fixture
def db_connection(app_root: Path):
    db_path = run_init_db(app_root, None)
    connection = get_connection(db_path)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def curated_flow_payload(fixture_dir: Path) -> dict:
    return json.loads((fixture_dir / "attack_flow_bundle.json").read_text(encoding="utf-8"))
