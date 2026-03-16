from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from threatdle.services.live_runtime_build import (
    build_live_runtime_from_sources,
    default_live_snapshot_id,
    default_live_start_day,
)


def test_default_live_start_day_uses_timezone():
    now = datetime(2026, 3, 16, 3, 30, tzinfo=UTC)
    assert default_live_start_day("America/New_York", now=now) == "2026-03-15"


def test_default_live_snapshot_id_uses_day_and_commit():
    now = datetime(2026, 3, 16, 15, 0, tzinfo=UTC)
    assert default_live_snapshot_id("America/New_York", now=now, commit_ref="ABCDEF123456") == "2026-03-16-live-abcdef1"
    assert default_live_snapshot_id("America/New_York", now=now, commit_ref=None) == "2026-03-16-live-local"


def test_build_live_runtime_from_sources_runs_pipeline(monkeypatch, db_connection, app_root: Path):
    calls: list[tuple[str, object]] = []

    def _record(name: str, return_value):
        def _inner(*args, **kwargs):
            calls.append((name, kwargs if kwargs else args[1:]))
            return return_value

        return _inner

    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.fetch_sources",
        _record("fetch_sources", {"status": "ok"}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.ingest_attack_stix",
        _record("ingest_attack_stix", {"rows": 10}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.ingest_overrides",
        _record("ingest_overrides", {"rows": 1}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.ingest_misp_actors",
        _record("ingest_misp_actors", {"rows": 2}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.ingest_attack_flow",
        _record("ingest_attack_flow", {"rows": 3}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.ingest_emulation_plans",
        _record("ingest_emulation_plans", {"rows": 4}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.ingest_incident_overrides",
        _record("ingest_incident_overrides", {"rows": 5}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.build_puzzle_tables",
        _record("build_puzzle_tables", {"rows": 6}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.generate_puzzle_range",
        _record("generate_puzzle_range", {"generated_days": []}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.export_live_runtime",
        _record("export_live_runtime", {"bundle_path": "build/runtime/game-data.json"}),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.mark_snapshot_ready",
        _record("mark_snapshot_ready", None),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.mark_snapshot_failed",
        _record("mark_snapshot_failed", None),
    )

    result = build_live_runtime_from_sources(
        db_connection,
        "snap-build",
        root_dir=app_root,
        out_dir=app_root / "build" / "runtime",
        timezone_name="America/New_York",
        start_day="2026-03-16",
        days=30,
        theme_mode="prefer",
        chain_mode="linked",
    )

    assert result["snapshot_id"] == "snap-build"
    assert result["days"] == 30
    assert result["start_day"] == "2026-03-16"
    assert [name for name, _ in calls] == [
        "fetch_sources",
        "ingest_attack_stix",
        "ingest_overrides",
        "ingest_misp_actors",
        "ingest_overrides",
        "ingest_attack_flow",
        "ingest_emulation_plans",
        "ingest_incident_overrides",
        "build_puzzle_tables",
        "mark_snapshot_ready",
        "generate_puzzle_range",
        "export_live_runtime",
    ]


def test_build_live_runtime_from_sources_marks_failed_on_error(monkeypatch, db_connection, app_root: Path):
    calls: list[str] = []

    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.fetch_sources",
        lambda *args, **kwargs: calls.append("fetch_sources") or {"status": "ok"},
    )

    def _boom(*args, **kwargs):
        calls.append("ingest_attack_stix")
        raise RuntimeError("boom")

    monkeypatch.setattr("threatdle.services.live_runtime_build.ingest_attack_stix", _boom)
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.mark_snapshot_failed",
        lambda *args, **kwargs: calls.append("mark_snapshot_failed"),
    )
    monkeypatch.setattr(
        "threatdle.services.live_runtime_build.mark_snapshot_ready",
        lambda *args, **kwargs: calls.append("mark_snapshot_ready"),
    )

    with pytest.raises(RuntimeError, match="boom"):
        build_live_runtime_from_sources(
            db_connection,
            "snap-fail",
            root_dir=app_root,
            out_dir=app_root / "build" / "runtime",
        )

    assert calls == ["fetch_sources", "ingest_attack_stix", "mark_snapshot_failed"]
