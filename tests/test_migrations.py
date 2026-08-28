from __future__ import annotations

from pathlib import Path

import pytest

from ntshield.migrations import DatabaseMigrator, MigrationError


def write_migration(root: Path, name: str, sql: str) -> Path:
    directory = root / "sqlite"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(sql, encoding="utf-8")
    return path


def test_migrations_are_ordered_atomic_and_checksum_verified(tmp_path) -> None:
    root = tmp_path / "migrations"
    first = write_migration(
        root,
        "0001_core.sql",
        "CREATE TABLE demo(id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
    )
    write_migration(
        root,
        "0002_index.sql",
        "CREATE INDEX idx_demo_value ON demo(value);",
    )
    database = tmp_path / "control.db"
    migrator = DatabaseMigrator(f"sqlite:///{database}", root)
    applied = migrator.apply()
    assert [item.version for item in applied] == [1, 2]
    assert migrator.status().current_version == 2
    assert migrator.apply() == ()

    first.write_text(
        "CREATE TABLE demo(id INTEGER PRIMARY KEY, forged TEXT NOT NULL);",
        encoding="utf-8",
    )
    drifted = DatabaseMigrator(f"sqlite:///{database}", root)
    with pytest.raises(MigrationError, match="checksum drift"):
        drifted.status()
