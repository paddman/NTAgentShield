from __future__ import annotations

import hashlib
import importlib
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Protocol
from urllib.parse import unquote, urlparse

_MIGRATION_RE = re.compile(r"^(?P<version>[0-9]{4,})_(?P<name>[a-z0-9][a-z0-9_-]*)\.sql$")
_LOCK_ID = 7_392_941_177


class MigrationError(RuntimeError):
    """Raised when migration history or database state violates an invariant."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    path: Path
    sql: str
    checksum: str

    @property
    def identifier(self) -> str:
        return f"{self.version:04d}_{self.name}"


@dataclass(frozen=True, slots=True)
class MigrationStatus:
    current_version: int
    pending: tuple[Migration, ...]
    applied: tuple[tuple[int, str, str], ...]


class _Connection(Protocol):
    def execute(self, query: str, params: Any = None, **kwargs: Any) -> Any: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


def discover_migrations(root: str | Path, dialect: str) -> tuple[Migration, ...]:
    directory = Path(root) / dialect
    if not directory.is_dir():
        raise MigrationError(f"migration directory does not exist: {directory}")
    migrations: list[Migration] = []
    seen: set[int] = set()
    for path in sorted(directory.glob("*.sql")):
        match = _MIGRATION_RE.fullmatch(path.name)
        if match is None:
            raise MigrationError(f"invalid migration filename: {path.name}")
        version = int(match.group("version"))
        if version in seen:
            raise MigrationError(f"duplicate migration version: {version}")
        seen.add(version)
        sql = path.read_text(encoding="utf-8")
        if not sql.strip():
            raise MigrationError(f"migration is empty: {path.name}")
        migrations.append(
            Migration(
                version=version,
                name=match.group("name"),
                path=path,
                sql=sql,
                checksum=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            )
        )
    if not migrations:
        raise MigrationError(f"no migrations found in {directory}")
    return tuple(migrations)


class DatabaseMigrator:
    """Checksum-verified migration runner for PostgreSQL and SQLite.

    PostgreSQL migrations use a transaction-scoped advisory lock. SQLite uses
    BEGIN IMMEDIATE. Applied migration bytes are immutable.
    """

    def __init__(self, database_url: str, migrations_root: str | Path):
        self.database_url = database_url.strip()
        self.migrations_root = Path(migrations_root)
        self.dialect = _dialect(self.database_url)
        self.migrations = discover_migrations(self.migrations_root, self.dialect)

    def status(self) -> MigrationStatus:
        with self._connection() as connection:
            self._ensure_history(connection)
            connection.commit()
            applied = self._applied(connection)
            self._verify_history(applied)
            current = max(applied, default=0)
            pending = tuple(item for item in self.migrations if item.version not in applied)
            rows = tuple(
                (version, applied[version][0], applied[version][1]) for version in sorted(applied)
            )
            return MigrationStatus(current, pending, rows)

    def apply(self, *, target_version: int | None = None) -> tuple[Migration, ...]:
        maximum = self.migrations[-1].version
        target = maximum if target_version is None else target_version
        if target < 0 or target > maximum:
            raise MigrationError(f"target version must be between 0 and {maximum}")
        applied_now: list[Migration] = []
        with self._connection() as connection:
            try:
                self._begin_locked(connection)
                self._ensure_history(connection)
                applied = self._applied(connection)
                self._verify_history(applied)
                for migration in self.migrations:
                    if migration.version > target or migration.version in applied:
                        continue
                    self._execute_script(connection, migration.sql)
                    statement = (
                        """
                        INSERT INTO schema_migrations(version, name, checksum, applied_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        """
                        if self.dialect == "sqlite"
                        else """
                        INSERT INTO schema_migrations(version, name, checksum, applied_at)
                        VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                        """
                    )
                    connection.execute(
                        statement,
                        (migration.version, migration.name, migration.checksum),
                    )
                    applied_now.append(migration)
                connection.commit()
            except Exception as exc:
                connection.rollback()
                if isinstance(exc, MigrationError):
                    raise
                raise MigrationError(f"migration failed: {exc}") from exc
        return tuple(applied_now)

    def _verify_history(self, applied: dict[int, tuple[str, str]]) -> None:
        known = {item.version: item for item in self.migrations}
        for version, (name, checksum) in applied.items():
            migration = known.get(version)
            if migration is None:
                raise MigrationError(f"database contains unknown migration version {version}")
            if migration.name != name:
                raise MigrationError(
                    f"migration {version} name drift: database={name!r}, source={migration.name!r}"
                )
            if migration.checksum != checksum:
                raise MigrationError(f"migration {migration.identifier} checksum drift detected")

    def _ensure_history(self, connection: _Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TIMESTAMP NOT NULL
            )
            """
        )

    def _applied(self, connection: _Connection) -> dict[int, tuple[str, str]]:
        rows = connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
        return {int(row[0]): (str(row[1]), str(row[2])) for row in rows}

    def _begin_locked(self, connection: _Connection) -> None:
        if self.dialect == "sqlite":
            connection.execute("BEGIN IMMEDIATE")
            return
        connection.execute("BEGIN")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_ID,))

    def _execute_script(self, connection: _Connection, sql: str) -> None:
        if self.dialect == "sqlite":
            buffer = ""
            for line in sql.splitlines(keepends=True):
                buffer += line
                if sqlite3.complete_statement(buffer):
                    statement = buffer.strip()
                    buffer = ""
                    if statement:
                        connection.execute(statement)
            if buffer.strip():
                raise MigrationError("SQLite migration contains an incomplete statement")
        else:
            connection.execute(sql, prepare=False)

    @contextmanager
    def _connection(self) -> Iterator[_Connection]:
        connection = _connect(self.database_url, self.dialect)
        try:
            yield connection
        finally:
            connection.close()


def default_migrations_root() -> Path:
    repository = Path(__file__).resolve().parents[2] / "migrations"
    if repository.is_dir():
        return repository
    packaged = Path(__file__).resolve().parent / "migration_sql"
    return packaged if packaged.is_dir() else Path("./migrations")


def _dialect(database_url: str) -> str:
    parsed = urlparse(database_url)
    if parsed.scheme in {"postgres", "postgresql"}:
        return "postgres"
    if parsed.scheme == "sqlite":
        return "sqlite"
    raise MigrationError("database URL must start with postgresql:// or sqlite:///")


def _connect(database_url: str, dialect: str) -> _Connection:
    if dialect == "sqlite":
        parsed = urlparse(database_url)
        path = unquote(parsed.path)
        if parsed.netloc and parsed.netloc != "localhost":
            path = f"//{parsed.netloc}{path}"
        if not path:
            raise MigrationError("SQLite database URL requires a file path")
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection
    try:
        psycopg = importlib.import_module("psycopg")
    except ModuleNotFoundError as exc:
        raise MigrationError(
            "install PostgreSQL support with: pip install 'ntagentshield[postgres]'"
        ) from exc
    return psycopg.connect(database_url, autocommit=False)
