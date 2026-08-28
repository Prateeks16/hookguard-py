"""Connection handling and the single-writer discipline.

Go pinned ``SetMaxOpenConns(1)`` to sidestep ``SQLITE_BUSY`` rather than
juggling concurrent writers against SQLite. The Python equivalent is one
connection guarded by a lock: ``check_same_thread=False`` so a threadpool
worker can use it, and every statement serialized through
:attr:`_StoreBase._lock`. Getting this wrong surfaces as intermittent
"database is locked" under the ingest batcher's flushes, which is exactly the
kind of failure that only shows up under load.

The store is synchronous on purpose. The Console's async handlers run these
calls in a worker thread; making the store itself async would mean an async
SQLite driver and a second concurrency model on top of a database that is
single-writer regardless.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from importlib import resources
from typing import Any

__all__ = ["_StoreBase", "like_escape"]


def like_escape(value: str) -> str:
    r"""Escape SQL LIKE metacharacters in a user-supplied substring.

    A filter value containing ``%`` or ``_`` must match literally rather than
    as a wildcard. Queries using this pair it with ``ESCAPE '\'``.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class _StoreBase:
    """Owns the connection. The public surface lives in the mixins."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Any:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- statement helpers -------------------------------------------------
    #
    # Every one takes the lock, so callers never have to remember to. The
    # lock is not reentrant, which is deliberate: a helper that called another
    # helper would deadlock rather than quietly running outside the
    # serialization these are here to provide.

    def _execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run a write. Returns the number of rows affected."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.rowcount

    def _insert(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run an INSERT. Returns the new rowid."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def _query_one(self, sql: str, params: Sequence[Any] = ()) -> tuple[Any, ...] | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _query_all(self, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _scalar(self, sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
        row = self._query_one(sql, params)
        if row is None or row[0] is None:
            return default
        return row[0]

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """One transaction, for a batched write.

        The ingest batcher's whole reason for existing is to turn N
        per-request writes into one write per tick, so the batch inserts have
        to actually share a transaction.
        """
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        with self._transaction() as conn:
            conn.executemany(sql, rows)


def connect(path: str) -> sqlite3.Connection:
    """Open (creating if absent) the database, with the Go DSN's pragmas.

    ``journal_mode=WAL`` lets the dashboard read while the batcher writes;
    ``busy_timeout`` gives a blocked statement time to retry rather than
    failing instantly; ``foreign_keys`` is off by default in SQLite and the
    schema relies on ``ON DELETE CASCADE`` for sessions.
    """
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def apply_schema_if_needed(conn: sqlite3.Connection) -> bool:
    """Apply the schema on first run. Returns whether it was applied.

    The schema is fixed upfront, so there is only ever this one migration.
    Applied-ness is tracked by looking for the ``users`` table in
    ``sqlite_master`` rather than by a migrations table -- same as Go, and it
    means a database created by either implementation is recognized by the
    other.
    """
    row = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'"
    ).fetchone()
    if row[0]:
        return False
    sql = (
        resources.files("hookguard_console.store.migrations")
        .joinpath("0001_init.sql")
        .read_text(encoding="utf-8")
    )
    conn.executescript(sql)
    conn.commit()
    return True
