"""The Console's database handle.

Composed from one mixin per Go store file, so ``users.py`` here covers what
``users.go`` covered there and the two trees stay comparable during the port.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ._base import _StoreBase, apply_schema_if_needed, connect
from .auth_events import AuthEventsMixin
from .endpoints import EndpointsMixin
from .events import EventsMixin
from .sessions import SessionsMixin
from .settings import SettingsMixin
from .users import UsersMixin

__all__ = ["Store", "open_store"]


class Store(
    UsersMixin,
    SessionsMixin,
    EndpointsMixin,
    EventsMixin,
    SettingsMixin,
    AuthEventsMixin,
    _StoreBase,
):
    """Single-writer by design -- see ``_base`` for why."""

    @property
    def connection(self) -> sqlite3.Connection:
        """Escape hatch for tests. Production code goes through the methods."""
        return self._conn


def open_store(path: str | Path) -> Store:
    """Open (creating if absent) the database at ``path``.

    Applies the schema on first run. A database created by the Go console
    opens here untouched: the schema is identical and applied-ness is tracked
    the same way, by looking for the ``users`` table rather than by a
    migrations table only one implementation would write.
    """
    path = Path(path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(str(path))
    apply_schema_if_needed(conn)
    return Store(conn)
