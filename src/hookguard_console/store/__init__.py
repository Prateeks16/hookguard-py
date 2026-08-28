"""The Console's SQLite database: schema, row types and queries.

The schema is shared verbatim with the Go implementation, so an existing
console database opens and reads here unchanged. Stdlib ``sqlite3`` only --
the Go build needed a driver dependency for this; Python does not.
"""

from ._base import like_escape
from .models import (
    DEFAULT_RETENTION_DAYS,
    AuthEvent,
    AuthEventKind,
    Endpoint,
    Event,
    EventFilter,
    HourlyCounts,
    NotFoundError,
    ProviderStats,
    RollupDelta,
    Session,
    Summary,
    User,
)
from .store import Store, open_store

__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "AuthEvent",
    "AuthEventKind",
    "Endpoint",
    "Event",
    "EventFilter",
    "HourlyCounts",
    "NotFoundError",
    "ProviderStats",
    "RollupDelta",
    "Session",
    "Store",
    "Summary",
    "User",
    "like_escape",
    "open_store",
]
