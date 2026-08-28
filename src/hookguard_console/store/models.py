"""Row types for the Console's database.

These mirror the Go structs field-for-field. The schema is shared with the Go
implementation -- an existing console database must open and read correctly
here -- so the column names, the unix-millisecond timestamps and the
integer-as-boolean columns are all contract rather than preference.
"""

from __future__ import annotations

from dataclasses import dataclass

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
    "Summary",
    "User",
]


class NotFoundError(LookupError):
    """No row matched. The counterpart of Go's ``store.ErrNotFound``."""


#: Fallback when the settings table has no ``retention_days`` row yet.
DEFAULT_RETENTION_DAYS = 30


class AuthEventKind:
    """The kinds recorded in ``auth_events``.

    Stored as plain strings rather than a CHECK constraint, so a new kind
    needs no migration -- the schema is fixed upfront.
    """

    LOGIN_OK = "login_ok"
    LOGIN_FAIL = "login_fail"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "pw_change"
    SESSION_REVOKE = "session_revoke"
    USER_CREATE = "user_create"


@dataclass(slots=True)
class User:
    id: int = 0
    email: str = ""
    password_hash: str = ""  # PHC string: $argon2id$v=19$m=65536,t=3,p=2$...
    role: str = "member"  # 'admin' | 'member'
    active: bool = True
    created_at: int = 0  # unix ms


@dataclass(slots=True)
class Session:
    id: int = 0
    token_hash: bytes = b""  # sha256(cookie token); the raw token is never stored
    user_id: int = 0
    csrf_token: str = ""
    created_at: int = 0
    last_seen_at: int = 0
    expires_at: int = 0  # absolute cap
    ip: str = ""
    user_agent: str = ""


@dataclass(slots=True)
class Endpoint:
    """A Route, DB-backed."""

    id: int = 0
    path: str = ""
    provider: str = ""
    upstream_url: str = ""
    replay_window: str = ""  # Go duration string ("5m") or ""
    secret_env: str = ""  # NAME of the env var; never the secret
    webhook_id: str = ""  # PayPal only; config, not a secret
    active: bool = True
    created_at: int = 0
    updated_at: int = 0


@dataclass(slots=True)
class Event:
    """One gateway verdict, as decoded from the ingest contract."""

    #: ``events.id``, the SSE tail cursor. 0 on rows not yet read back.
    id: int = 0
    received_at: int = 0  # unix ms, the gateway's timestamp
    path: str = ""
    provider: str = ""
    verdict: str = ""  # 'accepted' | 'rejected'
    reason: str = ""  # '' when accepted
    upstream_status: int = 0
    latency_ms: int = 0
    body_bytes: int = 0
    body_sha256: str = ""
    remote_ip: str = ""


@dataclass(slots=True)
class AuthEvent:
    id: int = 0
    at: int = 0
    user_id: int | None = None  # nullable: a failed login has no user
    email: str = ""
    kind: str = ""
    ip: str = ""


@dataclass(slots=True)
class RollupDelta:
    """One ``(hour, provider, verdict)`` bucket's increment for a flushed batch.

    Callers sum same-bucket events before upserting, so a batch of three
    same-bucket events becomes one upsert of ``n=3`` rather than three racing
    each other.
    """

    hour: int
    provider: str
    verdict: str
    n: int = 0


@dataclass(slots=True)
class Summary:
    """Overview stat-card data for one window."""

    accepted: int = 0
    rejected: int = 0
    #: 0 when there was no traffic at all -- callers distinguish that from a
    #: genuine 0% rate using ``total``.
    accept_rate: float = 0.0
    p50_latency_ms: int = 0

    @property
    def total(self) -> int:
        return self.accepted + self.rejected


@dataclass(slots=True)
class HourlyCounts:
    """One hour bucket's accepted/rejected split, for the Overview chart."""

    hour: int  # unix hour bucket, matching event_rollups.hour
    accepted: int = 0
    rejected: int = 0


@dataclass(slots=True)
class ProviderStats:
    """One provider's split over a window.

    No latency: rollups do not record it, and a per-provider p50 would need
    its own scan over events per card.
    """

    accepted: int = 0
    rejected: int = 0

    @property
    def total(self) -> int:
        """0 means "no traffic yet" rather than a 0% accept rate."""
        return self.accepted + self.rejected

    @property
    def accept_rate(self) -> float:
        return self.accepted / self.total if self.total else 0.0


@dataclass(slots=True)
class EventFilter:
    """Narrows a log query. Unset fields mean no filter on that dimension.

    ``reason`` and ``path`` are substring matches rather than exact: reasons
    are free-ish text, and someone filtering the live log wants "contains",
    not a dropdown the UI would have to keep in lockstep with the emitter's
    taxonomy.
    """

    provider: str = ""
    verdict: str = ""
    reason: str = ""
    path: str = ""
    from_ms: int = 0  # unix ms, 0 = no lower bound
    to_ms: int = 0  # unix ms, 0 = no upper bound
