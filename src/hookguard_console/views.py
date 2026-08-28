"""Shared view helpers: page context, liveness, formatting.

Everything a dashboard page needs beyond its own data, in one place, so a new
page gets the chrome right by construction rather than by remembering to fill
in six fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from starlette.requests import Request

from .store import ProviderStats, Store, Summary

__all__ = [
    "LIVENESS_WINDOW",
    "WINDOWS",
    "client_ip",
    "dashboard_status",
    "format_accept_rate",
    "format_timestamp_ms",
    "gateway_connected",
    "human_ago",
    "normalize_email",
    "page_context",
    "window_from_request",
]

#: "Connected" means an ingest flush within this long. The gateway posts on
#: every verdict, so silence for a minute is a real signal, not jitter.
LIVENESS_WINDOW = timedelta(seconds=60)

#: The only two windows the dashboard offers, mapped to hour counts.
#:
#: This is a lookup, not an echo. Whatever arrives in ?window= selects one of
#: these keys or falls through to the default -- the request's own text never
#: reaches the template. Templates interpolate the result into an htmx URL,
#: and Jinja2's autoescaping is HTML-only where Go's was context-aware, so
#: this being a closed set is what keeps that safe. There is a test.
WINDOWS: dict[str, int] = {"24h": 24, "7d": 24 * 7}
DEFAULT_WINDOW = "24h"


def window_from_request(request: Request) -> tuple[int, str]:
    """Map ``?window=`` to ``(hours, label)``, defaulting to 24h."""
    requested = request.query_params.get("window", "")
    if requested in WINDOWS:
        return WINDOWS[requested], requested
    return WINDOWS[DEFAULT_WINDOW], DEFAULT_WINDOW


def gateway_connected(now: datetime, last_ingest_ms: int) -> bool:
    """Whether the gateway has been heard from recently. Never is always stale."""
    if not last_ingest_ms:
        return False
    return now - datetime.fromtimestamp(last_ingest_ms / 1000, tz=UTC) <= LIVENESS_WINDOW


def human_ago(delta: timedelta) -> str:
    """A coarse "3s ago" for the status strip. Not a precision timestamp."""
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


@dataclass(frozen=True, slots=True)
class DashboardStatus:
    connected: bool = False
    last_ingest_at: int = 0
    last_event_ago: str = ""


def dashboard_status(store: Store, now: datetime) -> DashboardStatus:
    """Read the gateway's liveness from the last recorded ingest.

    A missing setting is the expected state on a fresh install, not an error,
    so it reports "no signal" rather than raising.
    """
    from .batcher import LAST_INGEST_SETTING
    from .store import NotFoundError

    try:
        raw = store.get_setting(LAST_INGEST_SETTING)
        last_ingest_ms = int(raw)
    except (NotFoundError, ValueError):
        return DashboardStatus()

    return DashboardStatus(
        connected=gateway_connected(now, last_ingest_ms),
        last_ingest_at=last_ingest_ms,
        last_event_ago=human_ago(now - datetime.fromtimestamp(last_ingest_ms / 1000, tz=UTC)),
    )


def page_context(
    request: Request,
    *,
    store: Store,
    version: str,
    now: datetime,
    nav_active: str = "",
    **extra: Any,
) -> dict[str, Any]:
    """The chrome every dashboard page renders, plus whatever the page adds."""
    session = request.state.session
    status = dashboard_status(store, now)
    return {
        "user": request.state.user,
        "csrf_token": session.csrf_token if session else "",
        "version": version,
        "nav_active": nav_active,
        "connected": status.connected,
        "last_event_ago": status.last_event_ago,
        **extra,
    }


def format_accept_rate(summary: Summary | ProviderStats) -> str:
    """A percentage, or an em dash when nothing has arrived.

    "0%" would be a lie on a fresh instance: it has not rejected everything,
    it has seen nothing. The two states look identical in a number and very
    different to someone deciding whether their config is broken.
    """
    if summary.total == 0:
        return "—"
    return f"{summary.accept_rate * 100:.0f}%"


def format_timestamp_ms(unix_ms: int) -> str:
    """Render a stored timestamp for display. UTC, second precision."""
    if not unix_ms:
        return ""
    return datetime.fromtimestamp(unix_ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


def normalize_email(email: str) -> str:
    """Lowercase and trim.

    The column is COLLATE NOCASE, so this only affects what gets stored and
    compared before it reaches SQL -- it is not the uniqueness guarantee.
    """
    return email.strip().lower()


def client_ip(request: Request) -> str:
    """The peer address.

    Deliberately not X-Forwarded-For. The Console sits behind a proxy the
    operator controls, but trusting a client-supplied header for a rate-limit
    key would let anyone bypass the limiter by varying it.
    """
    return request.client.host if request.client else ""
