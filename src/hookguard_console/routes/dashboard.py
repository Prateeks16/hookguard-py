"""The Overview page and the stats endpoint htmx polls."""

from __future__ import annotations

from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..deps import console_of, require_auth
from ..overview_chart import render_hourly_chart
from ..store import Event
from ..views import format_accept_rate, format_timestamp_ms, page_context, window_from_request

__all__ = ["handle_overview", "handle_stats_summary"]

RECENT_REJECTED_LIMIT = 10


@dataclass(frozen=True, slots=True)
class RejectedRow:
    """A rejected event ready for display. Formatting happens here rather than
    in the template, which has no filters registered and should not grow any
    for a single timestamp."""

    time: str
    provider: str
    path: str
    reason: str
    remote_ip: str


def _rows(events: list[Event]) -> list[RejectedRow]:
    return [
        RejectedRow(
            time=format_timestamp_ms(e.received_at),
            provider=e.provider,
            path=e.path,
            reason=e.reason,
            remote_ip=e.remote_ip,
        )
        for e in events
    ]


async def handle_overview(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)

    hours, window = window_from_request(request)
    now = console.now()
    has_any = console.store.has_any_event()

    extra: dict[str, object] = {"window": window, "has_any_event": has_any}

    # An instance that has never received anything gets the empty state rather
    # than a wall of zeros: zeros read as "everything failed", which is a very
    # different thing to be told while setting the product up.
    if has_any:
        summary = console.store.summary_window(int(now.timestamp()), hours)
        buckets = console.store.hourly_counts_window(int(now.timestamp()), hours)
        extra |= {
            "accepted": summary.accepted,
            "rejected": summary.rejected,
            "accept_rate_pct": format_accept_rate(summary),
            "p50_latency_ms": f"{summary.p50_latency_ms}ms",
            "chart_svg": render_hourly_chart(buckets),
            "recent_rejected": _rows(console.store.recent_rejected(RECENT_REJECTED_LIMIT)),
        }

    return console.render(
        "overview.html",
        page_context(
            request,
            store=console.store,
            version=console.version,
            now=now,
            nav_active="overview",
            **extra,
        ),
    )


async def handle_stats_summary(request: Request) -> Response:
    """The JSON htmx swaps into the stat cards every 30 seconds.

    Session-authed like any other dashboard route -- deliberately not the
    ingest route's Gateway-signature auth, since the caller here is a browser.
    """
    console = console_of(request)
    require_auth(request)

    hours, window = window_from_request(request)
    summary = console.store.summary_window(int(console.now().timestamp()), hours)
    return JSONResponse(
        {
            "accepted": summary.accepted,
            "rejected": summary.rejected,
            "accept_rate": summary.accept_rate,
            "p50_latency_ms": summary.p50_latency_ms,
            "window": window,
        }
    )
