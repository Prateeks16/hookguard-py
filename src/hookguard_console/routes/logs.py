"""Live Logs: the filtered list and the server-sent-events tail.

The stream polls the store on a fixed interval rather than being pushed to.
With one writer and a cursor on an autoincrement id, polling is a few
milliseconds of work per client per tick, and it avoids a pub/sub layer that
would exist only to serve one page.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from ..deps import console_of, require_auth
from ..store import Event, EventFilter
from ..views import format_timestamp_ms, page_context

__all__ = ["handle_logs_list", "handle_logs_stream"]

LIST_LIMIT = 200

#: How often the stream re-queries. Fast enough to feel live, slow enough that
#: an idle dashboard is not a busy loop against the database.
POLL_INTERVAL = 1.0

#: Bounds one tick's query, so a backlog is delivered over several ticks
#: rather than as one enormous frame.
STREAM_BATCH_LIMIT = 100

#: Sent when there is nothing to report, so a proxy between the browser and
#: the Console does not time the connection out as idle.
KEEPALIVE = ": keepalive\n\n"


@dataclass(frozen=True, slots=True)
class LogRow:
    """One event, formatted for display and for the detail drawer's data
    attributes."""

    id: int
    time: str
    provider: str
    path: str
    verdict: str
    reason: str
    upstream_status: int
    latency_ms: int
    body_bytes: int
    body_sha256: str
    remote_ip: str


def _to_row(event: Event) -> LogRow:
    return LogRow(
        id=event.id,
        time=format_timestamp_ms(event.received_at),
        provider=event.provider,
        path=event.path,
        verdict=event.verdict,
        reason=event.reason,
        upstream_status=event.upstream_status,
        latency_ms=event.latency_ms,
        body_bytes=event.body_bytes,
        body_sha256=event.body_sha256,
        remote_ip=event.remote_ip,
    )


@dataclass(frozen=True, slots=True)
class FilterView:
    """The filter as the form needs to redisplay it."""

    provider: str = ""
    verdict: str = ""
    reason: str = ""
    path: str = ""
    from_value: str = ""
    to_value: str = ""


def _parse_local_datetime(value: str) -> int:
    """Parse an ``<input type="datetime-local">`` value to unix milliseconds.

    Returns 0 for anything unparseable, which the store reads as "no bound" --
    a mistyped date should widen the search, not error the page.
    """
    if not value:
        return 0
    try:
        return int(datetime.fromisoformat(value).replace(tzinfo=UTC).timestamp() * 1000)
    except ValueError:
        return 0


def _filter_from_request(request: Request) -> tuple[EventFilter, FilterView]:
    params = request.query_params
    from_raw = params.get("from", "")
    to_raw = params.get("to", "")

    event_filter = EventFilter(
        provider=params.get("provider", ""),
        verdict=params.get("verdict", ""),
        reason=params.get("reason", ""),
        path=params.get("path", ""),
        from_ms=_parse_local_datetime(from_raw),
        to_ms=_parse_local_datetime(to_raw),
    )
    view = FilterView(
        provider=event_filter.provider,
        verdict=event_filter.verdict,
        reason=event_filter.reason,
        path=event_filter.path,
        from_value=from_raw,
        to_value=to_raw,
    )
    return event_filter, view


async def handle_logs_list(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)

    event_filter, view = _filter_from_request(request)
    rows = [_to_row(e) for e in console.store.list_events(event_filter, LIST_LIMIT)]

    # The stream carries the same filters, so a reconnecting client tails
    # exactly the view it is looking at rather than everything.
    stream_url = "/dashboard/logs/stream"
    if request.url.query:
        stream_url = f"{stream_url}?{request.url.query}"

    return console.render(
        "logs.html",
        page_context(
            request,
            store=console.store,
            version=console.version,
            now=console.now(),
            nav_active="logs",
            rows=rows,
            filter=view,
            stream_url=stream_url,
        ),
    )


def _matches(event: Event, event_filter: EventFilter) -> bool:
    """Apply the page's filters to a streamed event.

    The tail query is cursored on id alone, so filtering happens here. Kept
    consistent with the store's SQL: exact match on provider and verdict,
    substring on reason and path.
    """
    if event_filter.provider and event.provider != event_filter.provider:
        return False
    if event_filter.verdict and event.verdict != event_filter.verdict:
        return False
    if event_filter.reason and event_filter.reason not in event.reason:
        return False
    if event_filter.path and event_filter.path not in event.path:
        return False
    if event_filter.from_ms and event.received_at < event_filter.from_ms:
        return False
    return not (event_filter.to_ms and event.received_at > event_filter.to_ms)


async def handle_logs_stream(request: Request) -> Response:
    console = console_of(request)
    require_auth(request)
    event_filter, _ = _filter_from_request(request)

    async def events() -> AsyncIterator[str]:
        # Start at the tail: a fresh connection streams what happens next, not
        # the whole history, which the page has already rendered.
        cursor = await asyncio.to_thread(console.store.latest_event_id)
        while True:
            if await request.is_disconnected():
                return

            batch = await asyncio.to_thread(console.store.events_since, cursor, STREAM_BATCH_LIMIT)
            if batch:
                cursor = batch[-1].id
                payload = [asdict(_to_row(e)) for e in batch if _matches(e, event_filter)]
                if payload:
                    yield f"data: {json.dumps(payload)}\n\n"
                else:
                    yield KEEPALIVE
            else:
                yield KEEPALIVE

            await asyncio.sleep(POLL_INTERVAL)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Tells nginx not to buffer the stream; without it the events
            # arrive in bursts when its buffer fills, which looks like the
            # stream is broken.
            "X-Accel-Buffering": "no",
        },
    )
