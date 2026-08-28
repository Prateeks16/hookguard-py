"""Verdict events, rollups and the dashboard's aggregate queries.

Ported from web/internal/store/events.go.

The shape of this file follows one decision: the dashboard reads from
``event_rollups``, not from ``events``. Summaries and charts are then
O(hours) rather than O(events), which is what lets the Overview stay fast on
an instance that has been running for months. Latency is the exception --
rollups do not carry it -- so p50 comes from a bounded sample of recent rows
and is documented as an approximation.
"""

from __future__ import annotations

from collections.abc import Sequence

from ._base import _StoreBase, like_escape
from .models import (
    Event,
    EventFilter,
    HourlyCounts,
    NotFoundError,
    ProviderStats,
    RollupDelta,
    Summary,
)

__all__ = ["LATENCY_SAMPLE_LIMIT", "EventsMixin"]

_COLUMNS = (
    "id, received_at, path, provider, verdict, reason, upstream_status,"
    " latency_ms, body_bytes, body_sha256, remote_ip"
)

#: Bounds the p50 query so it stays cheap regardless of traffic volume. The
#: median of the most recent N events approximates the window's true median;
#: callers and templates should treat it as such.
LATENCY_SAMPLE_LIMIT = 1000


def _row_to_event(row: tuple) -> Event:
    return Event(
        id=row[0],
        received_at=row[1],
        path=row[2],
        provider=row[3],
        verdict=row[4],
        reason=row[5],
        upstream_status=row[6],
        latency_ms=row[7],
        body_bytes=row[8],
        body_sha256=row[9],
        remote_ip=row[10],
    )


class EventsMixin(_StoreBase):
    # -- writes ------------------------------------------------------------

    def insert_events(self, events: Sequence[Event]) -> None:
        """Insert a flushed tick's worth of events in one transaction.

        The batcher exists to turn N per-request writes into one write per
        tick against a single-writer database, so these have to share a
        transaction or the batching buys nothing.
        """
        if not events:
            return
        self._executemany(
            "INSERT INTO events"
            " (received_at, path, provider, verdict, reason, upstream_status,"
            "  latency_ms, body_bytes, body_sha256, remote_ip)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    e.received_at,
                    e.path,
                    e.provider,
                    e.verdict,
                    e.reason,
                    e.upstream_status,
                    e.latency_ms,
                    e.body_bytes,
                    e.body_sha256,
                    e.remote_ip,
                )
                for e in events
            ],
        )

    def upsert_rollups(self, deltas: Sequence[RollupDelta]) -> None:
        """Add each delta onto its ``(hour, provider, verdict)`` bucket."""
        if not deltas:
            return
        self._executemany(
            "INSERT INTO event_rollups (hour, provider, verdict, n) VALUES (?, ?, ?, ?)"
            " ON CONFLICT (hour, provider, verdict) DO UPDATE SET n = n + excluded.n",
            [(d.hour, d.provider, d.verdict, d.n) for d in deltas],
        )

    def delete_events_older_than(self, cutoff_ms: int) -> int:
        """Prune old events, returning the count deleted.

        ``event_rollups`` is deliberately untouched: it is the aggregate the
        Overview and charts read from, and it is kept far longer than the
        raw events are.
        """
        return self._execute("DELETE FROM events WHERE received_at < ?", (cutoff_ms,))

    # -- single-row reads --------------------------------------------------

    def count_events(self) -> int:
        return int(self._scalar("SELECT COUNT(*) FROM events", default=0))

    def has_any_event(self) -> bool:
        """Whether the table has ever held a row.

        Drives the Overview empty state, deliberately independent of any time
        window: an install whose only events are older than the window should
        show stale data, not the first-run empty state.
        """
        return bool(self._scalar("SELECT EXISTS(SELECT 1 FROM events LIMIT 1)", default=0))

    def latest_event(self) -> Event:
        row = self._query_one(f"SELECT {_COLUMNS} FROM events ORDER BY id DESC LIMIT 1")
        if row is None:
            raise NotFoundError("no events")
        return _row_to_event(row)

    def latest_event_id(self) -> int:
        """The current max id, 0 when empty.

        The SSE handler uses this to start a fresh connection at the tail
        rather than replaying the whole history.
        """
        return int(self._scalar("SELECT MAX(id) FROM events", default=0))

    def rollup_count(self, hour: int, provider: str, verdict: str) -> int:
        return int(
            self._scalar(
                "SELECT n FROM event_rollups WHERE hour = ? AND provider = ? AND verdict = ?",
                (hour, provider, verdict),
                default=0,
            )
        )

    # -- list reads --------------------------------------------------------

    def list_events(self, event_filter: EventFilter, limit: int) -> list[Event]:
        """The Live Logs query: up to ``limit`` matching events, newest first."""
        sql = f"SELECT {_COLUMNS} FROM events WHERE 1=1"
        args: list[object] = []

        if event_filter.provider:
            sql += " AND provider = ?"
            args.append(event_filter.provider)
        if event_filter.verdict:
            sql += " AND verdict = ?"
            args.append(event_filter.verdict)
        if event_filter.reason:
            sql += r" AND reason LIKE ? ESCAPE '\'"
            args.append(f"%{like_escape(event_filter.reason)}%")
        if event_filter.path:
            sql += r" AND path LIKE ? ESCAPE '\'"
            args.append(f"%{like_escape(event_filter.path)}%")
        if event_filter.from_ms > 0:
            sql += " AND received_at >= ?"
            args.append(event_filter.from_ms)
        if event_filter.to_ms > 0:
            sql += " AND received_at <= ?"
            args.append(event_filter.to_ms)

        # Ordered by id, not received_at: the gateway supplies the timestamp,
        # so two events can share one and paging would be ambiguous.
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [_row_to_event(r) for r in self._query_all(sql, args)]

    def events_since(self, since_id: int, limit: int) -> list[Event]:
        """The SSE tail query: events newer than a cursor, oldest first.

        Cursored on the autoincrement id rather than a timestamp, which
        sidesteps clock skew and duplicate timestamps between polls.
        """
        rows = self._query_all(
            f"SELECT {_COLUMNS} FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (since_id, limit),
        )
        return [_row_to_event(r) for r in rows]

    def recent_rejected(self, limit: int) -> list[Event]:
        """The Overview's recent-rejections table. Reasons are first-class
        here, so the whole row comes back rather than a projection."""
        rows = self._query_all(
            f"SELECT {_COLUMNS} FROM events WHERE verdict = 'rejected'"
            " ORDER BY received_at DESC LIMIT ?",
            (limit,),
        )
        return [_row_to_event(r) for r in rows]

    # -- aggregates --------------------------------------------------------

    def summary_window(self, now_unix: int, hours: int) -> Summary:
        """Stat-card data for the last ``hours`` buckets, ending at ``now``.

        ``now`` is passed in rather than read from the clock so the dashboard's
        numbers are testable.
        """
        now_hour = now_unix // 3600
        start_hour = now_hour - hours + 1

        summary = Summary()
        for verdict, total in self._query_all(
            "SELECT verdict, SUM(n) FROM event_rollups WHERE hour >= ? AND hour <= ?"
            " GROUP BY verdict",
            (start_hour, now_hour),
        ):
            if verdict == "accepted":
                summary.accepted = total
            elif verdict == "rejected":
                summary.rejected = total

        if summary.total:
            summary.accept_rate = summary.accepted / summary.total
        summary.p50_latency_ms = self._p50_latency_since(start_hour * 3600 * 1000)
        return summary

    def _p50_latency_since(self, since_ms: int) -> int:
        """Median latency over a bounded sample of recent events.

        An even-sized sample takes the lower of the two middle values rather
        than averaging them: latency_ms is an integer, both choices are
        defensible, and picking one deterministically keeps the figure stable.
        """
        rows = self._query_all(
            "SELECT latency_ms FROM events WHERE received_at >= ?"
            " ORDER BY received_at DESC LIMIT ?",
            (since_ms, LATENCY_SAMPLE_LIMIT),
        )
        if not rows:
            return 0
        latencies = sorted(r[0] for r in rows)
        mid = len(latencies) // 2
        if len(latencies) % 2 == 1:
            return latencies[mid]
        return latencies[mid - 1]

    def hourly_counts_window(self, now_unix: int, hours: int) -> list[HourlyCounts]:
        """One bucket per hour, ascending, with gaps zero-filled.

        The chart needs a dense series: an hour with no traffic is a zero, not
        a missing point, and leaving it out would make the x-axis lie.
        """
        now_hour = now_unix // 3600
        start_hour = now_hour - hours + 1

        by_hour: dict[int, HourlyCounts] = {}
        for hour, verdict, total in self._query_all(
            "SELECT hour, verdict, SUM(n) FROM event_rollups WHERE hour >= ? AND hour <= ?"
            " GROUP BY hour, verdict",
            (start_hour, now_hour),
        ):
            bucket = by_hour.setdefault(hour, HourlyCounts(hour=hour))
            if verdict == "accepted":
                bucket.accepted = total
            elif verdict == "rejected":
                bucket.rejected = total

        return [
            by_hour.get(start_hour + i, HourlyCounts(hour=start_hour + i)) for i in range(hours)
        ]

    def provider_stats_window(self, now_unix: int, hours: int) -> dict[str, ProviderStats]:
        """Per-provider splits over the window.

        Providers with no rows in the window are absent from the map rather
        than present with zeros: the caller knows the fixed provider list, and
        "never used" is a legitimate state the card renders differently from
        "used, all rejected".
        """
        now_hour = now_unix // 3600
        start_hour = now_hour - hours + 1

        out: dict[str, ProviderStats] = {}
        for provider, verdict, total in self._query_all(
            "SELECT provider, verdict, SUM(n) FROM event_rollups"
            " WHERE hour >= ? AND hour <= ? GROUP BY provider, verdict",
            (start_hour, now_hour),
        ):
            stats = out.setdefault(provider, ProviderStats())
            if verdict == "accepted":
                stats.accepted = total
            elif verdict == "rejected":
                stats.rejected = total
        return out
