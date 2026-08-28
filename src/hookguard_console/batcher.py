"""Batching ingested events into the store.

One background task drains a bounded queue on a 100ms tick, turning N
per-request writes into one write per tick against a single-writer database.
Without it, a burst of webhooks becomes a burst of individual transactions
contending for the same write lock.

Like the gateway's emitter, the queue is bounded and drops its oldest entry on
overflow: ingest must never apply backpressure to the HTTP response, because
the sender is the gateway and slowing it down would slow down webhook
verification itself.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from .store import Event, RollupDelta, Store

__all__ = ["Batcher", "hour_bucket", "rollup_deltas"]

log = logging.getLogger("hookguard.ingest")

QUEUE_SIZE = 1024
FLUSH_INTERVAL = 0.1  # seconds

#: Written after each flush so the Console can show when it last heard from
#: the gateway -- a silent gateway and a healthy one look identical otherwise.
LAST_INGEST_SETTING = "last_ingest_at"


def hour_bucket(unix_ms: int) -> int:
    """The unix-hour bucket ``event_rollups`` keys on."""
    return unix_ms // 1000 // 3600


def rollup_deltas(events: list[Event]) -> list[RollupDelta]:
    """Sum a batch into per-bucket increments.

    A batch of three same-bucket events becomes one upsert of ``n=3`` rather
    than three upserts racing each other for the same row.
    """
    counts: defaultdict[tuple[int, str, str], int] = defaultdict(int)
    for event in events:
        counts[(hour_bucket(event.received_at), event.provider, event.verdict)] += 1
    return [
        RollupDelta(hour=hour, provider=provider, verdict=verdict, n=n)
        for (hour, provider, verdict), n in counts.items()
    ]


class Batcher:
    """Queues events and persists them on a ticker."""

    def __init__(
        self, store: Store, *, tick: float = FLUSH_INTERVAL, queue_size: int = QUEUE_SIZE
    ) -> None:
        self._store = store
        self._tick = tick
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self._flush_done = asyncio.Event()
        self.dropped = 0

    async def start(self) -> None:
        if self._task is None:
            self._stopping.clear()
            self._task = asyncio.create_task(self._run(), name="hookguard-ingest")

    async def aclose(self) -> None:
        """Stop after persisting whatever is queued."""
        if self._task is None:
            return
        self._stopping.set()
        await self._task
        self._task = None

    def enqueue(self, event: Event) -> None:
        """Non-blocking enqueue, dropping the oldest entry on overflow."""
        try:
            self._queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        try:
            self._queue.get_nowait()
            self.dropped += 1
        except asyncio.QueueEmpty:
            pass
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    async def flush(self) -> None:
        """Persist everything enqueued before this call.

        Drains the queue first: an event sitting in the queue right now was
        enqueued before this call and must be included, so waiting on the
        ticker would be a race rather than a guarantee. Tests use this instead
        of sleeping.
        """
        await self._drain_and_persist()

    async def _run(self) -> None:
        stopping = asyncio.ensure_future(self._stopping.wait())
        try:
            while not self._stopping.is_set():
                # Wake on the tick, or immediately when asked to stop, so
                # shutdown does not wait out a full interval.
                done, _ = await asyncio.wait({stopping}, timeout=self._tick)
                await self._drain_and_persist()
                if done:
                    break
        finally:
            stopping.cancel()
            await self._drain_and_persist()

    def _drain(self) -> list[Event]:
        pending: list[Event] = []
        while True:
            try:
                pending.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                return pending

    async def _drain_and_persist(self) -> None:
        pending = self._drain()
        if not pending:
            return
        # The store is synchronous and lock-guarded; running it inline would
        # block the event loop for the duration of the transaction.
        await asyncio.to_thread(self._persist, pending)

    def _persist(self, pending: list[Event]) -> None:
        """Write one batch. Failures are logged, not raised.

        This runs on a background task with no request to fail: an exception
        escaping here would kill the task and silently stop all ingest, which
        is far worse than a logged write error.
        """
        try:
            self._store.insert_events(pending)
        except Exception:
            log.exception("insert events failed; %d events lost", len(pending))
            return
        try:
            self._store.upsert_rollups(rollup_deltas(pending))
        except Exception:
            log.exception("upsert rollups failed")
        try:
            self._store.set_setting(LAST_INGEST_SETTING, str(pending[-1].received_at))
        except Exception:
            log.exception("recording last ingest time failed")
