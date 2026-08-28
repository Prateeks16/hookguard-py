"""The periodic prune of old events.

Deletes events older than the configured retention window. ``event_rollups``
is deliberately untouched: it is the aggregate the Overview and charts read
from, it is tiny compared to the raw events, and keeping it is what lets a
one-hour retention window still show a month of trend.

The job also prunes the rate limiters, whose maps would otherwise grow one
entry per distinct login key forever.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

from .auth import Limiter
from .store import Store

__all__ = ["DEFAULT_INTERVAL", "RetentionJob", "sweep"]

log = logging.getLogger("hookguard.retention")

#: Once a day. Cheap enough to run more often, but the events table only
#: grows meaningfully slower than that.
DEFAULT_INTERVAL = timedelta(days=1)


def sweep(store: Store, now: datetime) -> int:
    """Delete events older than the retention window. Returns the count.

    ``now`` is a parameter rather than a call to the clock so this is testable
    directly, and the retention setting is read on every call rather than
    cached at construction -- which is what makes an admin's change take
    effect on the next tick instead of at the next restart.
    """
    days = store.get_retention_days()
    cutoff = now - timedelta(days=days)
    return store.delete_events_older_than(int(cutoff.timestamp() * 1000))


class RetentionJob:
    """Runs :func:`sweep` at startup and then once per interval.

    Sweeping at startup means a freshly deployed instance does not wait a
    full day for its first prune.
    """

    def __init__(
        self,
        store: Store,
        *,
        interval: timedelta = DEFAULT_INTERVAL,
        limiters: Sequence[Limiter] = (),
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._interval = interval
        self._limiters = tuple(limiters)
        self._now = now
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        if self._task is None:
            self._stopping.clear()
            self._task = asyncio.create_task(self._run(), name="hookguard-retention")

    async def aclose(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        await self._task
        self._task = None

    async def run_once(self) -> int:
        """One sweep, off the event loop. Returns events deleted."""
        now = self._now()
        deleted = await asyncio.to_thread(self._sweep_and_log, now)
        for limiter in self._limiters:
            limiter.prune(now)
        return deleted

    def _sweep_and_log(self, now: datetime) -> int:
        try:
            deleted = sweep(self._store, now)
        except Exception:
            log.exception("sweep failed")
            return 0
        if deleted:
            log.info("pruned %d events older than the retention window", deleted)
        return deleted

    async def _run(self) -> None:
        await self.run_once()
        while not self._stopping.is_set():
            # Waiting on the stop event rather than sleeping means shutdown is
            # immediate instead of taking up to a day.
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self._interval.total_seconds()
                )
            except TimeoutError:
                await self.run_once()
