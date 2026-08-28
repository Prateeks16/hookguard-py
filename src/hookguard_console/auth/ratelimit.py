"""Login and signup rate limiting.

A fixed-window counter per key, held in memory. Sufficient for a
single-instance self-hosted console: a distributed store would be the right
answer behind a load balancer, and the wrong amount of machinery here.

Consequences worth being honest about. The counters reset when the process
restarts, so an attacker who can force restarts can also clear them. And a
fixed window admits a burst across a boundary -- ``max`` attempts at the end
of one window and ``max`` more at the start of the next. Both are acceptable
against the thing this defends: online password guessing against an Argon2
hash, where even an unthrottled attacker is measured in attempts per second.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timedelta

__all__ = ["Limiter"]


class Limiter:
    """Allows at most ``max_hits`` per key within ``window``."""

    def __init__(self, max_hits: int, window: timedelta) -> None:
        self._max = max_hits
        self._window = window
        self._lock = threading.Lock()
        self._hits: defaultdict[str, list[datetime]] = defaultdict(list)

    def allow(self, key: str, now: datetime) -> tuple[bool, timedelta]:
        """Record a hit and report whether it is within the limit.

        ``now`` is passed in rather than read from the clock so the caller's
        tests are deterministic.

        Returns ``(allowed, retry_after)``. When not allowed, ``retry_after``
        is how long until the oldest hit in the window expires -- a refused
        attempt does NOT extend the window, or a determined attacker would
        lock the real user out indefinitely.
        """
        with self._lock:
            cutoff = now - self._window
            kept = [t for t in self._hits[key] if t > cutoff]

            if len(kept) >= self._max:
                self._hits[key] = kept
                return False, self._window - (now - kept[0])

            kept.append(now)
            self._hits[key] = kept
            return True, timedelta(0)

    def prune(self, now: datetime) -> int:
        """Drop keys with no live hits, returning how many were removed.

        Without this the map grows one entry per distinct key forever, and the
        key is attacker-supplied (an email address, an IP), so an unbounded map
        is a slow memory leak someone can drive.

        The Go implementation has no equivalent -- it prunes each key's slice
        but never removes the key -- so this is the one deliberate addition in
        this module. Phase 6 wires it into the Console's periodic job.
        """
        cutoff = now - self._window
        with self._lock:
            stale = [k for k, hits in self._hits.items() if not any(t > cutoff for t in hits)]
            for key in stale:
                del self._hits[key]
            return len(stale)

    @property
    def tracked_keys(self) -> int:
        """How many keys are currently held. For tests and diagnostics."""
        with self._lock:
            return len(self._hits)
