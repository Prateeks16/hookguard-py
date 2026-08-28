"""Best-effort delivery of verdict events to the Console.

Off the request path by construction. ``EVENTS_URL`` is optional: unset, no
background task runs and :meth:`EventEmitter.record` is a single branch, so the
gateway's behaviour without a Console is exactly what it was before this
module existed.

The queue is bounded and drops its oldest entry to make room for the newest.
Telemetry must never apply backpressure to verification -- a Console that is
slow, or down, must not slow down or fail a webhook.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import UTC, datetime, timedelta

import httpx
from starlette.requests import Request

from hookguard_core import gatewaysig
from hookguard_core.events import INGEST_PROVIDER_LABEL, VerifyEvent

from .config import Route

__all__ = ["EventEmitter", "classify_reason"]

log = logging.getLogger("hookguard.events")

#: Matches the Go implementation. Large enough to absorb a burst, small enough
#: that a wedged Console cannot grow memory without bound.
QUEUE_SIZE = 256

#: Delivery is best-effort and must not tie up the loop.
POST_TIMEOUT = httpx.Timeout(2.0)

#: A downed Console must not spam the log at request volume.
FAILURE_LOG_INTERVAL = timedelta(minutes=1)


def classify_reason(error: Exception | None) -> str:
    """Map a rejection to the small stable taxonomy the Console's event
    contract expects.

    Verifiers raise free-form messages with no error-type hierarchy, so this is
    a substring classifier over the exact strings they can produce today. The
    tests enumerate every one, so a reworded verifier error breaks a test
    rather than silently landing in the wrong bucket.

    Cases that do not cleanly fit -- a malformed cert response, an RSA key-type
    mismatch, a network failure -- land in "other" rather than being forced
    into a misleading category.
    """
    if error is None:
        return ""
    msg = str(error)

    if "missing" in msg and "header" in msg:
        return "missing header"
    if "outside replay window" in msg:
        return "stale timestamp"
    if (
        "not a trusted PayPal host" in msg
        or "must be https" in msg
        or "invalid paypal-cert-url" in msg
    ):
        return "cert host rejected"
    if "certificate chain" in msg:
        return "cert chain invalid"
    if "unsupported paypal-auth-algo" in msg:
        return "unsupported algorithm"
    if "signature mismatch" in msg or "no matching signature" in msg:
        return "signature mismatch"
    if (
        "encoding" in msg
        or "malformed" in msg
        or "invalid timestamp" in msg
        or "parse certificate" in msg
        or "no certificate found" in msg
    ):
        return "bad encoding"
    return "other"


class EventEmitter:
    """Posts verdict events to ``EVENTS_URL``, best-effort, off the hot path.

    An emitter built with an empty URL is disabled: no task, and ``record`` does
    one check and returns.
    """

    def __init__(self, url: str, secret: bytes) -> None:
        self._url = url
        self._secret = secret
        self._queue: asyncio.Queue[VerifyEvent] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._task: asyncio.Task[None] | None = None
        self._client: httpx.AsyncClient | None = None
        self._stopping = asyncio.Event()
        self._fail_count = 0
        self._last_log = datetime.min.replace(tzinfo=UTC)

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    async def start(self) -> None:
        """Start the single delivery task, if enabled."""
        if not self.enabled or self._task is not None:
            return
        self._client = httpx.AsyncClient(timeout=POST_TIMEOUT)
        self._task = asyncio.create_task(self._run(), name="hookguard-events")

    async def aclose(self) -> None:
        """Stop after delivering whatever is already queued.

        An event recorded after this is simply never delivered -- the process is
        on its way out -- but recording one stays safe, which is why stopping is
        signalled out of band rather than by closing the queue.
        """
        if self._task is None:
            if self._client is not None:
                await self._client.aclose()
                self._client = None
            return
        self._stopping.set()
        await self._task
        self._task = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def record(
        self,
        route: Route,
        body: bytes,
        request: Request,
        verdict: str,
        reason: str,
        upstream_status: int,
        latency: timedelta,
    ) -> None:
        """Build and enqueue one verdict event.

        Cheap to call unconditionally from the handler: the enabled check
        happens before any of the hashing work, so a disabled emitter costs one
        branch per request.
        """
        if not self.enabled:
            return
        self._emit(
            VerifyEvent(
                timestamp=datetime.now(UTC),
                path=route.path,
                provider=route.provider,
                verdict=verdict,
                reason=reason,
                upstream_status=upstream_status,
                latency_ms=int(latency.total_seconds() * 1000),
                body_bytes=len(body),
                body_sha256=hashlib.sha256(body).hexdigest(),
                remote_ip=remote_ip(request),
            )
        )

    def _emit(self, event: VerifyEvent) -> None:
        """Non-blocking enqueue, dropping the oldest entry on overflow.

        Under concurrent overflow this is best-effort rather than exact, which
        is the right trade for telemetry that must never block verification.
        """
        try:
            self._queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        try:
            self._queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    async def _run(self) -> None:
        stopping = asyncio.ensure_future(self._stopping.wait())
        try:
            while True:
                getter = asyncio.ensure_future(self._queue.get())
                done, _ = await asyncio.wait(
                    {getter, stopping}, return_when=asyncio.FIRST_COMPLETED
                )
                if getter in done:
                    await self._post(getter.result())
                    continue
                getter.cancel()
                break
            # Deliver what is already queued, then exit.
            while True:
                try:
                    await self._post(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    return
        finally:
            stopping.cancel()

    async def _post(self, event: VerifyEvent) -> None:
        assert self._client is not None
        payload = event.to_json_bytes()
        try:
            response = await self._client.post(
                self._url,
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    gatewaysig.PROVIDER_HEADER: INGEST_PROVIDER_LABEL,
                    gatewaysig.HEADER: gatewaysig.sign(
                        self._secret, INGEST_PROVIDER_LABEL, payload
                    ),
                },
            )
        except httpx.HTTPError as e:
            self._log_failure(e)
            return
        if response.status_code >= 300:
            self._log_failure(None)

    def _log_failure(self, error: Exception | None) -> None:
        self._fail_count += 1
        now = datetime.now(UTC)
        if now - self._last_log < FAILURE_LOG_INTERVAL:
            return
        if error is not None:
            log.warning(
                "%d delivery failure(s) in the last interval, most recent: %s",
                self._fail_count,
                error,
            )
        else:
            log.warning(
                "%d delivery failure(s) in the last interval (non-2xx response)",
                self._fail_count,
            )
        self._fail_count = 0
        self._last_log = now


def remote_ip(request: Request) -> str:
    """The peer address, without the port.

    Deliberately not X-Forwarded-For: the gateway is the internet-facing hop,
    and trusting a client-supplied header here would let anyone write whatever
    they liked into the Console's logs.
    """
    return request.client.host if request.client else ""
