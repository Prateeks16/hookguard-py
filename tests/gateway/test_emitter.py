"""The event emitter, ported from events_test.go.

Telemetry must never apply backpressure to verification. Most of these tests
are about what happens when the Console is slow, down, or absent.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from starlette.requests import Request

from hookguard_core import gatewaysig
from hookguard_core.events import INGEST_PROVIDER_LABEL, VerifyEvent
from hookguard_gateway.config import Route
from hookguard_gateway.emitter import QUEUE_SIZE, EventEmitter, classify_reason
from hookguard_gateway.providers.github import GitHubVerifier
from hookguard_gateway.providers.paypal import PayPalVerifier, check_cert_host
from hookguard_gateway.providers.shopify import ShopifyVerifier
from hookguard_gateway.providers.stripe import StripeVerifier
from hookguard_gateway.verifier import VerificationError

from .signers import headers

SECRET = b"internal-events"
ROUTE = Route(path="/hook/stripe", provider="stripe", upstream="http://u")


def fake_request(ip: str = "203.0.113.7") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": ROUTE.path,
            "headers": [],
            "client": (ip, 54321),
        }
    )


def event(n: int = 0) -> VerifyEvent:
    return VerifyEvent(
        timestamp=datetime.now(UTC),
        path=ROUTE.path,
        provider="stripe",
        verdict="accepted",
        body_bytes=n,
    )


# --------------------------------------------------------------------------
# Disabled
# --------------------------------------------------------------------------


async def test_unset_events_url_emits_nothing() -> None:
    """The default. No task runs and record is a single branch, so the gateway
    behaves exactly as it did before telemetry existed."""
    emitter = EventEmitter("", SECRET)
    assert not emitter.enabled
    await emitter.start()
    emitter.record(ROUTE, b"{}", fake_request(), "accepted", "", 200, timedelta())
    assert emitter._queue.qsize() == 0
    await emitter.aclose()  # must not hang or raise


async def test_close_on_a_disabled_emitter_is_a_noop() -> None:
    await EventEmitter("", SECRET).aclose()


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------


async def test_posts_a_signed_event() -> None:
    """The Console authenticates ingest with the same Gateway signature scheme
    the upstream uses, under a fixed provider label."""
    received: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(202)

    emitter = EventEmitter("http://console/api/v1/ingest", SECRET)
    await emitter.start()
    emitter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    emitter.record(
        ROUTE, b'{"id":1}', fake_request(), "accepted", "", 200, timedelta(milliseconds=17)
    )
    await emitter.aclose()

    assert len(received) == 1
    request = received[0]
    body = request.content

    assert request.headers[gatewaysig.PROVIDER_HEADER] == INGEST_PROVIDER_LABEL
    # The signature is over the exact bytes sent.
    gatewaysig.verify(SECRET, INGEST_PROVIDER_LABEL, body, request.headers[gatewaysig.HEADER])

    payload = json.loads(body)
    assert payload["path"] == ROUTE.path
    assert payload["provider"] == "stripe"
    assert payload["verdict"] == "accepted"
    assert payload["upstream_status"] == 200
    assert payload["latency_ms"] == 17
    assert payload["body_bytes"] == 8
    assert payload["remote_ip"] == "203.0.113.7"
    assert len(payload["body_sha256"]) == 64  # exact value asserted in the next test


async def test_body_hash_is_of_the_raw_body() -> None:
    import hashlib

    received: list[bytes] = []
    emitter = EventEmitter("http://console/ingest", SECRET)
    await emitter.start()
    emitter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: (received.append(r.content), httpx.Response(202))[1]
        )
    )
    body = b'{"note":"thanks \xf0\x9f\x9a\x80"}'
    emitter.record(ROUTE, body, fake_request(), "accepted", "", 200, timedelta())
    await emitter.aclose()

    assert json.loads(received[0])["body_sha256"] == hashlib.sha256(body).hexdigest()


async def test_a_failing_console_does_not_raise() -> None:
    """A down Console must never turn into a failed webhook."""
    emitter = EventEmitter("http://console/ingest", SECRET)
    await emitter.start()
    emitter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r))
        )
    )
    emitter.record(ROUTE, b"{}", fake_request(), "accepted", "", 200, timedelta())
    await emitter.aclose()  # the assertion is that this completes


async def test_a_non_2xx_response_does_not_raise() -> None:
    emitter = EventEmitter("http://console/ingest", SECRET)
    await emitter.start()
    emitter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(500))
    )
    emitter.record(ROUTE, b"{}", fake_request(), "accepted", "", 200, timedelta())
    await emitter.aclose()


async def test_close_drains_what_is_queued() -> None:
    delivered: list[bytes] = []
    emitter = EventEmitter("http://console/ingest", SECRET)
    await emitter.start()
    emitter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: (delivered.append(r.content), httpx.Response(202))[1]
        )
    )
    for i in range(10):
        emitter.record(ROUTE, b"x" * i, fake_request(), "accepted", "", 200, timedelta())
    await emitter.aclose()
    assert len(delivered) == 10, "shutdown must flush the queue, not discard it"


# --------------------------------------------------------------------------
# Backpressure
# --------------------------------------------------------------------------


async def test_overflow_drops_the_oldest_and_never_blocks() -> None:
    """The queue is bounded. Overflow drops the oldest entry rather than
    blocking the caller, which is a request-handling coroutine."""
    emitter = EventEmitter("http://console/ingest", SECRET)
    # No start(): nothing drains, so the queue fills deterministically.
    for i in range(QUEUE_SIZE + 50):
        emitter._emit(event(i))

    assert emitter._queue.qsize() == QUEUE_SIZE, "the queue must stay bounded"

    remaining = []
    while not emitter._queue.empty():
        remaining.append(emitter._queue.get_nowait().body_bytes)
    # The newest survived; the oldest were dropped.
    assert remaining[-1] == QUEUE_SIZE + 49
    assert 0 not in remaining


async def test_record_returns_promptly_under_overflow() -> None:
    """The point of drop-oldest: recording stays O(1) and never awaits."""
    emitter = EventEmitter("http://console/ingest", SECRET)
    started = asyncio.get_running_loop().time()
    for _ in range(QUEUE_SIZE * 4):
        emitter.record(ROUTE, b"{}", fake_request(), "accepted", "", 200, timedelta())
    assert asyncio.get_running_loop().time() - started < 1.0


# --------------------------------------------------------------------------
# Reason classification
# --------------------------------------------------------------------------


def test_no_error_classifies_as_empty() -> None:
    assert classify_reason(None) == ""


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("missing Stripe-Signature header", "missing header"),
        ("missing X-Hub-Signature-256 header", "missing header"),
        ("missing X-Shopify-Hmac-SHA256 header", "missing header"),
        ("missing PayPal signature headers", "missing header"),
        ("timestamp outside replay window", "stale timestamp"),
        ("paypal-cert-url host 'evil.com' is not a trusted PayPal host", "cert host rejected"),
        ("paypal-cert-url must be https", "cert host rejected"),
        ("invalid paypal-cert-url: bad", "cert host rejected"),
        ("paypal cert: certificate chain: untrusted", "cert chain invalid"),
        ("unsupported paypal-auth-algo 'SHA1withRSA'", "unsupported algorithm"),
        ("signature mismatch", "signature mismatch"),
        ("no matching signature", "signature mismatch"),
        ("invalid signature encoding", "bad encoding"),
        ("malformed Stripe-Signature header", "bad encoding"),
        ("invalid timestamp", "bad encoding"),
        ("paypal cert: parse certificate: bad", "bad encoding"),
        ("paypal cert: no certificate found in response", "bad encoding"),
        ("paypal cert: not an RSA key", "other"),
        ("paypal cert: fetch: status 500", "other"),
    ],
)
def test_classification_taxonomy(message: str, expected: str) -> None:
    assert classify_reason(VerificationError(message)) == expected


def test_every_verifier_error_classifies_to_a_known_bucket() -> None:
    """Enumerates the rejections the verifiers can actually produce, by
    provoking them, so a reworded error breaks this test rather than silently
    landing in "other".
    """
    now = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)
    produced: list[str] = []

    def capture(fn) -> None:
        try:
            fn()
        except VerificationError as e:
            produced.append(str(e))
        else:
            raise AssertionError("expected a rejection")

    stripe = StripeVerifier(secret=b"s", replay_window=timedelta(minutes=5))
    capture(lambda: stripe.verify(b"{}", headers(), now))
    capture(lambda: stripe.verify(b"{}", headers(**{"Stripe-Signature": "junk"}), now))
    capture(lambda: stripe.verify(b"{}", headers(**{"Stripe-Signature": "t=x,v1=aa"}), now))
    capture(lambda: stripe.verify(b"{}", headers(**{"Stripe-Signature": "t=1,v1=aa"}), now))

    github = GitHubVerifier(secret=b"s")
    capture(lambda: github.verify(b"{}", headers(), now))
    capture(lambda: github.verify(b"{}", headers(**{"X-Hub-Signature-256": "nope"}), now))
    capture(lambda: github.verify(b"{}", headers(**{"X-Hub-Signature-256": "sha256=zz"}), now))
    capture(
        lambda: github.verify(b"{}", headers(**{"X-Hub-Signature-256": "sha256=" + "aa" * 32}), now)
    )

    shopify = ShopifyVerifier(secret=b"s")
    capture(lambda: shopify.verify(b"{}", headers(), now))
    capture(lambda: shopify.verify(b"{}", headers(**{"X-Shopify-Hmac-SHA256": "!!"}), now))
    capture(lambda: shopify.verify(b"{}", headers(**{"X-Shopify-Hmac-SHA256": "YWJj"}), now))

    paypal = PayPalVerifier(webhook_id="WH", client=httpx.Client())
    capture(lambda: paypal.verify(b"{}", headers(), now))
    capture(lambda: check_cert_host("http://api.paypal.com/c.pem"))
    capture(lambda: check_cert_host("https://evil.com/c.pem"))

    assert produced, "no rejections were provoked"
    for message in produced:
        assert classify_reason(VerificationError(message)) != "other", (
            f"{message!r} fell through to 'other'; either the taxonomy or the "
            f"verifier's wording drifted"
        )
