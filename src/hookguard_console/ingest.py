"""Decoding and authenticating gateway verdict events.

The ingest route is authenticated by the Gateway signature, not by a session:
it is machine-to-machine, and the Gateway has no cookie. The same primitive
the Gateway signs webhooks with is reused here under a fixed provider label,
so there is one signature scheme in the system rather than two.
"""

from __future__ import annotations

import json

from hookguard_core import gatewaysig
from hookguard_core.events import INGEST_PROVIDER_LABEL, VerifyEvent

from .store import Event

__all__ = [
    "EXPECTED_PROVIDER",
    "PROVIDER_HEADER",
    "SIGNATURE_HEADER",
    "IngestError",
    "check_provider_header",
    "decode",
    "to_row",
    "verify",
]

#: Re-exported so handlers do not import gatewaysig just to know header names.
PROVIDER_HEADER = gatewaysig.PROVIDER_HEADER
SIGNATURE_HEADER = gatewaysig.HEADER

#: The ``X-HookGuard-Provider`` value this route requires. Not a real webhook
#: provider -- it is the event feed's identity within the shared scheme.
EXPECTED_PROVIDER = INGEST_PROVIDER_LABEL


class IngestError(Exception):
    """The request is not an authentic, well-formed event."""


def check_provider_header(got: str) -> None:
    """Reject anything not claiming to be the gateway's event feed.

    Runs before the HMAC: a request that does not even claim the right
    identity is refused without spending a hash on it.
    """
    if got != EXPECTED_PROVIDER:
        raise IngestError("unexpected provider header")


def verify(secret: bytes, body: bytes, signature: str) -> None:
    """Check the body against the Gateway signature headers.

    Uses the same primitive the gateway signs with -- no second
    implementation to keep in step.
    """
    try:
        gatewaysig.verify(secret, EXPECTED_PROVIDER, body, signature)
    except gatewaysig.GatewaySignatureError as e:
        raise IngestError(str(e)) from e


def decode(body: bytes) -> VerifyEvent:
    """Parse one event body.

    Raises:
        IngestError: malformed JSON, or a missing timestamp. The caller turns
            this into a 400 -- it is a broken sender, not a broken server.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise IngestError(f"malformed event JSON: {e}") from e
    if not isinstance(data, dict):
        raise IngestError("event must be a JSON object")
    try:
        return VerifyEvent.from_json_dict(data)
    except (KeyError, TypeError, ValueError) as e:
        raise IngestError(f"malformed event: {e}") from e


def to_row(event: VerifyEvent) -> Event:
    """Convert a decoded wire event to a database row.

    The wire carries an RFC 3339 timestamp; the table stores unix
    milliseconds, which is what every query buckets and orders on.
    """
    return Event(
        received_at=int(event.timestamp.timestamp() * 1000),
        path=event.path,
        provider=event.provider,
        verdict=event.verdict,
        reason=event.reason,
        upstream_status=event.upstream_status,
        latency_ms=event.latency_ms,
        body_bytes=event.body_bytes,
        body_sha256=event.body_sha256,
        remote_ip=event.remote_ip,
    )
