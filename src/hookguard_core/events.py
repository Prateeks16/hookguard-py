"""The verdict event the Gateway POSTs to the Console after each decision.

This is a wire contract, not an internal type: the Go console decodes this
exact shape, and during the port a Python gateway will be talking to it. Field
names and JSON types are therefore fixed -- changing one is a breaking change
for the other implementation, in whichever language it happens to be.

Stdlib only, like the rest of ``hookguard_core``: both services import this, so
a dependency here lands in both images.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

__all__ = ["INGEST_PROVIDER_LABEL", "VerifyEvent", "format_timestamp", "parse_timestamp"]

#: The fixed ``X-HookGuard-Provider`` value the ingest route signs with. Not a
#: real webhook provider -- just the ingest route's identity within the shared
#: Gateway-signature scheme, so the Console can reject anything not claiming to
#: be the gateway's event feed before it even checks the HMAC.
INGEST_PROVIDER_LABEL = "console-ingest"


def parse_timestamp(value: str) -> datetime:
    """Parse an RFC 3339 timestamp as the Go gateway puts it on the wire.

    Go marshals ``time.Time`` as RFC3339Nano, which prints up to nine
    fractional digits and strips trailing zeros -- so the same field arrives as
    ``.123456789Z``, ``.1Z`` or bare ``Z`` depending on the clock. Since 3.11
    ``fromisoformat`` handles all of those, including the ``Z`` suffix and
    sub-microsecond fractions (which it truncates, not rounds). The vector
    tests pin that against real Go output rather than trusting the claim.
    """
    return datetime.fromisoformat(value)


def format_timestamp(value: datetime) -> str:
    """Render a timestamp the way Go's ``time.Time`` marshals one.

    Naive datetimes are read as UTC; everything is emitted with a ``Z`` suffix
    rather than ``+00:00``, matching what the Go gateway puts on the wire.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class VerifyEvent:
    """One Gateway verdict, as posted to the Console's ingest route."""

    timestamp: datetime
    path: str
    provider: str
    verdict: str  # "accepted" | "rejected"
    reason: str = ""  # "" when accepted
    upstream_status: int = 0
    latency_ms: int = 0
    body_bytes: int = 0
    body_sha256: str = ""
    remote_ip: str = ""

    def to_json_dict(self) -> dict[str, Any]:
        """Render the exact JSON object the Go console's decoder expects."""
        return {
            "ts": format_timestamp(self.timestamp),
            "path": self.path,
            "provider": self.provider,
            "verdict": self.verdict,
            "reason": self.reason,
            "upstream_status": self.upstream_status,
            "latency_ms": self.latency_ms,
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
            "remote_ip": self.remote_ip,
        }

    def to_json_bytes(self) -> bytes:
        """Serialize for the wire.

        Compact separators, matching Go's ``json.Marshal``, so the same event
        produces byte-identical payloads in both implementations. Not required
        for correctness -- each side signs the bytes it actually sends -- but it
        makes a captured request comparable across the two.
        """
        return json.dumps(self.to_json_dict(), separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json_dict(cls, data: dict[str, Any]) -> VerifyEvent:
        """Build an event from a decoded ingest body.

        Missing fields take their zero value, matching Go's decoder: an event
        the gateway omitted a field from is not malformed, it is an event with
        that field empty.
        """
        return cls(
            timestamp=parse_timestamp(data["ts"]),
            path=data.get("path", ""),
            provider=data.get("provider", ""),
            verdict=data.get("verdict", ""),
            reason=data.get("reason", ""),
            upstream_status=data.get("upstream_status", 0),
            latency_ms=data.get("latency_ms", 0),
            body_bytes=data.get("body_bytes", 0),
            body_sha256=data.get("body_sha256", ""),
            remote_ip=data.get("remote_ip", ""),
        )
