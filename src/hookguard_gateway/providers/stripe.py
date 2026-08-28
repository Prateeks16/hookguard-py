"""Stripe's signature shape.

A ``Stripe-Signature`` header of the form ``t=<unix>,v1=<hex>[,v1=<hex>...]``,
where the HMAC-SHA256 is computed over ``"<t>.<rawBody>"``. Stripe is the one
supported provider whose signature carries a timestamp, so it is the only one
with a replay window: a timestamp outside the window is rejected even when the
HMAC matches.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta

from hookguard_core.goduration import GoDurationError, parse_go_duration
from hookguard_core.stricthex import decode_hex

from ..config import Route
from ..verifier import VerificationError, Verifier, VerifierDeps, register_provider

__all__ = ["StripeVerifier"]

HEADER = "Stripe-Signature"


@register_provider("stripe")
def _build(route: Route, secret: str, _deps: VerifierDeps) -> Verifier:
    if not secret:
        raise ValueError("empty secret")
    try:
        window = parse_go_duration(route.replay_window) if route.replay_window else timedelta(0)
    except GoDurationError as e:
        raise ValueError(f"replay_window: {e}") from e
    return StripeVerifier(secret=secret.encode("utf-8"), replay_window=window)


@dataclass(frozen=True, slots=True)
class StripeVerifier:
    secret: bytes
    replay_window: timedelta = timedelta(0)

    def verify(self, raw_body: bytes, headers, now: datetime) -> None:
        header = headers.get(HEADER)
        if not header:
            raise VerificationError(f"missing {HEADER} header")

        timestamp, signatures = _parse_header(header)
        if not timestamp or not signatures:
            raise VerificationError(f"malformed {HEADER} header")

        try:
            ts = int(timestamp)
        except ValueError:
            raise VerificationError("invalid timestamp") from None

        if self.replay_window > timedelta(0):
            delta = abs(now.timestamp() - ts)
            if delta > self.replay_window.total_seconds():
                raise VerificationError("timestamp outside replay window")

        # The signed payload is the timestamp, a literal dot, then the exact
        # bytes received -- concatenated, not formatted, so a body that is not
        # valid UTF-8 still hashes correctly.
        expected = hmac.new(
            self.secret,
            timestamp.encode("ascii") + b"." + raw_body,
            hashlib.sha256,
        ).digest()

        # Stripe may send several v1 signatures during a secret rotation; any
        # one matching is a pass. An unparseable candidate is skipped rather
        # than failing the request, matching Stripe's own library.
        for candidate in signatures:
            try:
                got = decode_hex(candidate)
            except ValueError:
                continue
            if hmac.compare_digest(got, expected):
                return
        raise VerificationError("no matching signature")


def _parse_header(header: str) -> tuple[str, list[str]]:
    """Split ``t=...,v1=...,v1=...`` into its timestamp and signatures.

    Unknown keys (Stripe has shipped ``v0`` alongside ``v1``) are ignored
    rather than treated as an error.
    """
    timestamp = ""
    signatures: list[str] = []
    for part in header.split(","):
        key, sep, value = part.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    return timestamp, signatures
