"""GitHub's signature shape.

An ``X-Hub-Signature-256`` header of the form ``sha256=<hex>``, where the
HMAC-SHA256 is computed over the raw body bytes. GitHub carries no timestamp,
so there is no replay window.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime

from hookguard_core.stricthex import decode_hex

from ..config import Route
from ..verifier import VerificationError, Verifier, VerifierDeps, register_provider

__all__ = ["GitHubVerifier"]

HEADER = "X-Hub-Signature-256"
_PREFIX = "sha256="


@register_provider("github")
def _build(_route: Route, secret: str, _deps: VerifierDeps) -> Verifier:
    if not secret:
        raise ValueError("empty secret")
    return GitHubVerifier(secret=secret.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class GitHubVerifier:
    secret: bytes

    def verify(self, raw_body: bytes, headers, _now: datetime) -> None:
        header = headers.get(HEADER)
        if not header:
            raise VerificationError(f"missing {HEADER} header")
        if not header.startswith(_PREFIX):
            raise VerificationError(f"malformed {HEADER} header")

        try:
            got = decode_hex(header[len(_PREFIX) :])
        except ValueError:
            raise VerificationError("invalid signature encoding") from None

        expected = hmac.new(self.secret, raw_body, hashlib.sha256).digest()
        if not hmac.compare_digest(got, expected):
            raise VerificationError("signature mismatch")
