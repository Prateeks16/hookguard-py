"""The Gateway signature: the single internal HMAC HookGuard adds to a verified
webhook before forwarding.

The Upstream authenticates the Gateway with one check instead of re-running
every Provider's verification. The signature binds the verified provider name
to the body, so the Upstream learns which Provider was verified and an attacker
cannot relabel a payload without breaking the signature.

Port of Go's ``internal/gatewaysig``. The preimage and the hex encoding are
identical on purpose: a Python gateway and a Go console must interoperate, so
this file is pinned by cross-language vectors in ``tests/vectors/`` rather than
by round-trip tests alone -- a round trip would pass just as happily against a
preimage we had invented.
"""

from __future__ import annotations

import hashlib
import hmac
import re

__all__ = [
    "HEADER",
    "PROVIDER_HEADER",
    "GatewaySignatureError",
    "sign",
    "verify",
]

#: Carries the hex HMAC.
HEADER = "X-HookGuard-Signature"

#: Carries the verified provider name.
PROVIDER_HEADER = "X-HookGuard-Provider"

# Go's hex.DecodeString accepts an even-length run of hex digits and nothing
# else. Python's bytes.fromhex is laxer -- it skips ASCII whitespace, so
# "de ad..." would decode where Go errors. Pin the strict shape ourselves so
# the two implementations reject the same inputs.
_HEX = re.compile(r"\A(?:[0-9a-fA-F]{2})*\Z")


class GatewaySignatureError(Exception):
    """The Gateway signature is malformed or does not match."""


def sign(secret: bytes, provider: str, body: bytes) -> str:
    """Return the hex HMAC-SHA256 over ``"<provider>.<body>"`` keyed by secret."""
    return _mac(secret, provider, body).hex()


def verify(secret: bytes, provider: str, body: bytes, sig_hex: str) -> None:
    """Check ``sig_hex`` against :func:`sign`, comparing in constant time.

    Returns ``None`` on success -- the Go original returns a nil error here, and
    callers in both languages branch on failure, not on a boolean.

    Raises:
        GatewaySignatureError: if the signature is not valid hex, or does not
            match.
    """
    if not _HEX.fullmatch(sig_hex):
        raise GatewaySignatureError("invalid gateway signature encoding")
    got = bytes.fromhex(sig_hex)
    if not hmac.compare_digest(got, _mac(secret, provider, body)):
        raise GatewaySignatureError("gateway signature mismatch")


def _mac(secret: bytes, provider: str, body: bytes) -> bytes:
    m = hmac.new(secret, digestmod=hashlib.sha256)
    m.update(provider.encode("utf-8"))
    m.update(b".")
    m.update(body)
    return m.digest()
