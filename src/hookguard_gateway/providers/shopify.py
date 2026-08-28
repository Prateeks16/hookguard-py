"""Shopify's signature shape.

An ``X-Shopify-Hmac-SHA256`` header whose value is the HMAC-SHA256 of the raw
body encoded as standard base64 -- not hex, which is the one twist versus
Stripe and GitHub. No timestamp, so no replay window.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime

from ..config import Route
from ..verifier import VerificationError, Verifier, VerifierDeps, register_provider

__all__ = ["ShopifyVerifier"]

HEADER = "X-Shopify-Hmac-SHA256"


@register_provider("shopify")
def _build(_route: Route, secret: str, _deps: VerifierDeps) -> Verifier:
    if not secret:
        raise ValueError("empty secret")
    return ShopifyVerifier(secret=secret.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class ShopifyVerifier:
    secret: bytes

    def verify(self, raw_body: bytes, headers, _now: datetime) -> None:
        header = headers.get(HEADER)
        if not header:
            raise VerificationError(f"missing {HEADER} header")

        try:
            # validate=True so stray characters are an error rather than being
            # silently discarded, which is what Go's StdEncoding does.
            got = base64.b64decode(header, validate=True)
        except (binascii.Error, ValueError):
            raise VerificationError("invalid signature encoding") from None

        expected = hmac.new(self.secret, raw_body, hashlib.sha256).digest()
        if not hmac.compare_digest(got, expected):
            raise VerificationError("signature mismatch")
