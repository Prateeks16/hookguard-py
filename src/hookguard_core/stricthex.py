"""Hex decoding that rejects what Go's ``hex.DecodeString`` rejects.

``bytes.fromhex`` skips ASCII whitespace, so ``"de ad..."`` decodes in Python
and errors in Go. That difference is harmless on its own -- the HMAC compare
still has to succeed afterwards -- but it is a verdict divergence between the
two implementations on a signature path, and the differential harness compares
verdicts. Pin the strict shape once, here, and use it everywhere a signature is
decoded.
"""

from __future__ import annotations

import re

__all__ = ["decode_hex"]

# An even-length run of hex digits and nothing else: no whitespace, no "0x",
# no sign. Exactly Go's grammar.
_HEX = re.compile(r"\A(?:[0-9a-fA-F]{2})*\Z")


def decode_hex(value: str) -> bytes:
    """Decode an even-length hex string.

    Raises:
        ValueError: if ``value`` is not purely an even-length run of hex
            digits -- including the whitespace ``bytes.fromhex`` would accept.
    """
    if not _HEX.fullmatch(value):
        raise ValueError("invalid hex encoding")
    return bytes.fromhex(value)
