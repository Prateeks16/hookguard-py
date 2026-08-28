"""Password-reset tokens.

Mirrors session tokens: only the hash is stored, so a leaked settings table
does not yield a usable reset link. Operator-run and handed over out of band
-- there is no SMTP in this system.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from .session import hash_token

__all__ = ["RESET_TOKEN_TTL", "new_reset_token"]

#: How long a printed reset URL stays valid.
RESET_TOKEN_TTL = timedelta(hours=1)

_TOKEN_BYTES = 32


def new_reset_token() -> tuple[str, bytes]:
    """A fresh reset token and its hash, same construction as a session token."""
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    return token, hash_token(token)
