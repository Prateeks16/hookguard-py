"""Session and CSRF tokens.

Only ``sha256(token)`` is ever stored. Someone with read access to the
database -- a backup, a stray copy, a SQL injection that only reads -- still
cannot mint a working cookie from what they find there.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

__all__ = [
    "SESSION_ABSOLUTE_TIMEOUT",
    "SESSION_COOKIE_NAME",
    "SESSION_IDLE_TIMEOUT",
    "hash_token",
    "new_csrf_token",
    "new_session_token",
]

#: The cookie carrying the raw session token.
SESSION_COOKIE_NAME = "hg_session"

#: Idle expiry: a session unused for this long is dead.
SESSION_IDLE_TIMEOUT = timedelta(days=7)

#: Absolute cap, regardless of activity. A session that has been alive this
#: long is re-authenticated even if it has been in constant use, which bounds
#: how long a stolen cookie stays useful.
SESSION_ABSOLUTE_TIMEOUT = timedelta(days=30)

_TOKEN_BYTES = 32


def new_session_token() -> tuple[str, bytes]:
    """A fresh session token and its hash.

    Returns ``(token, sha256(token))``: the token goes in the cookie, the hash
    goes in the database, and the two never swap places.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    return token, hash_token(token)


def hash_token(token: str) -> bytes:
    """The stored form of a token. Plain SHA-256, not a password hash.

    Deliberately not Argon2: the input is 32 bytes of CSPRNG output, so there
    is nothing to brute-force, and a slow hash on every request would be a
    denial-of-service vector rather than a defence.
    """
    return hashlib.sha256(token.encode("utf-8")).digest()


def new_csrf_token() -> str:
    """A fresh CSRF token, stored with the session and echoed by forms."""
    return secrets.token_urlsafe(_TOKEN_BYTES)
