"""CSRF tokens.

SameSite=Lax on the session cookie is the backstop, not the mechanism: it
depends on browser behaviour we do not control and does not cover every
request shape. The token is the actual defence.
"""

from __future__ import annotations

import hmac

__all__ = ["CSRF_FORM_FIELD", "CSRF_HEADER", "check_csrf"]

#: Sent by htmx requests.
CSRF_HEADER = "X-CSRF-Token"

#: Forms carry the same value as a hidden input under this name, so the
#: no-JavaScript path is protected identically.
CSRF_FORM_FIELD = "csrf_token"


def check_csrf(want: str, got: str) -> bool:
    """Compare the session's token against the request's, in constant time.

    An empty value on either side is a failure rather than a match: a missing
    token is exactly what a forged cross-site request looks like, and `"" ==
    ""` would wave it straight through.
    """
    if not want or not got:
        return False
    return hmac.compare_digest(want, got)
