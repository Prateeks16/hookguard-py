"""The Console's authentication primitives.

Argon2id password hashing, session and CSRF tokens, password-reset tokens,
and login rate limiting. Every parameter is fixed rather than tunable: this
is a security product's own login, so nothing here should be novel or
adjustable by accident.
"""

from .csrf import CSRF_FORM_FIELD, CSRF_HEADER, check_csrf
from .password import (
    MAX_PASSWORD_LEN,
    MIN_PASSWORD_LEN,
    PasswordPolicyError,
    dummy_hash,
    hash_password,
    validate_password,
    verify_password,
)
from .ratelimit import Limiter
from .reset import RESET_TOKEN_TTL, new_reset_token
from .session import (
    SESSION_ABSOLUTE_TIMEOUT,
    SESSION_COOKIE_NAME,
    SESSION_IDLE_TIMEOUT,
    hash_token,
    new_csrf_token,
    new_session_token,
)

__all__ = [
    "CSRF_FORM_FIELD",
    "CSRF_HEADER",
    "MAX_PASSWORD_LEN",
    "MIN_PASSWORD_LEN",
    "RESET_TOKEN_TTL",
    "SESSION_ABSOLUTE_TIMEOUT",
    "SESSION_COOKIE_NAME",
    "SESSION_IDLE_TIMEOUT",
    "Limiter",
    "PasswordPolicyError",
    "check_csrf",
    "dummy_hash",
    "hash_password",
    "hash_token",
    "new_csrf_token",
    "new_reset_token",
    "new_session_token",
    "validate_password",
    "verify_password",
]
