"""Argon2id password hashing.

Every parameter here is fixed rather than tunable. This is a security
product's own login, and the values are also written into the PHC string, so
a future parameter change can still verify hashes made under the old ones.

They must match the Go implementation exactly: an existing console database
carries hashes it generated, and getting this wrong locks every user out
rather than failing visibly. ``tests/fixtures/go-console.db`` holds a hash
produced by the Go build, and the suite verifies it here.
"""

from __future__ import annotations

import functools

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

__all__ = [
    "ARGON2_HASH_LEN",
    "ARGON2_MEMORY_KIB",
    "ARGON2_PARALLELISM",
    "ARGON2_SALT_LEN",
    "ARGON2_TIME_COST",
    "MAX_PASSWORD_LEN",
    "MIN_PASSWORD_LEN",
    "PasswordPolicyError",
    "dummy_hash",
    "hash_password",
    "validate_password",
    "verify_password",
]

# Pinned to the Go build's values. argon2-cffi's own defaults differ --
# parallelism is 4 there -- so these are set explicitly rather than inherited.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

#: Length-only policy, NIST-style: no composition rules, which push people
#: toward predictable substitutions without adding real entropy.
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128


class PasswordPolicyError(ValueError):
    """The password does not meet the length policy."""


_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    type=Type.ID,
)


def validate_password(password: str) -> None:
    """Raise :class:`PasswordPolicyError` if the password is unacceptable.

    Length is measured in characters, matching the Go implementation's use of
    ``len()`` on a string -- worth noting that differs for non-ASCII: Go counts
    bytes, Python counts code points, so a passphrase of accented characters
    clears the Python minimum slightly sooner. The bound is a floor on effort,
    not a security boundary, so the divergence is documented rather than
    engineered around.
    """
    if len(password) < MIN_PASSWORD_LEN:
        raise PasswordPolicyError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if len(password) > MAX_PASSWORD_LEN:
        raise PasswordPolicyError(f"password must be at most {MAX_PASSWORD_LEN} characters")


def hash_password(password: str) -> str:
    """Return the PHC-formatted Argon2id hash, with a fresh random salt."""
    return _hasher.hash(password)


def verify_password(password: str, phc: str) -> bool:
    """Whether the password matches the PHC-encoded hash.

    Parameters come from the hash itself, not from the constants above, so a
    hash written under different settings -- by an older build, or by Go --
    still verifies.

    Returns ``False`` rather than raising for a malformed hash: callers are
    authenticating a login, and a corrupt row in the users table should fail
    the login, not the request.
    """
    try:
        return _hasher.verify(phc, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


@functools.cache
def dummy_hash() -> str:
    """A valid hash to verify against when no such user exists.

    Login must take the same time whether the address is unknown or the
    password is wrong; skipping the hash for a missing user makes the two
    distinguishable by a stopwatch, which turns the login form into an account
    enumeration oracle.

    Computed once, lazily -- an Argon2 hash at import time would cost every
    process start, including the gateway's, which never calls this.
    """
    return hash_password("hookguard-dummy-hash-for-timing-defense")
