"""The Verifier contract and the provider registry.

A Verifier authenticates a raw webhook body against one Provider's signature
shape. ``verify`` returns ``None`` if the signature is valid and -- where the
shape carries a timestamp -- fresh within the replay window; otherwise it
raises :class:`VerificationError`.

``raw_body`` must be the exact bytes received. Never parse or re-serialize it
before verifying: JSON round-tripping reorders keys and normalizes whitespace,
and the HMAC is over bytes, not meaning.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

import httpx
from starlette.datastructures import Headers

from .config import Route

__all__ = [
    "ProviderFactory",
    "VerificationError",
    "Verifier",
    "VerifierDeps",
    "build_verifier",
    "known_providers",
    "register_provider",
]


class VerificationError(Exception):
    """A webhook failed verification.

    The message is part of a contract of sorts: the event emitter classifies
    rejections into a small taxonomy by matching on these strings, and the
    tests enumerate every one a verifier can produce, so changing the wording
    breaks a test rather than silently re-bucketing a rejection reason.
    """


@runtime_checkable
class Verifier(Protocol):
    """Authenticates a raw body against one Provider's signature shape."""

    def verify(self, raw_body: bytes, headers: Headers, now: datetime) -> None:
        """Raise :class:`VerificationError` if the request is not authentic."""
        ...


@dataclass(frozen=True, slots=True)
class VerifierDeps:
    """Shared, non-secret dependencies a provider factory may need beyond its
    own route config.

    Currently just the HTTP client PayPal uses to fetch its public certificate.
    Widen this rather than adding more positional arguments as providers grow.
    """

    client: httpx.Client


#: Builds a Verifier from an already-resolved secret and the shared deps.
ProviderFactory = Callable[[Route, str, VerifierDeps], Verifier]

_REGISTRY: dict[str, ProviderFactory] = {}


def register_provider(name: str) -> Callable[[ProviderFactory], ProviderFactory]:
    """Register a provider's factory under ``name``.

    Go did this from ``init()``; here each provider module calls it at import
    time and ``providers/__init__`` imports them all, so adding a provider is
    still one new file with no edit to this one.

    Raises:
        ValueError: on a duplicate name. That can only be a programming error
            -- two modules claiming the same provider -- and surfacing it at
            import time means it happens before any traffic.
    """

    def decorator(factory: ProviderFactory) -> ProviderFactory:
        if name in _REGISTRY:
            raise ValueError(f"duplicate provider registration: {name}")
        _REGISTRY[name] = factory
        return factory

    return decorator


def known_providers() -> frozenset[str]:
    """Every registered provider name. Used by tests and by config validation."""
    return frozenset(_REGISTRY)


def build_verifier(route: Route, secret: str, deps: VerifierDeps) -> Verifier:
    """Construct the Verifier for a Route from an already-resolved secret.

    Pure: no environment access and no I/O, so it stays unit-testable. The
    caller resolves the secret from the environment and passes it in. Dispatch
    is a registry lookup; each provider's factory validates its own required
    config.

    Raises:
        ValueError: unknown provider, or config that provider cannot use.
    """
    try:
        factory = _REGISTRY[route.provider]
    except KeyError:
        raise ValueError(f"unknown provider {route.provider!r}") from None
    return factory(route, secret, deps)
