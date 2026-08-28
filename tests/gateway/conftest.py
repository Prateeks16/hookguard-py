"""Fixtures for the gateway suite. Helpers live in signers.py."""

from __future__ import annotations

import httpx
import pytest

from hookguard_gateway.config import Config, Route

from .signers import RecordingUpstream


@pytest.fixture
def upstream() -> RecordingUpstream:
    return RecordingUpstream()


@pytest.fixture
def upstream_client(upstream: RecordingUpstream) -> httpx.AsyncClient:
    """A forward client wired straight to the upstream app, no sockets."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream))


def one_route_config(provider: str, **overrides: str) -> Config:
    route = Route(
        path="/hook/test",
        provider=provider,
        upstream="http://upstream/hook",
        **overrides,
    )
    return Config(routes=[route])
