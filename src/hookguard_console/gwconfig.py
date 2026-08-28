"""Conversion between Console endpoint rows and the Gateway's config.json.

An exported file must be byte-for-byte the schema the Gateway's loader already
reads, because that is the whole point: an operator edits endpoints in the
Console and hands the result to the Gateway.

Unlike the Go implementation, this reuses the Gateway's own ``Route`` model
rather than redeclaring it. Go had to duplicate the struct -- the two lived in
separate modules and the registry's rules were unexported -- and left a comment
warning that the copies must be kept in sync by hand. Here the ``console``
extra already installs the gateway package, so the shapes cannot drift.
"""

from __future__ import annotations

import json
from typing import Any

from hookguard_core.goduration import GoDurationError, parse_go_duration
from hookguard_gateway.config import Config, Route
from hookguard_gateway.verifier import known_providers

from .store import Endpoint

__all__ = [
    "ConfigValidationError",
    "export",
    "from_endpoint",
    "import_config",
    "marshal",
    "to_endpoint",
    "validate",
]

#: Providers whose secret comes from an environment variable. PayPal is the
#: exception: its webhook id is configuration, not a secret.
_SECRET_ENV_PROVIDERS = frozenset({"stripe", "github", "shopify"})


class ConfigValidationError(ValueError):
    """A route the Gateway could not build a verifier for."""


def from_endpoint(endpoint: Endpoint) -> Route:
    """One database row as the Gateway sees it."""
    return Route(
        path=endpoint.path,
        provider=endpoint.provider,
        upstream=endpoint.upstream_url,
        replay_window=endpoint.replay_window,
        secret_env=endpoint.secret_env,
        webhook_id=endpoint.webhook_id,
    )


def to_endpoint(route: Route) -> Endpoint:
    """A route as a row shell. Id and timestamps are the caller's to fill in
    at insert time."""
    return Endpoint(
        path=route.path,
        provider=route.provider,
        upstream_url=route.upstream,
        replay_window=route.replay_window,
        secret_env=route.secret_env,
        webhook_id=route.webhook_id,
        active=True,
    )


def export(endpoints: list[Endpoint]) -> Config:
    """Serialize endpoints to the Gateway's config shape.

    Callers pass ``list_active_endpoints()``: ordering and the active filter
    are the store's job, so an exported file is stable between runs.
    """
    return Config(routes=[from_endpoint(e) for e in endpoints])


def marshal(config: Config) -> str:
    """Render as JSON, matching the repository's own config.json formatting.

    Two-space indent, and ``webhook_id`` omitted when empty -- Go's struct tag
    carries ``omitempty``, and an exported file that differed from a
    hand-written one would be a confusing diff for no reason.
    """
    routes: list[dict[str, Any]] = []
    for route in config.routes:
        item: dict[str, Any] = {
            "path": route.path,
            "provider": route.provider,
            "upstream": route.upstream,
            "replay_window": route.replay_window,
            "secret_env": route.secret_env,
        }
        if route.webhook_id:
            item["webhook_id"] = route.webhook_id
        routes.append(item)
    return json.dumps({"routes": routes}, indent=2) + "\n"


def validate(route: Route) -> None:
    """Apply the same per-provider rules the Gateway's factories apply.

    Kept here rather than inferred from the gateway, because the factories
    need a resolved secret and this runs against config alone. A malformed
    import fails loudly here instead of producing a row the database's CHECK
    constraint would reject with a much less useful message.

    Raises:
        ConfigValidationError: on anything the Gateway could not build.
    """
    if not route.path:
        raise ConfigValidationError("path is required")
    if not route.upstream:
        raise ConfigValidationError("upstream is required")

    if route.provider == "paypal":
        if not route.webhook_id:
            raise ConfigValidationError("paypal requires webhook_id")
        if route.secret_env:
            raise ConfigValidationError("paypal must not set secret_env")
    elif route.provider in _SECRET_ENV_PROVIDERS:
        if not route.secret_env:
            raise ConfigValidationError(f"{route.provider} requires secret_env")
        if route.webhook_id:
            raise ConfigValidationError(f"{route.provider} must not set webhook_id")
        if route.provider == "stripe" and route.replay_window:
            try:
                parse_go_duration(route.replay_window)
            except GoDurationError as e:
                raise ConfigValidationError(f"replay_window: {e}") from e
    else:
        raise ConfigValidationError(f"unknown provider {route.provider!r}")

    # Cheap guard against this file and the gateway's registry drifting apart:
    # a provider handled above but no longer registered would otherwise pass
    # validation and then fail at gateway startup.
    if route.provider not in known_providers():
        raise ConfigValidationError(f"provider {route.provider!r} is not registered")


def import_config(data: bytes | str) -> list[Endpoint]:
    """Parse a config.json-shaped file into row shells, ready for insertion.

    Every route is validated, so a bad file is rejected as a whole rather than
    half-imported.
    """
    try:
        config = Config.model_validate(json.loads(data))
    except (json.JSONDecodeError, ValueError) as e:
        raise ConfigValidationError(f"parse config: {e}") from e

    endpoints = []
    for i, route in enumerate(config.routes):
        try:
            validate(route)
        except ConfigValidationError as e:
            raise ConfigValidationError(f"route {i} ({route.path}): {e}") from e
        endpoints.append(to_endpoint(route))
    return endpoints
