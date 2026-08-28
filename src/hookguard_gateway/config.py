"""The Gateway's routing table.

A Route binds an inbound path to one Provider verifier, an Upstream URL, a
replay window, and the name of the environment variable holding that
Provider's secret -- never the secret itself, so the config file stays
committable.

The JSON shape is unchanged from the Go implementation and is read by the
Console's export as well, so field names here are contract. The committed
``config*.json`` files are used as-is.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["Config", "Route", "config_path", "load_config"]


class Route(BaseModel):
    """One inbound path and everything needed to verify and forward it."""

    # Reject unknown keys rather than ignoring them: a typo'd field in a
    # hand-edited config would otherwise silently fall back to a default, and
    # for `replay_window` that means silently disabling the replay check.
    model_config = ConfigDict(extra="forbid")

    path: str
    provider: str
    upstream: str

    #: Go duration syntax ("5m"); "" means no replay check. Parsed by the
    #: provider that needs it, not here, so an unused window on a provider
    #: without timestamps is not silently accepted as meaningful.
    replay_window: str = ""

    #: The NAME of the env var holding the secret, never the secret.
    secret_env: str = ""

    #: PayPal only: the webhook subscription ID. Config, not a secret.
    webhook_id: str = ""


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    routes: list[Route] = Field(default_factory=list)


def load_config(path: str | os.PathLike[str]) -> Config:
    """Read and validate the routing table.

    Raises:
        OSError: the file cannot be read.
        ValueError: the file is not valid JSON, or does not match the schema.
    """
    raw = Path(path).read_text(encoding="utf-8")
    return Config.model_validate(json.loads(raw))


def config_path() -> str:
    """``CONFIG_PATH`` when set, else ``config.json`` in the working directory.

    Compose mounts a routing table over ``/config.json``, so the default covers
    the shipped deployment; the env var exists for running the gateway directly
    against a config file elsewhere.
    """
    return os.getenv("CONFIG_PATH") or "config.json"
