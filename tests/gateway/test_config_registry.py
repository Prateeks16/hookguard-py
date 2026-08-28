"""Config loading and the provider registry, ported from verifier_test.go.

Includes the committed ``config*.json`` files, which are shared verbatim with
the Go implementation -- if the Python reader cannot load them, the two are not
actually interoperable regardless of what the signature tests say.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from hookguard_gateway.config import Config, Route, config_path, load_config
from hookguard_gateway.providers.github import GitHubVerifier
from hookguard_gateway.providers.shopify import ShopifyVerifier
from hookguard_gateway.providers.stripe import StripeVerifier
from hookguard_gateway.verifier import (
    VerifierDeps,
    build_verifier,
    known_providers,
    register_provider,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def deps() -> VerifierDeps:
    return VerifierDeps(client=httpx.Client())


# --------------------------------------------------------------------------
# The committed config files
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["config.json", "config.docker.json", "config.fly.json"])
def test_shipped_config_files_load(name: str) -> None:
    """These files came over from the Go repo unchanged and are mounted into
    the running container. A schema drift here breaks deployment, not a test."""
    config = load_config(REPO_ROOT / name)
    assert config.routes, f"{name} has no routes"
    for route in config.routes:
        assert route.provider in known_providers(), f"{name}: unknown provider"
        assert route.path.startswith("/")
        assert route.upstream


def test_shipped_configs_build_real_verifiers(deps: VerifierDeps) -> None:
    """Every route in the shipped config must actually construct."""
    config = load_config(REPO_ROOT / "config.json")
    for route in config.routes:
        build_verifier(route, "a-secret", deps)


def test_config_json_still_matches_the_go_repos_copy() -> None:
    """Parsed equality, not byte equality: the file is a shared contract, and a
    field added on one side would silently be ignored on the other."""
    ours = json.loads((REPO_ROOT / "config.json").read_text(encoding="utf-8"))
    assert set(ours) == {"routes"}
    for route in ours["routes"]:
        assert set(route) <= {
            "path",
            "provider",
            "upstream",
            "replay_window",
            "secret_env",
            "webhook_id",
        }


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        load_config(tmp_path / "nope.json")


def test_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(path)


def test_unknown_field_is_rejected(tmp_path: Path) -> None:
    """A typo'd field would otherwise fall back to a default silently -- and
    for replay_window that means quietly disabling the replay check."""
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "routes": [
                    {
                        "path": "/hook/stripe",
                        "provider": "stripe",
                        "upstream": "http://u",
                        "replay_windwo": "5m",  # typo
                        "secret_env": "S",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_config(path)


def test_empty_routes_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"routes": []}', encoding="utf-8")
    assert load_config(path).routes == []


def test_config_path_prefers_the_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONFIG_PATH", raising=False)
    assert config_path() == "config.json"
    monkeypatch.setenv("CONFIG_PATH", "/etc/hookguard/routes.json")
    assert config_path() == "/etc/hookguard/routes.json"


def test_empty_config_path_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """An env var set to the empty string is unset, not a path to "" -- Go's
    os.Getenv check behaves the same way."""
    monkeypatch.setenv("CONFIG_PATH", "")
    assert config_path() == "config.json"


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------


def test_all_four_providers_are_registered() -> None:
    assert known_providers() == {"stripe", "github", "shopify", "paypal"}


@pytest.mark.parametrize(
    ("provider", "expected"),
    [("stripe", StripeVerifier), ("github", GitHubVerifier), ("shopify", ShopifyVerifier)],
)
def test_build_dispatches_by_provider(provider: str, expected: type, deps: VerifierDeps) -> None:
    route = Route(path=f"/hook/{provider}", provider=provider, upstream="http://u", secret_env="S")
    assert isinstance(build_verifier(route, "secret", deps), expected)


def test_unknown_provider_is_an_error(deps: VerifierDeps) -> None:
    route = Route(path="/hook/x", provider="nope", upstream="http://u")
    with pytest.raises(ValueError, match="unknown provider 'nope'"):
        build_verifier(route, "secret", deps)


@pytest.mark.parametrize("provider", ["stripe", "github", "shopify"])
def test_hmac_providers_require_a_secret(provider: str, deps: VerifierDeps) -> None:
    route = Route(path="/h", provider=provider, upstream="http://u", secret_env="S")
    with pytest.raises(ValueError, match="empty secret"):
        build_verifier(route, "", deps)


def test_stripe_rejects_an_unparseable_replay_window(deps: VerifierDeps) -> None:
    """The failure that would otherwise be silent: an unparseable window must
    stop the gateway starting, not default to no replay check."""
    route = Route(
        path="/hook/stripe",
        provider="stripe",
        upstream="http://u",
        secret_env="S",
        replay_window="5 minutes",
    )
    with pytest.raises(ValueError, match="replay_window"):
        build_verifier(route, "secret", deps)


def test_stripe_accepts_go_duration_syntax(deps: VerifierDeps) -> None:
    for window in ["5m", "1h30m", "300s", "0"]:
        route = Route(
            path="/hook/stripe",
            provider="stripe",
            upstream="http://u",
            secret_env="S",
            replay_window=window,
        )
        build_verifier(route, "secret", deps)


def test_duplicate_registration_is_refused() -> None:
    """Two modules claiming one provider can only be a programming error, and
    it surfaces at import time rather than at traffic time."""
    with pytest.raises(ValueError, match="duplicate provider registration"):
        register_provider("stripe")(lambda r, s, d: None)


def test_config_round_trips_through_json() -> None:
    """The Console exports this same shape back out, so it has to survive the
    trip in both directions."""
    original = Config(
        routes=[
            Route(
                path="/hook/stripe",
                provider="stripe",
                upstream="http://app:8080/stripe",
                replay_window="5m",
                secret_env="STRIPE_SECRET",
            )
        ]
    )
    assert Config.model_validate(json.loads(original.model_dump_json())) == original
