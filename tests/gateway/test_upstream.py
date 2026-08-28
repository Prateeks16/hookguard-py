"""The sample protected application.

Small, but it is the demonstration the whole design rests on: an upstream
replaces four bespoke provider verifications with one Gateway-signature check.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from hookguard_core import gatewaysig
from hookguard_gateway.app import build_app
from hookguard_gateway.config import Config, Route
from hookguard_gateway.upstream import build_app as build_upstream

from .signers import github_header

SECRET = b"internal-upstream"
GITHUB_SECRET = "ghsecret"
BODY = b'{"ref":"refs/heads/main"}'


@pytest.fixture
def client() -> TestClient:
    return TestClient(build_upstream(SECRET))


def test_accepts_a_correctly_signed_request(client: TestClient) -> None:
    response = client.post(
        "/github",
        content=BODY,
        headers={
            gatewaysig.PROVIDER_HEADER: "github",
            gatewaysig.HEADER: gatewaysig.sign(SECRET, "github", BODY),
        },
    )
    assert response.status_code == 200


def test_rejects_an_unsigned_request(client: TestClient) -> None:
    """The upstream is on an internal network, but it trusts nothing on it."""
    assert client.post("/github", content=BODY).status_code == 401


@pytest.mark.parametrize(
    ("provider", "signature_provider", "body", "why"),
    [
        ("github", "github", BODY + b"x", "body tampered after signing"),
        ("github", "stripe", BODY, "provider relabelled"),
        ("github", "github", BODY, "signature from the wrong secret"),
    ],
)
def test_rejects_forgeries(
    client: TestClient, provider: str, signature_provider: str, body: bytes, why: str
) -> None:
    secret = SECRET if why != "signature from the wrong secret" else b"guessed"
    response = client.post(
        "/github",
        content=body,
        headers={
            gatewaysig.PROVIDER_HEADER: provider,
            gatewaysig.HEADER: gatewaysig.sign(secret, signature_provider, BODY),
        },
    )
    assert response.status_code == 401, why


def test_rejects_a_malformed_signature_header(client: TestClient) -> None:
    response = client.post(
        "/github",
        content=BODY,
        headers={gatewaysig.PROVIDER_HEADER: "github", gatewaysig.HEADER: "not-hex"},
    )
    assert response.status_code == 401


def test_gateway_and_upstream_interoperate() -> None:
    """The full path: a signed webhook through a real gateway into a real
    upstream, with only the shared INTERNAL_SECRET between them."""
    upstream_app = build_upstream(SECRET)
    gateway = build_app(
        Config(
            routes=[
                Route(
                    path="/hook/github",
                    provider="github",
                    upstream="http://upstream/github",
                    secret_env="GITHUB_SECRET",
                )
            ]
        ),
        internal_secret=SECRET,
        secret_lookup={"GITHUB_SECRET": GITHUB_SECRET}.get,
        client=httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream_app)),
    )

    with TestClient(gateway) as client:
        accepted = client.post(
            "/hook/github",
            content=BODY,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, BODY)},
        )
        rejected = client.post(
            "/hook/github",
            content=BODY,
            headers={"X-Hub-Signature-256": github_header("wrong-secret", BODY)},
        )

    assert accepted.status_code == 200
    assert accepted.text == "ok\n"
    assert rejected.status_code == 401


def test_a_mismatched_internal_secret_breaks_the_pair() -> None:
    """If the gateway and upstream disagree on INTERNAL_SECRET, every request
    fails closed rather than being waved through."""
    gateway = build_app(
        Config(
            routes=[
                Route(
                    path="/hook/github",
                    provider="github",
                    upstream="http://upstream/github",
                    secret_env="GITHUB_SECRET",
                )
            ]
        ),
        internal_secret=b"gateway-thinks-this",
        secret_lookup={"GITHUB_SECRET": GITHUB_SECRET}.get,
        client=httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_upstream(b"upstream-thinks-that"))
        ),
    )
    with TestClient(gateway) as client:
        response = client.post(
            "/hook/github",
            content=BODY,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, BODY)},
        )
    # The provider signature was fine, so the gateway forwarded; the upstream
    # is the one that refused.
    assert response.status_code == 401
