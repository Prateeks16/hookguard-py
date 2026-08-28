"""End-to-end gateway behaviour, ported from main_test.go.

These are the invariants the whole project rests on: the bytes are not touched,
the Gateway signature is attached and is unforgeable, and a rejected request
reaches nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from hookguard_core import gatewaysig
from hookguard_gateway.app import MAX_BODY_BYTES, build_app
from hookguard_gateway.config import Config, Route

from .signers import RecordingUpstream, github_header, stripe_header

INTERNAL = b"internal_e2e"
STRIPE_SECRET = "whsec_e2e"
GITHUB_SECRET = "ghsecret"


def _client(upstream: RecordingUpstream, routes: list[Route], **kw) -> TestClient:
    secrets = {"STRIPE_SECRET": STRIPE_SECRET, "GITHUB_SECRET": GITHUB_SECRET}
    app = build_app(
        Config(routes=routes),
        internal_secret=INTERNAL,
        secret_lookup=secrets.get,
        client=httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream)),
        **kw,
    )
    return TestClient(app)


STRIPE_ROUTE = Route(
    path="/hook/stripe",
    provider="stripe",
    upstream="http://upstream/stripe",
    replay_window="5m",
    secret_env="STRIPE_SECRET",
)
GITHUB_ROUTE = Route(
    path="/hook/github",
    provider="github",
    upstream="http://upstream/github",
    secret_env="GITHUB_SECRET",
)


def _now_ts() -> str:
    return str(int(datetime.now(UTC).timestamp()))


# --------------------------------------------------------------------------
# The raw-body invariant
# --------------------------------------------------------------------------


def test_raw_body_reaches_the_upstream_byte_for_byte(upstream: RecordingUpstream) -> None:
    """The payload is built to break naive JSON re-serialization: odd spacing,
    unsorted keys, a trailing-zero float, and a multi-byte character. If anyone
    adds a parse/re-encode to the forward path, this fails."""
    payload = '{ "b":1,"a":  100.00, "msg":"héllo 🚀" }'.encode()
    ts = _now_ts()

    with _client(upstream, [STRIPE_ROUTE]) as client:
        response = client.post(
            "/hook/stripe",
            content=payload,
            headers={"Stripe-Signature": stripe_header(STRIPE_SECRET, ts, payload)},
        )

    assert response.status_code == 200
    assert upstream.received_body == payload


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x00\x01\xff\xfe", b'{\n  "a": 1\n}\n', b"a" * 200_000],
    ids=["empty", "not-utf8", "newlines", "large"],
)
def test_body_shapes_survive_the_round_trip(upstream: RecordingUpstream, payload: bytes) -> None:
    with _client(upstream, [GITHUB_ROUTE]) as client:
        response = client.post(
            "/hook/github",
            content=payload,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, payload)},
        )
    assert response.status_code == 200
    assert upstream.received_body == payload


# --------------------------------------------------------------------------
# The trust boundary
# --------------------------------------------------------------------------


def test_verified_request_arrives_with_a_valid_gateway_signature(
    upstream: RecordingUpstream,
) -> None:
    payload = b'{"id":"evt_1"}'
    ts = _now_ts()

    with _client(upstream, [STRIPE_ROUTE]) as client:
        client.post(
            "/hook/stripe",
            content=payload,
            headers={"Stripe-Signature": stripe_header(STRIPE_SECRET, ts, payload)},
        )

    assert upstream.received_headers[gatewaysig.PROVIDER_HEADER.lower()] == "stripe"
    # The upstream's own check, performed here exactly as it would perform it.
    gatewaysig.verify(
        INTERNAL,
        "stripe",
        upstream.received_body,
        upstream.received_headers[gatewaysig.HEADER.lower()],
    )


def test_gateway_signature_binds_the_provider_name(upstream: RecordingUpstream) -> None:
    """An attacker who relabels a verified payload as another provider breaks
    the signature -- that is what makes the binding worth having."""
    payload = b'{"id":"evt_1"}'
    ts = _now_ts()

    with _client(upstream, [STRIPE_ROUTE]) as client:
        client.post(
            "/hook/stripe",
            content=payload,
            headers={"Stripe-Signature": stripe_header(STRIPE_SECRET, ts, payload)},
        )

    signature = upstream.received_headers[gatewaysig.HEADER.lower()]
    with pytest.raises(gatewaysig.GatewaySignatureError):
        gatewaysig.verify(INTERNAL, "github", payload, signature)


def test_an_attacker_without_the_internal_secret_cannot_forge_one() -> None:
    payload = b'{"id":"evt_1"}'
    forged = gatewaysig.sign(b"guessed-secret", "stripe", payload)
    with pytest.raises(gatewaysig.GatewaySignatureError):
        gatewaysig.verify(INTERNAL, "stripe", payload, forged)


# --------------------------------------------------------------------------
# Rejection
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "why"),
    [
        ({}, "no signature header at all"),
        ({"Stripe-Signature": "garbage"}, "malformed header"),
        ({"Stripe-Signature": "t=1,v1=" + "a" * 64}, "wrong signature and stale"),
    ],
)
def test_rejected_requests_never_reach_the_upstream(
    upstream: RecordingUpstream, headers: dict[str, str], why: str
) -> None:
    with _client(upstream, [STRIPE_ROUTE]) as client:
        response = client.post("/hook/stripe", content=b'{"id":"evt_1"}', headers=headers)

    assert response.status_code == 401, why
    assert upstream.calls == 0, "the upstream must not be contacted for a rejected request"


def test_tampered_body_is_rejected(upstream: RecordingUpstream) -> None:
    payload = b'{"id":"evt_1"}'
    ts = _now_ts()
    header = stripe_header(STRIPE_SECRET, ts, payload)

    with _client(upstream, [STRIPE_ROUTE]) as client:
        response = client.post(
            "/hook/stripe", content=payload + b"x", headers={"Stripe-Signature": header}
        )

    assert response.status_code == 401
    assert upstream.calls == 0


def test_rejection_does_not_disclose_which_check_failed(upstream: RecordingUpstream) -> None:
    """The response to a bad signature and a stale timestamp must be
    indistinguishable to the caller."""
    payload = b'{"id":"evt_1"}'
    with _client(upstream, [STRIPE_ROUTE]) as client:
        bad_sig = client.post(
            "/hook/stripe",
            content=payload,
            headers={"Stripe-Signature": stripe_header("wrong", _now_ts(), payload)},
        )
        stale = client.post(
            "/hook/stripe",
            content=payload,
            headers={"Stripe-Signature": stripe_header(STRIPE_SECRET, "1", payload)},
        )

    assert bad_sig.status_code == stale.status_code == 401
    assert bad_sig.text == stale.text


# --------------------------------------------------------------------------
# Limits and wiring
# --------------------------------------------------------------------------


def test_oversized_body_is_capped(upstream: RecordingUpstream) -> None:
    oversized = b"a" * (MAX_BODY_BYTES + 1)
    with _client(upstream, [GITHUB_ROUTE]) as client:
        response = client.post(
            "/hook/github",
            content=oversized,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, oversized)},
        )
    assert response.status_code == 413
    assert upstream.calls == 0


def test_upstream_status_is_passed_through(upstream: RecordingUpstream) -> None:
    upstream.status = 503
    upstream.body = b"upstream is unhappy\n"
    payload = b"{}"
    with _client(upstream, [GITHUB_ROUTE]) as client:
        response = client.post(
            "/hook/github",
            content=payload,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, payload)},
        )
    assert response.status_code == 503
    assert response.text == "upstream is unhappy\n"


def test_unreachable_upstream_is_a_502() -> None:
    """A dead upstream is a gateway error, not a crash -- and the client must
    not be told it was an authentication problem.

    httpx.ConnectError is what a refused connection actually raises, which is
    why the transport raises that rather than a bare OSError: the handler
    catches httpx.HTTPError, and a test that raised something else would be
    asserting against a failure mode production never produces.
    """

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    payload = b"{}"
    app = build_app(
        Config(routes=[GITHUB_ROUTE]),
        internal_secret=INTERNAL,
        secret_lookup={"GITHUB_SECRET": GITHUB_SECRET}.get,
        client=httpx.AsyncClient(transport=httpx.MockTransport(refuse)),
    )
    with TestClient(app) as client:
        response = client.post(
            "/hook/github",
            content=payload,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, payload)},
        )
    assert response.status_code == 502


def test_only_configured_paths_exist(upstream: RecordingUpstream) -> None:
    with _client(upstream, [STRIPE_ROUTE]) as client:
        assert client.post("/hook/github", content=b"{}").status_code == 404
        assert client.get("/healthz").status_code == 200


def test_get_is_not_allowed_on_a_hook(upstream: RecordingUpstream) -> None:
    with _client(upstream, [STRIPE_ROUTE]) as client:
        assert client.get("/hook/stripe").status_code == 405


def test_multiple_routes_are_independent(upstream: RecordingUpstream) -> None:
    payload = b"{}"
    with _client(upstream, [STRIPE_ROUTE, GITHUB_ROUTE]) as client:
        gh = client.post(
            "/hook/github",
            content=payload,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, payload)},
        )
        # The GitHub secret must not verify on the Stripe route.
        cross = client.post(
            "/hook/stripe",
            content=payload,
            headers={"X-Hub-Signature-256": github_header(GITHUB_SECRET, payload)},
        )
    assert gh.status_code == 200
    assert cross.status_code == 401


def test_a_broken_route_fails_at_construction() -> None:
    """A gateway that started with an unusable route would accept traffic on it
    and reject everything, which is worse than not starting."""
    with pytest.raises(SystemExit, match="unknown provider"):
        build_app(
            Config(routes=[Route(path="/x", provider="nope", upstream="http://u")]),
            internal_secret=INTERNAL,
            secret_lookup=lambda _: "",
        )

    with pytest.raises(SystemExit, match="empty secret"):
        build_app(
            Config(routes=[GITHUB_ROUTE]),
            internal_secret=INTERNAL,
            secret_lookup=lambda _: "",
        )
