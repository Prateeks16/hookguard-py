"""The three HMAC providers, ported from stripe_test.go, github_test.go and
shopify_test.go."""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta

import pytest

from hookguard_gateway.providers.github import GitHubVerifier
from hookguard_gateway.providers.shopify import ShopifyVerifier
from hookguard_gateway.providers.stripe import StripeVerifier
from hookguard_gateway.verifier import VerificationError

from .signers import github_header, headers, shopify_header, stripe_header

SECRET = "whsec_test"
BODY = b'{"id":"evt_1","amount":4242}'
NOW = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------
# Stripe
# --------------------------------------------------------------------------


def _stripe(window: timedelta = timedelta(minutes=5)) -> StripeVerifier:
    return StripeVerifier(secret=SECRET.encode(), replay_window=window)


def test_stripe_accepts_a_valid_signature() -> None:
    ts = str(int(NOW.timestamp()))
    h = headers(**{"Stripe-Signature": stripe_header(SECRET, ts, BODY)})
    _stripe().verify(BODY, h, NOW)


def test_stripe_rejects_a_tampered_body() -> None:
    ts = str(int(NOW.timestamp()))
    h = headers(**{"Stripe-Signature": stripe_header(SECRET, ts, BODY)})
    with pytest.raises(VerificationError, match="no matching signature"):
        _stripe().verify(BODY + b" ", h, NOW)


def test_stripe_rejects_the_wrong_secret() -> None:
    ts = str(int(NOW.timestamp()))
    h = headers(**{"Stripe-Signature": stripe_header("other", ts, BODY)})
    with pytest.raises(VerificationError, match="no matching signature"):
        _stripe().verify(BODY, h, NOW)


def test_stripe_rejects_a_stale_timestamp() -> None:
    """Valid HMAC, but outside the window -- the replay check must still fail
    it. This is the case a signature-only verifier would wave through."""
    stale = NOW - timedelta(minutes=10)
    ts = str(int(stale.timestamp()))
    h = headers(**{"Stripe-Signature": stripe_header(SECRET, ts, BODY)})
    with pytest.raises(VerificationError, match="outside replay window"):
        _stripe().verify(BODY, h, NOW)


def test_stripe_rejects_a_future_timestamp_beyond_the_window() -> None:
    """The window is absolute, not one-sided: a clock-skewed or replayed future
    timestamp is as unacceptable as a stale one."""
    ahead = NOW + timedelta(minutes=10)
    ts = str(int(ahead.timestamp()))
    h = headers(**{"Stripe-Signature": stripe_header(SECRET, ts, BODY)})
    with pytest.raises(VerificationError, match="outside replay window"):
        _stripe().verify(BODY, h, NOW)


def test_stripe_zero_window_disables_the_replay_check() -> None:
    ancient = NOW - timedelta(days=400)
    ts = str(int(ancient.timestamp()))
    h = headers(**{"Stripe-Signature": stripe_header(SECRET, ts, BODY)})
    _stripe(window=timedelta(0)).verify(BODY, h, NOW)


def test_stripe_accepts_any_of_several_v1_signatures() -> None:
    """Stripe sends more than one v1 during a secret rotation; one match is a
    pass."""
    ts = str(int(NOW.timestamp()))
    good = stripe_header(SECRET, ts, BODY).split("v1=")[1]
    h = headers(**{"Stripe-Signature": f"t={ts},v1={'0' * 64},v1={good}"})
    _stripe().verify(BODY, h, NOW)


def test_stripe_ignores_unknown_scheme_versions() -> None:
    ts = str(int(NOW.timestamp()))
    good = stripe_header(SECRET, ts, BODY).split("v1=")[1]
    h = headers(**{"Stripe-Signature": f"t={ts},v0=deadbeef,v1={good}"})
    _stripe().verify(BODY, h, NOW)


@pytest.mark.parametrize(
    ("header", "match"),
    [
        ("", "missing"),
        ("garbage", "malformed"),
        ("v1=abcd", "malformed"),  # no timestamp
        ("t=123", "malformed"),  # no signature
        ("t=notanumber,v1=" + "a" * 64, "invalid timestamp"),
    ],
)
def test_stripe_rejects_malformed_headers(header: str, match: str) -> None:
    h = headers(**{"Stripe-Signature": header}) if header else headers()
    with pytest.raises(VerificationError, match=match):
        _stripe().verify(BODY, h, NOW)


def test_stripe_rejects_non_hex_signature() -> None:
    ts = str(int(NOW.timestamp()))
    h = headers(**{"Stripe-Signature": f"t={ts},v1=zzzz"})
    with pytest.raises(VerificationError, match="no matching signature"):
        _stripe().verify(BODY, h, NOW)


# --------------------------------------------------------------------------
# GitHub
# --------------------------------------------------------------------------


def test_github_accepts_a_valid_signature() -> None:
    h = headers(**{"X-Hub-Signature-256": github_header(SECRET, BODY)})
    GitHubVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


def test_github_rejects_a_tampered_body() -> None:
    h = headers(**{"X-Hub-Signature-256": github_header(SECRET, BODY)})
    with pytest.raises(VerificationError, match="signature mismatch"):
        GitHubVerifier(secret=SECRET.encode()).verify(b"{}", h, NOW)


def test_github_rejects_the_wrong_secret() -> None:
    h = headers(**{"X-Hub-Signature-256": github_header("other", BODY)})
    with pytest.raises(VerificationError, match="signature mismatch"):
        GitHubVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


@pytest.mark.parametrize(
    ("header", "match"),
    [
        ("", "missing"),
        ("sha1=" + "a" * 40, "malformed"),  # the older, weaker header GitHub also sends
        ("a" * 64, "malformed"),  # no prefix
        ("sha256=nothex", "invalid signature encoding"),
        ("sha256=abc", "invalid signature encoding"),  # odd length
    ],
)
def test_github_rejects_malformed_headers(header: str, match: str) -> None:
    h = headers(**{"X-Hub-Signature-256": header}) if header else headers()
    with pytest.raises(VerificationError, match=match):
        GitHubVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


def test_github_rejects_hex_with_embedded_whitespace() -> None:
    """bytes.fromhex would accept this; Go's hex.DecodeString does not, and a
    verdict divergence on a signature path is exactly what the differential
    harness exists to catch."""
    digest = hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest()
    spaced = digest[:2] + " " + digest[2:]
    h = headers(**{"X-Hub-Signature-256": "sha256=" + spaced})
    with pytest.raises(VerificationError, match="invalid signature encoding"):
        GitHubVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


# --------------------------------------------------------------------------
# Shopify
# --------------------------------------------------------------------------


def test_shopify_accepts_a_valid_signature() -> None:
    h = headers(**{"X-Shopify-Hmac-SHA256": shopify_header(SECRET, BODY)})
    ShopifyVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


def test_shopify_rejects_a_tampered_body() -> None:
    h = headers(**{"X-Shopify-Hmac-SHA256": shopify_header(SECRET, BODY)})
    with pytest.raises(VerificationError, match="signature mismatch"):
        ShopifyVerifier(secret=SECRET.encode()).verify(b"{}", h, NOW)


def test_shopify_rejects_the_wrong_secret() -> None:
    h = headers(**{"X-Shopify-Hmac-SHA256": shopify_header("other", BODY)})
    with pytest.raises(VerificationError, match="signature mismatch"):
        ShopifyVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


def test_shopify_rejects_hex_where_base64_is_expected() -> None:
    """The one twist versus Stripe and GitHub. A hex digest is valid base64
    characters, so this decodes to the wrong bytes rather than erroring -- and
    must still be rejected."""
    digest = hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest()
    h = headers(**{"X-Shopify-Hmac-SHA256": digest})
    with pytest.raises(VerificationError, match="signature mismatch"):
        ShopifyVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


@pytest.mark.parametrize(
    ("header", "match"),
    [
        ("", "missing"),
        ("!!!not base64!!!", "invalid signature encoding"),
        ("short", "invalid signature encoding"),
    ],
)
def test_shopify_rejects_malformed_headers(header: str, match: str) -> None:
    h = headers(**{"X-Shopify-Hmac-SHA256": header}) if header else headers()
    with pytest.raises(VerificationError, match=match):
        ShopifyVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


# --------------------------------------------------------------------------
# Shared invariants
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b'{"note":"thanks \xf0\x9f\x9a\x80"}',  # multi-byte UTF-8
        b"\x00\x01\xff\xfe",  # not valid UTF-8 at all
        b'{\n  "a": 1\n}\n',
        b"a" * 100_000,
    ],
    ids=["empty", "emoji", "not-utf8", "newlines", "large"],
)
def test_every_provider_hashes_raw_bytes(body: bytes) -> None:
    """Verification is over bytes, not text. A body that is not valid UTF-8
    must verify as readily as one that is -- decoding anywhere in the path
    would break these."""
    ts = str(int(NOW.timestamp()))
    StripeVerifier(secret=SECRET.encode(), replay_window=timedelta(minutes=5)).verify(
        body, headers(**{"Stripe-Signature": stripe_header(SECRET, ts, body)}), NOW
    )
    GitHubVerifier(secret=SECRET.encode()).verify(
        body, headers(**{"X-Hub-Signature-256": github_header(SECRET, body)}), NOW
    )
    ShopifyVerifier(secret=SECRET.encode()).verify(
        body, headers(**{"X-Shopify-Hmac-SHA256": shopify_header(SECRET, body)}), NOW
    )


def test_header_lookup_is_case_insensitive() -> None:
    """Providers send inconsistent casing and HTTP/2 lowercases everything."""
    h = headers(**{"x-hub-signature-256": github_header(SECRET, BODY)})
    GitHubVerifier(secret=SECRET.encode()).verify(BODY, h, NOW)


def test_shopify_signature_is_base64_of_the_digest_not_of_the_hex() -> None:
    """Pins the encoding itself, independent of our own helper."""
    expected = base64.b64encode(hmac.new(SECRET.encode(), BODY, hashlib.sha256).digest()).decode()
    assert shopify_header(SECRET, BODY) == expected
