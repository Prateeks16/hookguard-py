"""The Python leg of the three-way differential harness.

This file and ``oracle/verifier/differential_test.go`` read the SAME committed
vector file and assert against the SAME expected column. Neither suite talks to
the other; agreement between the two implementations is transitive through the
file rather than coordinated at runtime.

Three legs, in decreasing coverage:

1. **Cross-language.** Every vector, both implementations, same expected
   verdict. This is the leg that covers Shopify and the replay window.
2. **Vendor oracle, Python.** ``stripe.WebhookSignature.verify_header`` judges
   the Stripe vectors independently.
3. **Vendor oracle, Go.** ``go-github`` judges the GitHub vectors, and
   ``stripe-go`` the Stripe ones, in the Go suite. PyGithub has no
   signature-verification helper, so this leg is why ``oracle/`` is kept.

Shopify has no official library in **either** language -- the Python SDK's
``validate_hmac`` is for OAuth query parameters, a different algorithm from
webhook body verification -- so its vectors carry oracle ``none`` and rest on
leg 1 alone. That is the same honest caveat the original Go report carried; the
port neither improves nor worsens it.

PayPal is outside the harness entirely, in both languages, as it was in Go.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import stripe
from starlette.datastructures import Headers

from hookguard_gateway.config import Route
from hookguard_gateway.verifier import VerificationError, VerifierDeps, build_verifier

pytestmark = pytest.mark.differential

VECTOR_PATH = Path(__file__).resolve().parents[1] / "vectors" / "signatures.json"
VECTORS: dict[str, Any] = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
CASES: list[dict[str, Any]] = VECTORS["vectors"]

#: Which oracle names this suite knows how to run. A vector carrying anything
#: else fails rather than being skipped -- see test_every_oracle_is_recognized.
KNOWN_ORACLES = {"stripe", "go-github", "none"}


def _verdict(case: dict[str, Any]) -> bool:
    """Run one vector through the Python implementation."""
    route = Route(
        path=f"/hook/{case['provider']}",
        provider=case["provider"],
        upstream="http://upstream",
        replay_window=case["replay_window"],
        secret_env="UNUSED" if case["provider"] != "paypal" else "",
        webhook_id="unused" if case["provider"] == "paypal" else "",
    )
    verifier = build_verifier(route, case["secret"], VerifierDeps(client=httpx.Client()))
    now = datetime.fromtimestamp(case["now_unix"], tz=UTC)
    try:
        verifier.verify(base64.b64decode(case["body_b64"]), Headers(case["headers"]), now)
    except VerificationError:
        return False
    return True


def _ids(cases: list[dict[str, Any]]) -> list[str]:
    return [c["name"] for c in cases]


# --------------------------------------------------------------------------
# Leg 1: cross-language
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_verdict_matches_the_expected_column(case: dict[str, Any]) -> None:
    """The Go suite asserts this same thing against this same file, which is
    what pins the two implementations to each other."""
    assert _verdict(case) is case["expected"], (
        f"{case['name']}: this implementation disagrees with the vector file"
    )


# --------------------------------------------------------------------------
# Leg 2: the vendor oracle available in Python
# --------------------------------------------------------------------------

STRIPE_CASES = [c for c in CASES if c["oracle"] == "stripe" and not c["time_sensitive"]]


def _stripe_oracle(case: dict[str, Any]) -> bool | None:
    """Stripe's own verdict, or ``None`` where the library cannot form one.

    ``tolerance=None`` makes this signature-only, matching the Go leg's
    ``ValidatePayloadIgnoringTolerance``: both vendor legs ask the same
    question, and the replay window is covered by leg 1 instead. Deliberately
    not the event-construction API -- that also deserializes the body, so it
    would reject an empty payload for reasons unrelated to signatures.

    The ``None`` case is real, not defensive: the library does
    ``payload.decode("utf-8")`` before verifying, so a body that is not valid
    UTF-8 raises UnicodeDecodeError rather than producing a verdict. Catching
    that as "rejects" would be wrong -- the library has no opinion, and
    recording one for it would manufacture a disagreement with stripe-go, which
    HMACs the raw bytes and accepts.
    """
    body = base64.b64decode(case["body_b64"])
    header = case["headers"].get("Stripe-Signature")
    try:
        stripe.WebhookSignature.verify_header(body, header, case["secret"], tolerance=None)
    except UnicodeDecodeError:
        return None
    except (stripe.SignatureVerificationError, ValueError):
        return False
    return True


@pytest.mark.parametrize("case", STRIPE_CASES, ids=_ids(STRIPE_CASES))
def test_stripe_official_library_agrees(case: dict[str, Any]) -> None:
    """Stripe's own library must return the same verdict we do, wherever it can
    form one."""
    oracle = _stripe_oracle(case)
    ours = _verdict(case)
    if oracle is None:
        pytest.skip("the Python library cannot verify this body; see the non-UTF-8 test")
    assert ours == oracle, f"{case['name']}: ours={ours} stripe={oracle} -- verdicts must agree"
    assert ours is case["expected"]


def test_the_python_oracle_only_abstains_where_expected() -> None:
    """Pins the exact set of cases Stripe's Python library cannot judge.

    Today that is precisely the non-UTF-8 body: the library decodes the payload
    before verifying, so it cannot verify a body it cannot decode -- a stricter
    reading than the protocol, since the signature is over bytes. Our verdict
    there is corroborated by stripe-go, which accepts it, and by the
    cross-language leg.

    If Stripe fixes this, or the limitation spreads, this test fails and the
    exclusion gets revisited rather than quietly widening.
    """
    abstained = {c["name"] for c in STRIPE_CASES if _stripe_oracle(c) is None}
    assert abstained == {"stripe/valid non-utf8 body"}, (
        f"the set of cases the Python oracle cannot judge changed: {abstained}"
    )


# --------------------------------------------------------------------------
# Guards: a harness that quietly stops testing is worse than none
# --------------------------------------------------------------------------


def test_vector_file_is_populated() -> None:
    assert len(CASES) >= 40, "vector file looks truncated"


def test_both_verdicts_are_well_represented() -> None:
    """A file of nothing but valid signatures would pass against a verifier
    that accepted unconditionally."""
    accepted = sum(1 for c in CASES if c["expected"])
    rejected = len(CASES) - accepted
    assert accepted >= 5 and rejected >= 5, f"accept={accepted} reject={rejected}"


def test_every_provider_is_covered() -> None:
    covered = {c["provider"] for c in CASES}
    assert {"stripe", "github", "shopify"} <= covered


def test_every_oracle_is_recognized() -> None:
    """A vector added with an oracle this suite does not know must break the
    build, not silently lose its vendor leg."""
    for case in CASES:
        assert case["oracle"] in KNOWN_ORACLES, (
            f"{case['name']}: unrecognized oracle {case['oracle']!r} -- update this file"
        )


def test_the_stripe_oracle_leg_actually_runs() -> None:
    """Guards against the parametrization silently emptying out."""
    assert len(STRIPE_CASES) >= 10


def test_shopify_has_no_vendor_oracle_and_says_so() -> None:
    """Documents the honest gap rather than leaving it implicit: if an official
    Python or Go Shopify webhook verifier ever appears, this test should fail
    and the vectors be upgraded to use it."""
    shopify_cases = [c for c in CASES if c["provider"] == "shopify"]
    assert shopify_cases
    assert all(c["oracle"] == "none" for c in shopify_cases)


def test_time_sensitive_cases_are_covered_by_the_cross_language_leg() -> None:
    """The replay-window vectors are excluded from the vendor legs because the
    official libraries read the system clock. They must still be present, and
    leg 1 must still assert them."""
    time_sensitive = [c for c in CASES if c["time_sensitive"]]
    assert time_sensitive, "no replay-window vectors; the window is then untested here"
    for case in time_sensitive:
        assert case["expected"] is False
        assert _verdict(case) is False
