"""PayPal, ported from paypal_test.go.

PayPal is the only asymmetric provider and the only one with no oracle in the
differential harness -- neither language has an official library to diff
against -- so these tests are the whole safety net.
"""

from __future__ import annotations

import base64
import zlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from hookguard_gateway.config import Route
from hookguard_gateway.providers.paypal import (
    CERT_MAX_BYTES,
    PayPalVerifier,
    _CertCache,
    check_cert_host,
    parse_cert_chain,
    signed_message,
    verify_signature,
)
from hookguard_gateway.verifier import VerificationError, VerifierDeps, build_verifier

from .signers import headers

WEBHOOK_ID = "WH-TEST-123"
BODY = b'{"event_type":"PAYMENT.CAPTURE.COMPLETED"}'
TRANSMISSION_ID = "tx-1"
TRANSMISSION_TIME = "2026-08-29T12:00:00Z"
NOW = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_paypal(key: rsa.RSAPrivateKey, body: bytes, webhook_id: str = WEBHOOK_ID) -> str:
    message = signed_message(TRANSMISSION_ID, TRANSMISSION_TIME, webhook_id, body)
    return base64.b64encode(key.sign(message, padding.PKCS1v15(), hashes.SHA256())).decode()


# --------------------------------------------------------------------------
# The signed message and signature check
# --------------------------------------------------------------------------


def test_signed_message_shape() -> None:
    """id|time|webhookId|crc32, with the CRC as an unsigned decimal."""
    crc = zlib.crc32(BODY) & 0xFFFFFFFF
    assert signed_message(TRANSMISSION_ID, TRANSMISSION_TIME, WEBHOOK_ID, BODY) == (
        f"{TRANSMISSION_ID}|{TRANSMISSION_TIME}|{WEBHOOK_ID}|{crc}".encode()
    )


def test_crc32_is_unsigned() -> None:
    """Go's crc32.ChecksumIEEE is a uint32. A signed interpretation would emit
    a negative number for half of all bodies and break every such signature."""
    # A body whose CRC has the high bit set.
    body = b"\xff" * 7
    crc = int(signed_message("a", "b", "c", body).decode().rsplit("|", 1)[1])
    assert crc >= 0
    assert crc == zlib.crc32(body) & 0xFFFFFFFF


def test_signature_roundtrip(keypair: rsa.RSAPrivateKey) -> None:
    verify_signature(
        keypair.public_key(),
        TRANSMISSION_ID,
        TRANSMISSION_TIME,
        WEBHOOK_ID,
        BODY,
        sign_paypal(keypair, BODY),
    )


def test_signature_rejects_a_tampered_body(keypair: rsa.RSAPrivateKey) -> None:
    with pytest.raises(VerificationError, match="signature mismatch"):
        verify_signature(
            keypair.public_key(),
            TRANSMISSION_ID,
            TRANSMISSION_TIME,
            WEBHOOK_ID,
            BODY + b"x",
            sign_paypal(keypair, BODY),
        )


def test_signature_rejects_the_wrong_webhook_id(keypair: rsa.RSAPrivateKey) -> None:
    """The webhook ID is inside the signed message, so a signature minted for
    another subscription must not verify against ours."""
    with pytest.raises(VerificationError, match="signature mismatch"):
        verify_signature(
            keypair.public_key(),
            TRANSMISSION_ID,
            TRANSMISSION_TIME,
            WEBHOOK_ID,
            BODY,
            sign_paypal(keypair, BODY, webhook_id="WH-SOMEONE-ELSE"),
        )


def test_signature_rejects_another_key(keypair: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(VerificationError, match="signature mismatch"):
        verify_signature(
            keypair.public_key(),
            TRANSMISSION_ID,
            TRANSMISSION_TIME,
            WEBHOOK_ID,
            BODY,
            sign_paypal(other, BODY),
        )


@pytest.mark.parametrize("bad", ["not base64!!", "a", "===="])
def test_signature_rejects_malformed_base64(keypair: rsa.RSAPrivateKey, bad: str) -> None:
    with pytest.raises(VerificationError, match="invalid paypal-transmission-sig encoding"):
        verify_signature(
            keypair.public_key(), TRANSMISSION_ID, TRANSMISSION_TIME, WEBHOOK_ID, BODY, bad
        )


def test_empty_signature_is_a_mismatch_not_an_encoding_error(keypair: rsa.RSAPrivateKey) -> None:
    """ "" is valid base64 -- it decodes to zero bytes -- so it is rejected as a
    signature that does not match, not as one that failed to decode. Go's
    StdEncoding behaves the same way, and the distinction matters because the
    emitter buckets those two rejections differently."""
    with pytest.raises(VerificationError, match="signature mismatch"):
        verify_signature(
            keypair.public_key(), TRANSMISSION_ID, TRANSMISSION_TIME, WEBHOOK_ID, BODY, ""
        )


# --------------------------------------------------------------------------
# The cert-URL allowlist -- the control that stops a forged signature
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://api.paypal.com/cert.pem",
        "https://api.sandbox.paypal.com/v1/notifications/certs/x",
        "https://paypal.com/cert.pem",
        "https://PAYPAL.COM/cert.pem",  # case-insensitive host
    ],
)
def test_allowlist_accepts_paypal_hosts(url: str) -> None:
    check_cert_host(url)


@pytest.mark.parametrize(
    ("url", "why"),
    [
        ("https://evil.com/cert.pem", "unrelated host"),
        ("https://notpaypal.com/cert.pem", "suffix without the dot boundary"),
        ("https://paypal.com.evil.com/cert.pem", "domain as a prefix of another"),
        ("http://api.paypal.com/cert.pem", "plain http"),
        ("ftp://api.paypal.com/cert.pem", "non-http scheme"),
        ("https:///cert.pem", "no host"),
        ("", "empty"),
        ("not a url", "unparseable"),
    ],
)
def test_allowlist_rejects_everything_else(url: str, why: str) -> None:
    """paypal-cert-url is attacker-controlled. Without this check an attacker
    serves their own certificate and forges any signature."""
    with pytest.raises(VerificationError):
        check_cert_host(url)


def test_evil_cert_url_is_rejected_before_any_fetch(keypair: rsa.RSAPrivateKey) -> None:
    """The point is to never make the request, not to make it and then judge
    the response -- so the transport must never be called at all."""
    fetched: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        return httpx.Response(200, content=b"")

    verifier = PayPalVerifier(
        webhook_id=WEBHOOK_ID,
        client=httpx.Client(transport=httpx.MockTransport(record)),
    )
    h = headers(
        **{
            "paypal-transmission-id": TRANSMISSION_ID,
            "paypal-transmission-time": TRANSMISSION_TIME,
            "paypal-transmission-sig": sign_paypal(keypair, BODY),
            "paypal-cert-url": "https://evil.example/cert.pem",
            "paypal-auth-algo": "SHA256withRSA",
        }
    )
    with pytest.raises(VerificationError, match="not a trusted PayPal host"):
        verifier.verify(BODY, h, NOW)
    assert fetched == [], "no request may be made to a non-allowlisted host"


# --------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------


def _full_headers(keypair: rsa.RSAPrivateKey, **overrides: str) -> object:
    base = {
        "paypal-transmission-id": TRANSMISSION_ID,
        "paypal-transmission-time": TRANSMISSION_TIME,
        "paypal-transmission-sig": sign_paypal(keypair, BODY),
        "paypal-cert-url": "https://api.paypal.com/cert.pem",
        "paypal-auth-algo": "SHA256withRSA",
    }
    base.update(overrides)
    return headers(**{k: v for k, v in base.items() if v})


@pytest.mark.parametrize(
    "missing",
    [
        "paypal-transmission-id",
        "paypal-transmission-time",
        "paypal-transmission-sig",
        "paypal-cert-url",
    ],
)
def test_missing_headers_are_rejected(keypair: rsa.RSAPrivateKey, missing: str) -> None:
    verifier = PayPalVerifier(webhook_id=WEBHOOK_ID, client=httpx.Client())
    with pytest.raises(VerificationError, match="missing PayPal signature headers"):
        verifier.verify(BODY, _full_headers(keypair, **{missing: ""}), NOW)


@pytest.mark.parametrize("algo", ["SHA1withRSA", "none", "HS256"])
def test_unsupported_auth_algo_is_rejected(keypair: rsa.RSAPrivateKey, algo: str) -> None:
    """A downgrade to a weaker algorithm must be refused outright."""
    verifier = PayPalVerifier(webhook_id=WEBHOOK_ID, client=httpx.Client())
    with pytest.raises(VerificationError, match="unsupported paypal-auth-algo"):
        verifier.verify(BODY, _full_headers(keypair, **{"paypal-auth-algo": algo}), NOW)


def test_auth_algo_comparison_is_case_insensitive(keypair: rsa.RSAPrivateKey) -> None:
    """Matches Go's strings.EqualFold. Gets past the algo check and fails later
    on the cert fetch, which is what we assert."""
    verifier = PayPalVerifier(webhook_id=WEBHOOK_ID, client=httpx.Client())
    with pytest.raises(VerificationError) as excinfo:
        verifier.verify(BODY, _full_headers(keypair, **{"paypal-auth-algo": "sha256withrsa"}), NOW)
    assert "unsupported paypal-auth-algo" not in str(excinfo.value)


# --------------------------------------------------------------------------
# Certificate handling
# --------------------------------------------------------------------------


def _self_signed_pem(key: rsa.RSAPrivateKey) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.paypal.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("api.paypal.com")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_self_signed_certificate_is_rejected(keypair: rsa.RSAPrivateKey) -> None:
    """An attacker who got past the host allowlist still has to present a chain
    to a trusted root."""
    with pytest.raises(VerificationError, match="certificate chain"):
        parse_cert_chain(_self_signed_pem(keypair))


@pytest.mark.parametrize(
    "content", [b"", b"not a pem at all", b"-----BEGIN CERTIFICATE-----\ngarbage\n"]
)
def test_unparseable_cert_response_is_rejected(content: bytes) -> None:
    with pytest.raises(VerificationError):
        parse_cert_chain(content)


def test_cert_cache_returns_within_ttl(keypair: rsa.RSAPrivateKey) -> None:
    cache = _CertCache()
    cert = x509.load_pem_x509_certificates(_self_signed_pem(keypair))[0]
    url = "https://api.paypal.com/cert.pem"
    assert cache.get(url) is None
    cache.set(url, cert)
    assert cache.get(url) is cert


def test_cert_cache_expires(keypair: rsa.RSAPrivateKey) -> None:
    cache = _CertCache(ttl=timedelta(seconds=-1))  # already expired on insert
    cert = x509.load_pem_x509_certificates(_self_signed_pem(keypair))[0]
    cache.set("https://api.paypal.com/cert.pem", cert)
    assert cache.get("https://api.paypal.com/cert.pem") is None


def test_cert_cache_is_keyed_by_url(keypair: rsa.RSAPrivateKey) -> None:
    cache = _CertCache()
    cert = x509.load_pem_x509_certificates(_self_signed_pem(keypair))[0]
    cache.set("https://api.paypal.com/a.pem", cert)
    assert cache.get("https://api.paypal.com/b.pem") is None


def test_oversized_cert_response_is_truncated() -> None:
    """A hostile or broken response must not be buffered without bound. The
    truncated body then fails to parse, which is the correct outcome."""
    huge = b"-----BEGIN CERTIFICATE-----\n" + b"A" * (CERT_MAX_BYTES * 2)
    verifier = PayPalVerifier(
        webhook_id=WEBHOOK_ID,
        client=httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, content=huge))
        ),
    )
    with pytest.raises(VerificationError):
        verifier._cert("https://api.paypal.com/cert.pem")


def test_non_200_cert_response_is_rejected() -> None:
    verifier = PayPalVerifier(
        webhook_id=WEBHOOK_ID,
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))),
    )
    with pytest.raises(VerificationError, match="status 404"):
        verifier._cert("https://api.paypal.com/cert.pem")


# --------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------


def test_paypal_requires_a_webhook_id() -> None:
    deps = VerifierDeps(client=httpx.Client())
    with pytest.raises(ValueError, match="missing webhook_id"):
        build_verifier(Route(path="/hook/paypal", provider="paypal", upstream="http://u"), "", deps)


def test_paypal_takes_no_secret() -> None:
    """The webhook ID is config, not a secret, so an empty secret is fine."""
    deps = VerifierDeps(client=httpx.Client())
    verifier = build_verifier(
        Route(
            path="/hook/paypal",
            provider="paypal",
            upstream="http://u",
            webhook_id=WEBHOOK_ID,
        ),
        "",
        deps,
    )
    assert isinstance(verifier, PayPalVerifier)
