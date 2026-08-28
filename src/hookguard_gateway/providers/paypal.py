"""PayPal's signature shape.

Asymmetric, unlike every other supported provider: RSA-SHA256 over
``"transmissionId|transmissionTime|webhookId|crc32(body)"``, verified against a
certificate PayPal serves at the URL in the ``paypal-cert-url`` header. The
webhook ID identifies the configured subscription -- it is config, not a
secret, which is why this provider takes no ``secret_env``.

Security note, and the reason this file is the most careful in the package:
``paypal-cert-url`` is attacker-controlled input. Without the host allowlist
below, an attacker supplies a URL to their own certificate and forges any
signature this verifier would then accept. PayPal is also the one provider with
no oracle in the differential harness -- neither language has an official
library to diff against -- so nothing downstream will catch a mistake here.
"""

from __future__ import annotations

import base64
import binascii
import functools
import threading
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import certifi
import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.verification import PolicyBuilder, Store

from ..config import Route
from ..verifier import VerificationError, Verifier, VerifierDeps, register_provider

__all__ = ["PayPalVerifier", "check_cert_host", "signed_message"]

AUTH_ALGO = "SHA256withRSA"
CERT_TTL = timedelta(hours=1)

#: PayPal's certificates are a few KB; cap well above that so a hostile or
#: broken response cannot ask us to buffer without bound.
CERT_MAX_BYTES = 1 << 20

#: Which hosts we will ever fetch a certificate from. See the module docstring.
CERT_HOST_ALLOWLIST = ("paypal.com",)


@register_provider("paypal")
def _build(route: Route, _secret: str, deps: VerifierDeps) -> Verifier:
    if not route.webhook_id:
        raise ValueError("missing webhook_id")
    return PayPalVerifier(webhook_id=route.webhook_id, client=deps.client)


def signed_message(
    transmission_id: str, transmission_time: str, webhook_id: str, body: bytes
) -> bytes:
    """Build PayPal's signed message.

    The transmission id, its time, the configured webhook ID, and an unsigned
    decimal CRC32 of the raw body, joined by ``|``.
    """
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return f"{transmission_id}|{transmission_time}|{webhook_id}|{crc}".encode()


def check_cert_host(raw_url: str) -> None:
    """Pin ``paypal-cert-url`` to a PayPal-owned host over https.

    Runs *before* any network fetch: the point is to never make the request at
    all, not to make it and then judge the response.

    Raises:
        VerificationError: the URL is unparseable, not https, or not on an
            allowlisted host.
    """
    try:
        parsed = urlparse(raw_url)
    except ValueError as e:
        raise VerificationError(f"invalid paypal-cert-url: {e}") from e

    if parsed.scheme != "https":
        raise VerificationError("paypal-cert-url must be https")

    host = (parsed.hostname or "").lower()
    if not host:
        raise VerificationError("invalid paypal-cert-url: no host")

    for domain in CERT_HOST_ALLOWLIST:
        # Exact match, or a subdomain of it. The leading dot matters:
        # "notpaypal.com" must not match "paypal.com".
        if host == domain or host.endswith("." + domain):
            return
    raise VerificationError(f"paypal-cert-url host {host!r} is not a trusted PayPal host")


@dataclass(eq=False)
class _CertCache:
    """TTL'd cache of fetched certificates, keyed by cert URL, so concurrent
    webhooks do not each refetch."""

    ttl: timedelta = CERT_TTL
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _entries: dict[str, tuple[x509.Certificate, datetime]] = field(default_factory=dict, repr=False)

    def get(self, url: str) -> x509.Certificate | None:
        with self._lock:
            entry = self._entries.get(url)
            if entry is None:
                return None
            cert, fetched_at = entry
            if datetime.now(UTC) - fetched_at > self.ttl:
                return None
            return cert

    def set(self, url: str, cert: x509.Certificate) -> None:
        with self._lock:
            self._entries[url] = (cert, datetime.now(UTC))


@dataclass(eq=False)
class PayPalVerifier:
    webhook_id: str
    client: httpx.Client
    _certs: _CertCache = field(default_factory=_CertCache, repr=False)

    def verify(self, raw_body: bytes, headers, _now: datetime) -> None:
        transmission_id = headers.get("paypal-transmission-id")
        transmission_time = headers.get("paypal-transmission-time")
        signature_b64 = headers.get("paypal-transmission-sig")
        cert_url = headers.get("paypal-cert-url")
        auth_algo = headers.get("paypal-auth-algo")

        if not (transmission_id and transmission_time and signature_b64 and cert_url):
            raise VerificationError("missing PayPal signature headers")
        if (auth_algo or "").lower() != AUTH_ALGO.lower():
            raise VerificationError(f"unsupported paypal-auth-algo {auth_algo!r}")

        cert = self._cert(cert_url)
        public_key = cert.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise VerificationError("paypal cert: not an RSA key")

        verify_signature(
            public_key,
            transmission_id,
            transmission_time,
            self.webhook_id,
            raw_body,
            signature_b64,
        )

    def _cert(self, cert_url: str) -> x509.Certificate:
        cached = self._certs.get(cert_url)
        if cached is not None:
            return cached

        check_cert_host(cert_url)

        try:
            response = self.client.get(cert_url)
        except httpx.HTTPError as e:
            raise VerificationError(f"paypal cert: fetch failed: {e}") from e
        if response.status_code != 200:
            raise VerificationError(f"paypal cert: fetch: status {response.status_code}")

        body = response.content[:CERT_MAX_BYTES]
        cert = parse_cert_chain(body)
        self._certs.set(cert_url, cert)
        return cert


@functools.lru_cache(maxsize=1)
def _trust_store() -> Store:
    """The trust anchors, parsed once.

    Go's ``leaf.Verify`` uses the system root pool; Python has no equivalent
    built in, so these come from certifi. Verifying the chain at all is the
    point -- without it the host allowlist would be the only control standing
    between an attacker and a forged signature.
    """
    with open(certifi.where(), "rb") as fh:
        return Store(x509.load_pem_x509_certificates(fh.read()))


def parse_cert_chain(pem_data: bytes) -> x509.Certificate:
    """Parse a PEM bundle and return the leaf, having verified it chains to a
    trusted root.

    PayPal serves the leaf first, optionally followed by intermediates.

    Raises:
        VerificationError: nothing parseable in the response, or the leaf does
            not chain to a trusted root.
    """
    try:
        certs = x509.load_pem_x509_certificates(pem_data)
    except ValueError as e:
        raise VerificationError(f"paypal cert: parse certificate: {e}") from e
    if not certs:
        raise VerificationError("paypal cert: no certificate found in response")

    leaf, intermediates = certs[0], certs[1:]

    builder = PolicyBuilder().store(_trust_store())
    try:
        # The leaf is a TLS server certificate for the cert-url host, so its
        # own subject is the right thing to check it against.
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        name = san.value.get_values_for_type(x509.DNSName)[0]
        builder.build_server_verifier(x509.DNSName(name)).verify(leaf, intermediates)
    except Exception as e:
        raise VerificationError(f"paypal cert: certificate chain: {e}") from e
    return leaf


def verify_signature(
    public_key: rsa.RSAPublicKey,
    transmission_id: str,
    transmission_time: str,
    webhook_id: str,
    body: bytes,
    signature_b64: str,
) -> None:
    """Check the RSA-SHA256 signature over PayPal's message.

    Split out from :meth:`PayPalVerifier.verify` so it can be unit-tested with
    a locally generated keypair, with no cert fetch or network access involved.
    """
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        raise VerificationError("invalid paypal-transmission-sig encoding") from None

    message = signed_message(transmission_id, transmission_time, webhook_id, body)
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise VerificationError("signature mismatch") from None
