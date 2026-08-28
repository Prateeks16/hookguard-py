"""The Providers page's setup guides.

A static literal rather than a query over observed ``events.provider`` values,
deliberately: a provider the operator has configured but not yet received
traffic for must still show its setup guide, which is the page's whole point.

The documentary fields describe what the gateway's verifier actually checks,
so they are the place to look when a rejection reason needs explaining. The
rejection lists are the subset of the emitter's taxonomy each verifier can
really produce -- a reason that appears in Live Logs should be findable here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["PROVIDER_CATALOG", "ProviderGuide"]


@dataclass(frozen=True, slots=True)
class ProviderGuide:
    id: str  # matches the provider name in config.json and events.provider
    name: str
    algorithm: str
    headers: tuple[str, ...]  # exactly the headers that verifier reads
    secret_source: str
    #: The route key that value's *name* goes in: secret_env for the HMAC
    #: providers (the variable's name, never the secret), webhook_id for
    #: PayPal (config, not a secret at all).
    config_field: str
    replay_window: str
    reject_reasons: tuple[str, ...]
    checklist: tuple[str, ...] = field(default=())


PROVIDER_CATALOG: tuple[ProviderGuide, ...] = (
    ProviderGuide(
        id="stripe",
        name="Stripe",
        algorithm='HMAC-SHA256, hex, over "<timestamp>.<raw body>"',
        headers=("Stripe-Signature",),
        secret_source=(
            "Stripe Dashboard → Developers → Webhooks → the endpoint's signing secret (whsec_…)."
        ),
        config_field="secret_env",
        replay_window=(
            "5m by default — Stripe is the one provider that signs a timestamp, "
            "so a stale-but-valid signature is still rejected."
        ),
        reject_reasons=("missing header", "bad encoding", "stale timestamp", "signature mismatch"),
    ),
    ProviderGuide(
        id="github",
        name="GitHub",
        algorithm="HMAC-SHA256, hex, over the raw body, sha256= prefixed",
        headers=("X-Hub-Signature-256",),
        secret_source=(
            "The secret you typed when you created the webhook (repo/org → "
            "Settings → Webhooks). GitHub never shows it again."
        ),
        config_field="secret_env",
        replay_window="None — GitHub sends no timestamp, so there is nothing to age out.",
        reject_reasons=("missing header", "bad encoding", "signature mismatch"),
    ),
    ProviderGuide(
        id="shopify",
        name="Shopify",
        algorithm="HMAC-SHA256, base64, over the raw body",
        headers=("X-Shopify-Hmac-SHA256",),
        secret_source=(
            "Your Shopify app's webhook signing secret (Partner Dashboard → app → API credentials)."
        ),
        config_field="secret_env",
        replay_window="None — Shopify sends no timestamp.",
        reject_reasons=("missing header", "bad encoding", "signature mismatch"),
    ),
    ProviderGuide(
        id="paypal",
        name="PayPal",
        algorithm='RSA-SHA256 (asymmetric) over "id|time|webhookId|crc32(body)"',
        headers=(
            "paypal-transmission-sig",
            "paypal-transmission-id",
            "paypal-transmission-time",
            "paypal-cert-url",
            "paypal-auth-algo",
        ),
        secret_source=(
            "No shared secret. PayPal signs with its own key; the gateway fetches "
            "the certificate named by paypal-cert-url, pins the host to "
            "*.paypal.com over HTTPS, and validates the chain to a trusted root "
            "before trusting it."
        ),
        config_field="webhook_id",
        replay_window=(
            "None — the transmission time is signed but PayPal defines no "
            "staleness rule the gateway enforces."
        ),
        reject_reasons=(
            "missing header",
            "unsupported algorithm",
            "cert host rejected",
            "cert chain invalid",
            "bad encoding",
            "signature mismatch",
        ),
        checklist=(
            "Set webhook_id to your webhook subscription ID from the PayPal "
            "Developer dashboard (replace WH-CHANGE-ME). It is config, not a secret.",
            "Send one event from the PayPal sandbox webhook simulator through the "
            "deployed gateway and confirm it returns 200.",
            "Do this before trusting real traffic: PayPal has no official library "
            "in either language, so unlike the HMAC providers its live cert-fetch "
            "path is not covered by the differential harness.",
        ),
    ),
)
