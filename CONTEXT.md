# HookGuard

A self-hosted gateway that verifies inbound webhook signatures at the network edge and forwards only authenticated traffic to a protected application. College major project (2 devs, 1 week). Originally Go; this repository is the Python port.

## Language

**Gateway**:
The edge component being built — it terminates inbound webhook traffic, verifies the signature, and forwards verified requests upstream.
_Avoid_: proxy, middleware, server

**Provider**:
An external service that dispatches signed webhooks (Stripe, GitHub, Shopify). Each Provider has its own signature shape.
_Avoid_: source, vendor, sender

**Upstream**:
The application the Gateway protects, which receives only verified webhooks.
_Avoid_: backend, client, consumer, app

**Signature shape**:
The provider-specific format and algorithm of a webhook signature (e.g. timestamped-concat, prefixed-hex, base64-encoded). The unit of variation HookGuard abstracts over.
_Avoid_: format, scheme, type

**Replay window**:
The maximum age a signed webhook may have before the Gateway rejects it as stale, even if cryptographically valid.
_Avoid_: tolerance, expiry, TTL

**Differential harness**:
The test rig that asserts the Gateway's verify verdict agrees with two independent implementations -- this one and the retained Go one -- and, where a vendor publishes a library that verifies webhook signatures, with that library too. Runs over one committed set of generated and adversarial vectors. The project's correctness proof.
_Avoid_: test suite, conformance test

**Oracle**:
An independent judge of a single vector's verdict: a vendor's own library where one exists, otherwise the other implementation. Stripe has one in both languages, GitHub only in Go, Shopify and PayPal in neither.
_Avoid_: reference, baseline

**Gateway signature**:
The single internal HMAC the Gateway computes over a verified request before forwarding, so the Upstream can authenticate the Gateway with one check instead of re-running every Provider's verification.
_Avoid_: internal header, verified header, proxy token

**Internal secret**:
The one shared key, known only to Gateway and Upstream, used to compute and verify the Gateway signature. Distinct from any Provider's signing secret.
_Avoid_: app secret, shared key

**Route**:
A configured binding of an inbound path to one Provider verifier, an Upstream URL, a replay window, and the env var naming that Provider's secret.
_Avoid_: endpoint, mapping, handler
