# HookGuard — Project Report

A self-hosted gateway that verifies inbound webhook signatures at the network
edge and forwards only authenticated traffic to a protected application.

This repository is the **Python** implementation. It began as a port of a Go
build of the same system, and the port is itself part of the result: the Go
implementation is retained as a test oracle, which makes the project's central
correctness claim stronger than it was before.

## 1. The problem

Four providers, four different ways of signing the same kind of request.

| Provider | Algorithm | Encoding | Signed over | Timestamp |
|---|---|---|---|---|
| Stripe | HMAC-SHA256 | hex | `"<timestamp>.<raw body>"` | yes, enforced |
| GitHub | HMAC-SHA256 | hex, `sha256=` prefixed | raw body | no |
| Shopify | HMAC-SHA256 | **base64** | raw body | no |
| PayPal | **RSA-SHA256** | base64 | `"id\|time\|webhookId\|crc32(body)"` | signed, not enforced |

Every application that receives webhooks from more than one provider
reimplements all of these, usually inline in a request handler. The failure
mode is the dangerous kind: a mistake does not raise an error or break a test,
it silently accepts forged requests.

HookGuard does the verification once, in front of the application. The
application then verifies **one** signature — the Gateway signature — instead
of four.

## 2. Design

### The trust boundary

Two independent halves:

- **Cryptographic.** The gateway re-signs each verified body with a single
  `INTERNAL_SECRET`, binding the verified provider name into the signature. An
  attacker without that secret cannot forge a request the application accepts,
  and cannot relabel a Stripe payload as a GitHub one.
- **Network.** The application is never published. Only the gateway, on a
  shared internal network, can reach it.

Either half alone still refuses forged traffic. The demo script proves the
first by aiming a forged Gateway signature straight at the upstream and
watching it return 401.

### The raw-body invariant

The signature is over bytes, not over meaning. Parsing a body and
re-serializing it reorders keys and normalizes whitespace, and the resulting
bytes will not match. The gateway therefore never parses a webhook body — it
buffers, verifies, and forwards the same bytes. In FastAPI that meant handlers
that take the request object and stream the body themselves, rather than
declaring a typed body model, and the test suite includes payloads that are not
valid UTF-8 at all: any decode anywhere in the path would break them.

### Components

| Component | Role |
|---|---|
| Gateway | Terminates webhook traffic, verifies, re-signs, forwards |
| Upstream | Sample protected application; verifies one signature |
| Console | Operator dashboard: routes, live logs, provider guides, settings |

The Console is optional. Remove it and the gateway and upstream behave
identically.

## 3. Correctness: the three-way differential harness

The claim is that each verifier agrees with the provider's own library. The
harness makes that claim continuous rather than a one-time result.

`tests/vectors/signatures.json` holds 41 cases — 18 that must be accepted and
23 that must be rejected — generated from the providers' documented algorithms
using raw primitives, deliberately **not** by asking a verifier for the answer.
A generator that consulted the implementation would produce a harness that
could only ever agree with itself.

Both suites read that same committed file and assert against the same expected
column. Neither talks to the other, so agreement between the two
implementations is transitive through the file rather than coordinated at
runtime.

| Provider | Python oracle | Go oracle | Result |
|---|---|---|---|
| Stripe | `stripe` (official) | `stripe-go` (official) | Two independent official oracles |
| GitHub | none exists | `go-github` (official) | Pinned to the vendor through the Go leg |
| Shopify | none exists | none exists | Cross-language agreement only |
| PayPal | none exists | none exists | Outside the harness |

### What the harness found

Three things surfaced on its first runs that reasoning about the code had not.

**Stripe's event-construction API is the wrong oracle.** Using it, the harness
reported a disagreement on a *correctly signed empty body*: `ConstructEvent`
also deserializes the payload, so it rejected it for a reason unrelated to
signatures. The original Go harness had sidestepped this by restricting its
payloads to valid JSON. Both legs now use the signature-only APIs, which keeps
the adversarial payloads and makes the two vendor legs ask the same question.

**Stripe's Python library cannot verify a non-UTF-8 body at all.** It decodes
the payload before verifying, so it raises rather than returning a verdict —
stricter than the protocol, since the signature is over bytes. `stripe-go` and
both implementations here accept such a body. That single case is excluded from
the Python vendor leg, and the exclusion set is itself asserted so it cannot
widen unnoticed.

**A correction to an earlier claim.** An early version of the migration plan
stated that Python gained an official Shopify oracle. It does not: the
`ShopifyAPI` package's `validate_hmac` computes a sorted query-string HMAC for
OAuth callbacks, a different algorithm, and nothing in the package verifies a
webhook body. The dependency was dropped. Shopify is therefore neutral in this
port, not improved — the same caveat the Go report carried.

## 4. What the port changed

### Kept

The wire contract is unchanged: the Gateway signature scheme, the `config.json`
shape, the ingest event JSON, and the SQLite schema are all byte-for-byte
identical. The two implementations interoperate in both directions, which is
what allowed the port to land one component at a time. Concretely:

- A signature produced by the Go build verifies here, and vice versa, checked
  against 90 generated vectors.
- A database written by the Go console opens and reads here, checked against a
  fixture produced by the Go console's own packages.
- An Argon2id hash generated by the Go build verifies here unchanged, so an
  existing installation migrates with no user action.

### Lost

**The single static binary.** The Go build shipped roughly 15MB on a distroless
base with no runtime dependencies. These images carry a Python runtime and are
larger. The *security* property behind that claim survives and is still
enforced in CI: no provider SDK reaches a shipped service, because those live
in a `[dev]` extra as harness oracles.

**The race detector.** `go test -race` has no Python counterpart. The
concurrent surfaces — the event emitter, the ingest batcher, the rate limiter —
have explicit concurrency tests instead, which is a weaker guarantee honestly
stated.

### Found

Porting a system is a close reading of it, and it surfaced defects in the
original that no test covered:

- The Console's Content-Security-Policy is `default-src 'self'`, which blocks
  inline style attributes. All 42 of them across ten templates had **never
  applied** in any CSP-enforcing browser. They are utility classes now.
- The same policy blocked the `data:` URI favicon, so no icon ever rendered.
- Those two compounded a third. The route form hid its provider-specific fields
  with a server-rendered inline style, which the CSP dropped, and the
  JavaScript that would have corrected it only ran on `change` — never on load.
  The form showed the secret, replay **and** webhook fields for every provider
  until the select was touched.
- `?next=` rejected `//evil.example` but not `/\evil.example`, which some
  browsers read the same way.

All are fixed here, and verified by reading `securitypolicyviolation` events
from a real browser against a running server: two violations before, zero
after.

## 5. Verification

| Layer | What it proves |
|---|---|
| 738 automated tests | Unit and integration behaviour across both services. 737 pass; one is a documented skip, where Stripe's Python library cannot judge a non-UTF-8 body |
| Three-way differential harness | Verdict agreement across two implementations and the vendors' libraries |
| Cross-language vectors | Signatures, durations and timestamps match the Go build exactly |
| Go-written database fixture | An existing installation's data reads correctly |
| Packaging check in CI | The built wheel carries its templates and migration, installed clean |
| `demo.sh` | The whole threat model end to end against running processes |

`demo.sh` is the one to run first. It starts both services and sends a valid
webhook (200), a tampered body (401), a wrong-secret signature (401), a stale
timestamp with a valid HMAC (401), and a forged Gateway signature aimed
directly at the upstream (401).

## 6. Limitations

- **PayPal is not covered by the harness.** No official library exists in
  either language, so its live certificate-fetch path is exercised only by
  unit tests with a generated keypair. `PRODUCTION.md` requires a sandbox
  smoke test before trusting real traffic.
- **The Console requires TLS.** Its session cookie is `Secure`, so sign-in does
  not work over plain HTTP at all.
- **Single instance.** The rate limiter is in-process and SQLite is
  single-writer. Both are appropriate for a self-hosted console and neither
  survives horizontal scaling unchanged.
- **Routing is read at startup.** Changing routes requires a gateway restart.
