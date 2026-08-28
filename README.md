# HookGuard

A self-hosted gateway that verifies inbound webhook signatures at the network
edge and forwards only authenticated traffic to your application. Stripe,
GitHub, Shopify and PayPal supported.

Python port of [Prateeks16/hookguard](https://github.com/Prateeks16/hookguard).
The wire contract is unchanged, so the two implementations interoperate: this
gateway will run against the Go console and vice versa.

## Why

Every webhook provider signs its requests differently (different headers,
algorithms, encodings, replay rules). Verifying them correctly is fiddly and
error-prone, and a subtle mistake silently disables the security. HookGuard
does the verification once, in front of your app. Your app then trusts **one**
thing -- the Gateway signature -- instead of implementing N bespoke verifiers.

```
                          verifies provider signature
   Stripe --.             attaches Gateway signature
   GitHub --|
   Shopify--+-->  HookGuard  --------------------->  Your app
   PayPal --'   (port 9000)        internal network  (verifies ONE signature)
                                   app is NOT exposed
```

## How it works

1. A provider POSTs a signed webhook to `/hook/<provider>`.
2. HookGuard reads the **raw body** (never parsing it -- parsing then
   re-serializing would change the bytes and break the signature) and verifies
   the provider's signature: constant-time HMAC compare for the symmetric
   providers, or an RSA-SHA256 check against PayPal's published certificate,
   plus a replay-window check where the provider includes a timestamp (Stripe).
3. On success it re-signs the body with a single `INTERNAL_SECRET` (the
   **Gateway signature**, binding the verified provider name) and forwards the
   unchanged bytes upstream. On failure it returns `401` and forwards nothing.
4. Your app verifies that one Gateway signature and trusts the payload.

## Correctness

The project's central claim is that each verifier agrees byte-for-byte with the
provider's own official library. This port carries that claim with a **three-way
differential harness**: the Python verifier, the original Go implementation
(retained under `oracle/`), and the vendors' libraries all read one committed
vector file and must return identical verdicts.

`oracle/` is a **test-only** Go module. No Go source, binary or toolchain enters
a published image -- CI asserts it, and `oracle` is in `.dockerignore`.

## Status

Ported in phases; see [MIGRATION.md](MIGRATION.md) for the full plan.

| Phase | Scope | State |
|------:|-------|-------|
| 0 | Repository scaffold, CI, dependency split | done |
| 1 | Shared core (`gatewaysig`, event schema, Go durations) | not started |
| 2 | Gateway: config, verifiers, four providers, forwarding | not started |
| 3 | Three-way differential harness | not started |
| 4 | Console store (SQLite) | not started |
| 5 | Console auth (Argon2, sessions, CSRF) | not started |
| 6 | Console HTTP: routes, templates, ingest, retention | not started |
| 7 | Docker, compose, Fly, publish | not started |
| 8 | Documentation | not started |

## Development

```sh
python -m venv .venv
.venv/Scripts/activate        # or: source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

The dependency split is enforced, not conventional: installing `[gateway]` or
`[console]` must never pull a provider SDK. Those live in `[dev]` only, because
they are differential-harness oracles rather than runtime dependencies.

## License

MIT -- see [LICENSE](LICENSE).
