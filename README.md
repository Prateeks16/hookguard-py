# HookGuard

A self-hosted gateway that verifies inbound webhook signatures at the network
edge and forwards only authenticated traffic to your application. Stripe,
GitHub, Shopify and PayPal supported.

Python port of [Prateeks16/hookguard](https://github.com/Prateeks16/hookguard).
The wire contract is unchanged, so the two implementations interoperate: this
gateway runs against the Go console and vice versa.

## Why

Every webhook provider signs its requests differently — different headers,
algorithms, encodings, replay rules. Verifying them correctly is fiddly and
error-prone, and a subtle mistake silently disables the security rather than
breaking anything you would notice. HookGuard does the verification once, in
front of your app. Your app then trusts **one** thing — the Gateway signature —
instead of implementing four bespoke verifiers.

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
2. HookGuard reads the **raw body** — never parsing it, because parsing and
   re-serializing reorders keys and normalizes whitespace, and the signature is
   over bytes — and verifies the provider's signature: a constant-time HMAC
   compare for the symmetric providers, or an RSA-SHA256 check against PayPal's
   published certificate. Where the provider signs a timestamp (Stripe), a
   stale-but-valid signature is rejected too.
3. On success it re-signs the body with a single `INTERNAL_SECRET` — the
   **Gateway signature**, which binds the verified provider name — and forwards
   the unchanged bytes upstream. On failure it returns `401` and forwards
   nothing.
4. Your app verifies that one signature and trusts the payload.

The trust boundary has two reinforcing halves: the **Gateway signature** (an
attacker without `INTERNAL_SECRET` cannot forge a request your app will accept)
and **network isolation** (the app is never published; only the gateway can
reach it). Either half standing alone still refuses forged traffic.

## Quick start

```sh
cp .env.example .env        # fill in real secrets
docker compose up --build
```

Or pull the images CI publishes on every green push to `main`:

```sh
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

Only the gateway is published (`:9000`). The upstream has no `ports:` mapping —
it is unreachable from the host; only the gateway, on the shared internal
network, can talk to it.

Send a webhook (this signs a Stripe payload with `openssl`):

```sh
SECRET=whsec_change-me                 # must match STRIPE_SECRET
BODY='{"id":"evt_1","amount":4242}'
TS=$(date +%s)
SIG=$(printf '%s' "$TS.$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

curl -s -X POST localhost:9000/hook/stripe \
  -H "Stripe-Signature: t=$TS,v1=$SIG" \
  --data "$BODY"
# -> "ok"  (verified, forwarded, upstream accepted)
```

A tampered body, a wrong secret, or a stale timestamp returns `401` and never
reaches your app. `bash demo.sh` runs all of those plus a forged Gateway
signature aimed straight at the upstream.

## Correctness

The project's central claim is that each verifier agrees with the provider's
own official library. This build carries that claim with a **three-way
differential harness**: the Python verifier, the original Go implementation
(retained under `oracle/`), and the vendors' libraries all read one committed
vector file — 41 cases, 23 of which must be rejected — and must return
identical verdicts.

| Provider | Python oracle | Go oracle |
|---|---|---|
| Stripe | `stripe` (official) | `stripe-go` (official) |
| GitHub | none exists | `go-github` (official) |
| Shopify | none exists | none exists |
| PayPal | none exists | none exists |

GitHub is why `oracle/` is kept: PyGithub has no signature-verification helper,
so without the Go leg that verdict would rest on a re-implementation. Shopify
and PayPal have no official verifier in **either** language — Shopify's Python
SDK exposes `validate_hmac`, but that is a sorted query-string HMAC for OAuth
callbacks, a different algorithm — so those rest on the cross-language leg and
the documented algorithm. That is the same caveat the Go build carried.

`oracle/` is **test-only**. No Go source, binary or toolchain enters a
published image; `oracle` is in `.dockerignore` and CI asserts it.

## Requirements and limits

**TLS is required for the Console.** Its session cookie is `Secure`, so a
browser will not send it back over plain HTTP and sign-in silently does
nothing. Terminate TLS in front of it. The gateway itself serves plain HTTP by
design and expects a proxy in front (see [PRODUCTION.md](PRODUCTION.md)).

**This is not a zero-dependency static binary.** The Go build shipped ~15MB on
distroless; these images are larger and carry a Python runtime. The security
property behind that old claim survives and is still CI-enforced: no provider
SDK reaches a shipped service. The dependency split is real, not conventional —
`[gateway]` and `[console]` are what ship, and the provider SDKs live in
`[dev]` because they are harness oracles.

## Development

```sh
python -m venv .venv
.venv/Scripts/activate        # or: source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

The Go leg of the harness needs a Go toolchain and the vector file:

```sh
cd oracle && go test ./verifier/
```

## Documentation

| Document | What it covers |
|---|---|
| [PRODUCTION.md](PRODUCTION.md) | Deployment checklist: TLS, secrets, routes, verification |
| [MIGRATION.md](MIGRATION.md) | The port: what moved, what changed, what the harness found |
| [docs/DEPLOY-FLY.md](docs/DEPLOY-FLY.md) | Deploying to Fly.io |
| [docs/REPORT.md](docs/REPORT.md) | The project write-up |
| [CONTEXT.md](CONTEXT.md) | The project's own vocabulary |

## License

MIT — see [LICENSE](LICENSE).
