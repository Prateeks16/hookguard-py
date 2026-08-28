# Porting HookGuard from Go to Python

Working plan for the Python port. This is the copy that travels with the code;
a formatted version is published as the migration-plan artifact.

Source of truth for the port is the Go tree at
[Prateeks16/hookguard@b3d293a](https://github.com/Prateeks16/hookguard) —
9,945 lines across 73 files in two modules.

## 1. Two framing decisions

**The wire contract does not change.** The `X-HookGuard-Signature` scheme, the
`config.json` shape, the ingest event JSON and the SQLite schema all stay
byte-for-byte identical. Every phase below is independently shippable — the
Python gateway runs against the existing Go console and vice versa — so
nothing has to land as a big-bang cutover.

**Go survives as a test dependency, and only as a test dependency.** The
existing Go verifiers already work and are already tested, so keeping them
costs nothing but CI minutes. They become the third leg of the differential
harness (§5), which recovers the one loss that could genuinely have hurt this
project. No Go binary, source file or toolchain enters any published image:
`oracle` is in `.dockerignore` and CI asserts it.

## 2. Layout

```
hookguard-py/
  pyproject.toml          extras: [gateway] [console] [dev] -- the module split, enforced
  config*.json            copied verbatim from the Go repo
  docker/                 gateway.Dockerfile console.Dockerfile upstream.Dockerfile
  src/
    hookguard_core/       was internal/gatewaysig -- shared, stdlib-only
      gatewaysig.py       Sign / Verify, header names
      events.py           the VerifyEvent wire shape, one definition
      goduration.py       "5m" -> timedelta (no stdlib equivalent)
    hookguard_gateway/
      __main__.py app.py config.py verifier.py emitter.py upstream.py
      providers/          stripe.py github.py shopify.py paypal.py
    hookguard_console/
      __main__.py app.py middleware.py gwconfig.py
      auth/ store/ routes/ ui/
  tests/
    vectors/signatures.json   the committed interchange -- read by BOTH suites
    gateway/ console/
  oracle/                 TEST-ONLY Go. Never built into an image.
```

## 3. Component mapping

| Go | Python | Notes |
|---|---|---|
| `internal/gatewaysig` | `hookguard_core/gatewaysig.py` | Pure `hmac`/`hashlib`. Same preimage, same hex output. |
| `Route.ReplayWindow` | `hookguard_core/goduration.py` | New file, no Go counterpart. See risk 2. |
| `main.go` | `gateway/__main__.py` + `app.py` | FastAPI app; timeouts become uvicorn flags; graceful drain moves into `lifespan`. |
| `config.go` | `gateway/config.py` | Pydantic model over the unchanged JSON. |
| `verifier.go` | `gateway/verifier.py` | `Protocol` + `@register("stripe")` decorator, replacing the interface and `init()` registry. |
| `stripe.go` `github.go` `shopify.go` | `gateway/providers/*.py` | Direct translation. `hmac.compare_digest` for every comparison. |
| `paypal.go` | `gateway/providers/paypal.py` | RSA-SHA256 via `cryptography`; cert cache, 1h TTL, host allowlist and 1MB cap preserved. |
| `events.go` | `gateway/emitter.py` | Goroutine + buffered channel to `asyncio.Task` + `asyncio.Queue(1024)`, same drop-oldest policy. |
| `cmd/upstream` | `gateway/upstream.py` | Sample protected app. |
| `web/cmd/console` | `console/__main__.py` | Subcommands via `argparse`. |
| `internal/server/server.go` | `console/app.py` | 31 routes to `APIRouter`s; the `Server` struct becomes `app.state` + dependencies. |
| `internal/server/handlers_*.go` | `console/routes/*.py` | One module per handler file. Bulkiest chunk. |
| `internal/server/middleware.go` | `console/middleware.py` | Session + CSRF + security headers as Starlette middleware. |
| `internal/auth/password.go` | `console/auth/password.py` | `argon2-cffi`. PHC strings stay compatible — risk 4. |
| `internal/auth/{session,csrf,ratelimit}.go` | `console/auth/*.py` | `secrets.token_urlsafe(32)`, `hmac.compare_digest`, in-process limiter. |
| `internal/store/*.go` | `console/store/*.py` | Stdlib `sqlite3`; the `.sql` migration copied verbatim. |
| `internal/ingest` | `console/ingest.py` + `batcher.py` | 100ms flush ticker on an asyncio task. |
| `internal/retention` | `console/retention.py` | Daily sweep, runs once at startup as today. |
| `internal/gwconfig` | `console/gwconfig.py` | Export must still emit two-space-indented JSON. |
| `ui/templates/*.html` (15) | `ui/templates/*.html` | Go templates to Jinja2. `define`/`template` to `extends`/`block`. Risk 1. |
| `ui/static/` (11 files) | `ui/static/` | Copied unchanged, htmx included. |
| `verifier.go` + providers | `oracle/verifier.go` | Carried over unmodified. Cross-language leg of the harness. |
| `diff_test.go` | `oracle/differential_test.go` | Rewritten to read the committed vector file. |

## 4. Dependencies

| Group | Packages | Ships? |
|---|---|---|
| `[gateway]` | `fastapi`, `uvicorn[standard]`, `httpx`, `cryptography` | in image |
| `[console]` | gateway extras + `jinja2`, `argon2-cffi`, `python-multipart` | in image |
| `[dev]` | `pytest`, `pytest-asyncio`, `ruff`, `stripe` | CI only |
| `oracle/go.mod` | `stripe-go`, `go-github` + the Go toolchain | CI only |

Target is **Python 3.12** (the development machine's version). Nothing in the
port needs 3.13. SQLite needs nothing installed — stdlib `sqlite3` handles
WAL, `busy_timeout` and `foreign_keys` through the same pragmas the Go DSN set.

## 5. The three-way harness

Today the harness diffs one implementation against the vendors' libraries.
After the port it diffs **two independent implementations, in two languages,
against each other and against the vendors' libraries** — on the same
committed inputs.

There is no RPC and no subprocess. `tests/vectors/signatures.json` is committed
and holds every case: body bytes base64-encoded so nothing normalizes them in
transit, plus the header, the secret, and the expected verdict. Both suites
read that file and assert against that same expected column, so agreement
between them is transitive and provable rather than coordinated at runtime.

| Provider | Python oracle | Go oracle | Result |
|---|---|---|---|
| Stripe | `stripe` (official) | `stripe-go` (official) | Two official oracles. Stronger than today. |
| GitHub | none exists | `go-github` (official) | **The loss, recovered.** Python's verdict is pinned to the official library through the Go leg. |
| Shopify | **none exists** | re-implementation | Unchanged from Go. See the correction below. |
| PayPal | none | none | Unchanged — PayPal is outside the harness today too. |

**Correction (phase 3).** An earlier revision of this plan claimed Python
gained an official Shopify oracle. That was wrong, and checking it was what
found it: the `ShopifyAPI` package's `validate_hmac` computes a sorted
query-string HMAC for OAuth callbacks, a different algorithm from webhook body
verification, and nothing in the package verifies a webhook body at all. The
dependency was dropped. Shopify therefore has **no official oracle in either
language** and rests on the cross-language leg plus the documented algorithm --
exactly the caveat the Go report already carried. The port is neutral on
Shopify, not an improvement. It remains a net gain overall: two official Stripe
oracles where there was one, and GitHub's recovered.

**A second finding, from running the harness.** Using Stripe's event-construction
API as the oracle conflates signature validity with event deserialization: it
rejected a correctly signed empty body. The Go original avoided this by
restricting its payloads to valid JSON. Both legs now use the signature-only
APIs (`ValidatePayloadIgnoringTolerance` and `verify_header(tolerance=None)`),
which keeps the adversarial payloads and makes the two vendor legs ask the same
question. Relatedly, Stripe's *Python* library decodes the payload as UTF-8
before verifying, so it cannot judge a non-UTF-8 body at all; that one case is
explicitly excluded from the Python vendor leg, and the exclusion set is itself
asserted so it cannot widen unnoticed.

**Caveat to settle.** Python is a submission requirement, so a
Go directory invites a question. It is named `oracle/`, its purpose is stated
here and in its own README, and CI proves no Go artifact reaches an image. If
the rule forbids it anyway, deleting `oracle/` costs nothing operationally —
the shipped system is untouched and the Python-vs-official-library diffs still
run. Only the cross-language leg drops, taking GitHub back to a
re-implementation oracle: the same caveat Shopify carries in the current Go
report.

## 6. What we accept losing

- **The single static binary.** "Zero external dependencies in the shipped
  binary" no longer holds; images go from ~15MB distroless to ~90MB on
  `python:3.12-slim`. The security property behind the claim survives and is
  still CI-enforced: no provider SDK reaches a service runtime. The marketing
  sentence needs rewriting; the guarantee does not.
- **The race detector.** `go test -race` has no Python counterpart. Mitigation
  is explicit concurrency tests — N concurrent enqueues, assert no loss beyond
  the documented drop-oldest. The retained Go verifiers are pure functions, so
  `-race` would tell us nothing about them anyway.

The gain is in the harness itself: Stripe now has two independent official
oracles rather than one, GitHub's is recovered through the Go leg, and every
vector is judged by two implementations in two languages. Shopify and PayPal
are unchanged from the Go original.

## 7. Risks, ordered by how quietly they fail

1. **Contextual escaping is not like-for-like.** Go's `html/template` escapes
   per context; Jinja2's autoescape is HTML-only. Three templates interpolate
   into URL attributes today: `href` in `providers.html`, and `hx-put`/`hx-get`
   in `endpoint_form.html` and `overview.html`. Each needs an explicit filter or
   server-side validation. A security regression if missed, and nothing will
   look broken.
2. **Go duration strings.** `replay_window` holds `"5m"`, `"1h30m"`, `"300s"`
   in config files, in the `endpoints` table, and in `gwconfig.Validate`. No
   stdlib parser exists. A naive `int(s)` or a regex that quietly returns zero
   disables replay protection while every test still passes.
3. **Raw body integrity.** `await request.body()` and never a Pydantic body
   model or `request.json()` on a webhook route — parsing and re-serializing
   changes the bytes.
4. **Argon2 parameters.** The schema pins `m=65536,t=3,p=2`. `argon2-cffi`'s
   defaults differ. Get it right and existing PHC hashes verify unchanged, so an
   existing console database migrates with no user action.
5. **Single-writer SQLite.** Go pinned `SetMaxOpenConns(1)`. Python's
   equivalent is one shared connection with `check_same_thread=False` behind a
   lock. Getting it wrong surfaces as intermittent "database is locked".
6. **PayPal's cert-URL allowlist.** `paypal-cert-url` is attacker-controlled;
   the host pin is the only thing stopping a forged signature validating against
   an attacker's certificate. PayPal has no oracle, so the harness will not
   catch a mistake here.
7. **Drop-oldest under load.** `asyncio.Queue` has no drop-oldest mode, so it is
   `get_nowait()` then `put_nowait()` on overflow. Easy to write as an unbounded
   queue by accident, turning a telemetry burst into a memory leak.
8. **The oracle drifting out of the build.** Guard it by having the Go suite
   fail on any vector it does not recognize, rather than skipping unknown rows.

## 8. Build order

| Phase | Scope | Exit check |
|------:|-------|------------|
| 0 | Scaffold: pyproject, extras, ruff, pytest, CI, this file | Smoke suite green; `[gateway]` install has no provider SDK |
| 1 | Shared core: `gatewaysig`, event schema, Go durations | A signature from the Go build verifies in Python and vice versa |
| 2 | Gateway: config, registry, four providers, forwarding, emitter, upstream | Provider unit tests green; runs in compose against the Go console |
| 3 | **Three-way harness** | Python, Go and the vendors' libraries agree on every vector |
| 4 | Console store | A database written by the Go console reads correctly under Python |
| 5 | Console auth | A password hash from the Go build verifies unchanged |
| 6 | Console HTTP: middleware, 31 routes, 15 templates, ingest, retention, SSE | Handler tests green; accepts ingest from the Go gateway |
| 7 | Deployment: Dockerfiles, compose, Fly, CI guards, GHCR | `docker compose up` from a clean clone; `demo.sh` passes |
| 8 | Documentation | No document still describes a Go build as the shipped system |

## 9. CI translation

| Go step | Python | Notes |
|---|---|---|
| `go build ./...` | import smoke test | Install each extra in a clean venv, import the package. |
| `go vet ./...` | `ruff check` | Close enough in role; stricter in places. |
| `gofmt -l .` | `ruff format --check` | Plus `gofmt -l oracle/`, which still applies. |
| `go test -race ./...` | `pytest` | No race detector. See §6. |
| `go test -run Differential` | two jobs, one vector file | `pytest -m differential` and `go test ./oracle`. |
| `go list -deps` grep guard | assert import fails | Install `[gateway]` only, require `import stripe` to raise. |
| — | no-Go-in-images guard | New. Assert no Go artifact in a built image. |
| `docker build` x3 + GHCR | unchanged | Only the Dockerfile paths move. |
