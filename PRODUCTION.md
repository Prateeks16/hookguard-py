# Production Deployment Checklist

HookGuard is a signature-verifying gateway. It is the **only** surface exposed
to the internet; it verifies each provider's webhook signature, attaches an
internal Gateway signature, and forwards the unaltered body to a protected
upstream that is never published to the network.

This checklist gets a real deployment turnkey. Read it top to bottom once.

## 1. Put TLS in front — required, for both services

The gateway serves **plain HTTP on `:9000`**. Webhook providers POST to a public
**HTTPS** URL, so you must terminate TLS ahead of it:

- Caddy, nginx, or a cloud load balancer terminates HTTPS and reverse-proxies to
  `gateway:9000`.
- The public URL becomes `https://hooks.your-domain.com/hook/<provider>`.
- Do **not** expose `:9000` directly without TLS. Signatures are still verified,
  but the traffic and your upstream's response would be in the clear.

**The Console is stricter: it does not work over plain HTTP at all.** Its
session cookie is `Secure`, so a browser will not send it back over an
unencrypted connection. Sign-in appears to do nothing — the form posts, the
server sets a cookie, and the next request arrives anonymous. If you are
debugging a Console login that silently returns you to the login page, this is
almost always why. `localhost` is the exception browsers make; any other host
needs real TLS.

## 2. Secrets — set every one, or the gateway won't boot

Both compose files use `${VAR:?}`, so a missing secret fails fast at start
rather than at the first webhook. Copy `.env.example` to `.env` and fill in
**real** values:

| Env var | Used by | Source |
| --- | --- | --- |
| `INTERNAL_SECRET` | Gateway↔upstream signature (shared) | Generate a strong random string: `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `STRIPE_SECRET` | `/hook/stripe` | Stripe Dashboard → webhook signing secret (`whsec_…`) |
| `GITHUB_SECRET` | `/hook/github` | The secret you set when creating the GitHub webhook |
| `SHOPIFY_SECRET` | `/hook/shopify` | Shopify app → webhook signing secret |

PayPal uses **no** shared secret (asymmetric). See §4.

The routing table stores only the *name* of each secret's environment variable,
never its value — which is why `config.json` and the Console's config export are
both safe to commit and to hand around.

## 3. Routes — point each provider's dashboard at the matching path

Routes are declared in `config.json` (local) or `config.docker.json`
(container, mounted read-only). Each provider's dashboard webhook URL must
match its route:

| Provider | Public webhook URL | Upstream (internal) |
| --- | --- | --- |
| Stripe | `https://…/hook/stripe` | `http://upstream:8080/stripe` |
| GitHub | `https://…/hook/github` | `http://upstream:8080/github` |
| Shopify | `https://…/hook/shopify` | `http://upstream:8080/shopify` |
| PayPal | `https://…/hook/paypal` | `http://upstream:8080/paypal` |

Edit the `upstream` URLs to point at your real application.

## 4. PayPal — extra step and a smoke test

PayPal carries no shared secret. Instead:

- Set `webhook_id` in the PayPal route to your **webhook subscription ID** from
  the PayPal Developer dashboard (replace `WH-CHANGE-ME`). It is config, not a
  secret.
- PayPal's signature is asymmetric (RSA-SHA256). The gateway fetches PayPal's
  certificate at request time, pins the cert host to `*.paypal.com` over HTTPS
  **before making any request**, and validates the chain to a trusted root
  before trusting it.

**Smoke-test PayPal before trusting real traffic.** The HMAC providers are
proven against their vendors' own libraries by the differential harness. PayPal
has no official library in **either** Python or Go, so its live cert-fetch path
is not exercised there. Send one event from the **PayPal sandbox** webhook
simulator through the deployed gateway and confirm it returns `200`. This needs
a free PayPal developer account.

## 5. Deploy

### Option A — pull pre-built images (recommended)

Every image was published by CI only after the three-way differential harness,
the full test suite, the lint pass, the packaging check and the dependency
guards passed on that commit.

```sh
cp .env.example .env      # then fill in real secrets
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

Pin a release rather than tracking `main`:

```sh
HOOKGUARD_TAG=sha-<full-40-char-sha> docker compose -f docker-compose.prod.yml up -d
```

### Option B — Fly.io

See [docs/DEPLOY-FLY.md](docs/DEPLOY-FLY.md).

### Option C — build from source

```sh
docker compose up --build -d
```

### Either way

Confirm the upstream has no published port. `docker compose ps` should show a
port mapping for the gateway and the console, and **none** for the upstream.
That is the network half of the trust boundary; if it has a mapping, something
has gone wrong.

## 6. Verify the deployment

```sh
# Health
curl -s https://hooks.your-domain.com/healthz

# A real signed webhook (Stripe)
SECRET=<your STRIPE_SECRET>
BODY='{"id":"evt_1","amount":4242}'
TS=$(date +%s)
SIG=$(printf '%s' "$TS.$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://hooks.your-domain.com/hook/stripe \
  -H "Stripe-Signature: t=$TS,v1=$SIG" --data "$BODY"     # expect 200

# The same body with the signature left off
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://hooks.your-domain.com/hook/stripe \
  --data "$BODY"                                          # expect 401
```

`bash scripts/demo-traffic.sh https://hooks.your-domain.com` sends a broader
mix against a deployed gateway.

## 7. Operational notes

**Restarts.** Routing is read at startup. Changing `config.json` — or exporting
a new one from the Console — requires restarting the gateway to take effect.

**Secret rotation.** `INTERNAL_SECRET` is shared between the gateway and the
upstream. Rotate it by updating both and restarting both; there is a window
during the rollout where one has the new value and the other does not, and
requests in that window fail closed rather than being let through.

**Logs.** The gateway logs each route at startup and warns on upstream
failures. It does not log bodies or signatures.

**What is stored.** The Console keeps a SHA-256 of each body, never the body
itself, and captures no request headers. There is nothing in its database that
would let someone reconstruct a payload.

**Telemetry is optional.** `EVENTS_URL` unset means the gateway's verification
path behaves exactly as it would if the feature did not exist. A Console that
is down or slow cannot slow down or fail a webhook: the event queue is bounded
and drops its oldest entry rather than applying backpressure.

## 8. Console — the web dashboard (optional)

Remove the `console` service entirely and the gateway and upstream behave
identically.

### Bootstrap: creating the first account

Signup is **closed by default**, and there is no auto-close-after-first-user
logic. The sequence is:

1. Set `CONSOLE_ALLOW_SIGNUP=true` and start the Console.
2. Visit `/signup` over HTTPS and create your account. The first account
   created becomes the admin.
3. Set `CONSOLE_ALLOW_SIGNUP=false` and restart.

If you skip step 3, signup stays open on a public URL indefinitely.

### Forgotten passwords

There is no SMTP in this system. An operator mints a one-time link from the
host:

```sh
docker compose exec console python -m hookguard_console reset-password you@example.com
```

It prints a single-use URL valid for one hour. Only the token's hash is stored,
so that output is the only copy — losing it means minting another.

### Seeding routes from an existing deployment

```sh
docker compose exec console python -m hookguard_console seed-config /config.json
```

Existing paths are skipped rather than overwritten.

### Exposure

Treat the Console as an admin surface, not a public page. Put it behind the
same TLS proxy, and consider restricting it to a VPN or an IP allowlist. It has
rate-limited login, Argon2id password hashing, CSRF on every state-changing
route, and a Content-Security-Policy of `default-src 'self'` with no
exceptions — but none of that is a reason to publish an admin UI more widely
than it needs to be.

### Data

One SQLite file at `CONSOLE_DATA_DIR/console.db`, holding users, sessions,
routes and events. Back it up by copying that one file. A nightly job prunes
events older than the configured retention window (30 days by default,
adjustable in Settings); the rollup aggregates the dashboard reads are kept
regardless, which is why a short retention window still shows a long trend.
