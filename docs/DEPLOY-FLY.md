# Deploying HookGuard to Fly.io

> **A note on this port.** Two things differ from the Go deployment these
> instructions were written for. A Python process cold-starts in roughly a
> second rather than milliseconds, which is still comfortably inside every
> supported provider's webhook timeout but is why the gateway's
> `min_machines_running` stays at 0 for cost rather than for speed. And the
> VM memory floors went from 256mb to 512mb: an interpreter plus FastAPI
> needs it.
>
> `force_https` on the Console is not optional. Its session cookie is
> `Secure`, so sign-in does not work over plain HTTP at all.



Three apps, one org, mirroring the Docker topology exactly: the gateway and the
Console get public URLs, the upstream gets none and is reachable only over
Fly's private network. Roughly ten minutes.

**Cost:** Fly bills pay-as-you-go and its terms change; check
[fly.io/docs/about/pricing](https://fly.io/docs/about/pricing/) before you
start rather than assuming this is free. The configs here ask for the smallest
VMs, one region, and scale-to-zero on the gateway to keep the footprint small.

## 0. Install and sign in

**Windows (PowerShell):**

```powershell
iwr https://fly.io/install.ps1 -useb | iex
```

Then **open a new terminal** — the installer adds `~\.fly\bin` to PATH and the
session you ran it in will not pick it up. `curl -L https://fly.io/install.sh | sh`
does *not* work here: PowerShell aliases `curl` to `Invoke-WebRequest` and has
no `sh` to pipe into.

**macOS / Linux:**

```sh
curl -L https://fly.io/install.sh | sh    # or: brew install flyctl
```

Then, on any platform:

```sh
fly version      # confirms it is on PATH
fly auth login   # opens a browser
```

## 1. Pick your app names

Fly app names are **globally unique**, so `hookguard-py-gateway` may be taken. If
so, choose a suffix and change it in all four places, or the private DNS names
will not resolve:

- `app = ` in `fly/gateway.toml`, `fly/upstream.toml`, `fly/console.toml`
- the `.internal` hostnames in `config.fly.json` and in `EVENTS_URL` in
  `fly/gateway.toml`

Pick a region close to you while you are at it — `primary_region` is `sin`
(Singapore) in all three files; `fly platform regions` lists the rest.

## 2. Create the apps

```sh
fly apps create hookguard-py-upstream
fly apps create hookguard-py-gateway
fly apps create hookguard-py-console
```

## 3. Generate one internal secret and give it to all three

This is the Gateway signature key. Generate it yourself — it should never be
typed into a chat, a commit, or a file:

```sh
INTERNAL_SECRET=$(openssl rand -base64 32)

fly secrets set INTERNAL_SECRET="$INTERNAL_SECRET" --app hookguard-py-upstream
fly secrets set INTERNAL_SECRET="$INTERNAL_SECRET" --app hookguard-py-gateway
fly secrets set INTERNAL_SECRET="$INTERNAL_SECRET" --app hookguard-py-console
```

The gateway also needs each provider's signing secret. For a demo these can be
values you invent, as long as whatever signs the test traffic uses the same
ones. For real webhooks they must match the provider dashboards (PRODUCTION.md
§2):

```sh
fly secrets set \
  STRIPE_SECRET="whsec_$(openssl rand -hex 16)" \
  GITHUB_SECRET="$(openssl rand -hex 16)" \
  SHOPIFY_SECRET="$(openssl rand -hex 16)" \
  --app hookguard-py-gateway
```

Save those three values — step 6 needs them. `fly secrets list` shows only
digests, never the values.

## 4. A volume for the Console's SQLite file

```sh
fly volumes create console_data --app hookguard-py-console --size 1 --region sin
```

## 5. Deploy, upstream first

Order matters only on the first deploy: the gateway resolves the upstream's
`.internal` name at request time, but deploying bottom-up avoids a window where
a verified webhook has nowhere to go.

```sh
fly deploy --config fly/upstream.toml
fly deploy --config fly/console.toml
fly deploy --config fly/gateway.toml
```

Confirm the upstream is genuinely unexposed — this should print **no** IPs:

```sh
fly ips list --app hookguard-py-upstream
```

If it prints any, the network half of the trust boundary is gone. Remove them
with `fly ips release`.

## 6. Prove it works

```sh
STRIPE_SECRET=... GITHUB_SECRET=... SHOPIFY_SECRET=... \
  bash scripts/demo-traffic.sh https://hookguard-py-gateway.fly.dev
```

Three `200`s and eight `401`s. Every one of those eleven decisions is now a row
in the Console's Live Logs with its reason — which is the thing worth showing
someone.

## 7. Create your Console account

Signup ships closed, which is correct for a public URL. Open it exactly long
enough to make the first account, which automatically becomes admin:

```sh
fly secrets set CONSOLE_ALLOW_SIGNUP=true --app hookguard-py-console
# visit https://hookguard-py-console.fly.dev/signup and create the account
fly secrets set CONSOLE_ALLOW_SIGNUP=false --app hookguard-py-console
```

Each `fly secrets set` restarts the app. If you would rather never open signup,
`fly ssh console --app hookguard-py-console --command "/python -m hookguard_console reset-password you@example.com"`
prints a one-time reset URL for an address that does not exist yet.

## What to show

- `https://hookguard-py-console.fly.dev` — landing page, and `/playground`, both
  public, no login needed.
- The dashboard behind login: Overview, **Live Logs** with the rejection
  reasons from step 6, and the Providers page.
- `fly ips list --app hookguard-py-upstream` printing nothing, next to a working
  webhook, is the architecture argument in one command.
