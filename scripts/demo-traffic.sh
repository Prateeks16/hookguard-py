#!/usr/bin/env bash
# Drive a DEPLOYED gateway through the full threat model, so the Console has
# real accepted/rejected traffic to show instead of empty states.
#
# demo.sh does this against a gateway it builds and runs locally; this does it
# against one already running somewhere, over HTTPS.
#
#   STRIPE_SECRET=... GITHUB_SECRET=... SHOPIFY_SECRET=... \
#     bash scripts/demo-traffic.sh https://hookguard-gateway.fly.dev
#
# The secrets must be the same values the deployed gateway was given. Requires
# curl and openssl. Nothing here is secret-bearing over the wire beyond the
# signatures themselves, which is the point.
set -u

GW="${1:-}"
if [ -z "$GW" ]; then
	echo "usage: $0 <gateway-url>   e.g. https://hookguard-gateway.fly.dev" >&2
	exit 2
fi
GW="${GW%/}"

: "${STRIPE_SECRET:?set STRIPE_SECRET to the value the deployed gateway uses}"
: "${GITHUB_SECRET:?set GITHUB_SECRET to the value the deployed gateway uses}"
: "${SHOPIFY_SECRET:?set SHOPIFY_SECRET to the value the deployed gateway uses}"

hmac_hex() { printf '%s' "$2" | openssl dgst -sha256 -hmac "$1" | awk '{print $NF}'; }
hmac_b64() { printf '%s' "$2" | openssl dgst -sha256 -hmac "$1" -binary | openssl base64 -A; }

# label, path, header, value, body
req() {
	local code body
	code=$(curl -s -o /tmp/hg_demo_body -w '%{http_code}' --max-time 15 \
		-X POST "$GW$2" -H "$3: $4" --data "$5" 2>/dev/null)
	body=$(tr -d '\n' </tmp/hg_demo_body 2>/dev/null)
	printf '  %-40s -> HTTP %-3s %s\n' "$1" "$code" "$body"
}

BODY='{"id":"evt_demo","amount":4242,"currency":"usd"}'
TS=$(date +%s)
OLD=$((TS - 900))

echo "target: $GW"
echo
echo "=== accepted: a correctly signed webhook from each provider ==="
req "stripe, valid"        /hook/stripe  "Stripe-Signature"       "t=$TS,v1=$(hmac_hex "$STRIPE_SECRET" "$TS.$BODY")" "$BODY"
req "github, valid"        /hook/github  "X-Hub-Signature-256"    "sha256=$(hmac_hex "$GITHUB_SECRET" "$BODY")"       "$BODY"
req "shopify, valid"       /hook/shopify "X-Shopify-Hmac-SHA256"  "$(hmac_b64 "$SHOPIFY_SECRET" "$BODY")"             "$BODY"

echo
echo "=== rejected: every way a webhook can fail, one per reason ==="
req "stripe, tampered body"    /hook/stripe  "Stripe-Signature"      "t=$TS,v1=$(hmac_hex "$STRIPE_SECRET" "$TS.$BODY")" '{"id":"evt_demo","amount":999999}'
req "stripe, wrong secret"     /hook/stripe  "Stripe-Signature"      "t=$TS,v1=$(hmac_hex 'not-the-secret' "$TS.$BODY")" "$BODY"
req "stripe, stale timestamp"  /hook/stripe  "Stripe-Signature"      "t=$OLD,v1=$(hmac_hex "$STRIPE_SECRET" "$OLD.$BODY")" "$BODY"
req "stripe, malformed header" /hook/stripe  "Stripe-Signature"      "garbage"                                          "$BODY"
req "github, missing header"   /hook/github  "X-Irrelevant"          "none"                                             "$BODY"
req "github, bad encoding"     /hook/github  "X-Hub-Signature-256"   "sha256=nothexatall"                               "$BODY"
req "shopify, wrong secret"    /hook/shopify "X-Shopify-Hmac-SHA256" "$(hmac_b64 'not-the-secret' "$BODY")"             "$BODY"
req "paypal, untrusted cert"   /hook/paypal  "paypal-transmission-id" "abc"                                             "$BODY"

echo
echo "expected: the three valid webhooks 200, everything else 401."
echo "open the Console's Live Logs to see each rejection with its reason."
