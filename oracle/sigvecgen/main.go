// Command sigvecgen emits ../../tests/vectors/signatures.json: the shared input
// to the differential harness.
//
// It deliberately does NOT import the verifier package. Every signature here is
// built from the provider's documented algorithm using raw crypto primitives,
// and every expected verdict follows from how the case was constructed, not
// from running an implementation. A generator that asked a verifier what the
// answer was would produce a harness that could only ever agree with itself.
//
// Timestamps are fixed rather than relative to the run, so the file is
// deterministic and committable: each vector carries the reference `now` the
// verifier should be given.
//
// Regenerate (from the repo root):
//
//	cd oracle && go run ./sigvecgen > ../tests/vectors/signatures.json
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Vector is one differential case. Both suites read this and must produce
// Expected for it.
type Vector struct {
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Secret   string            `json:"secret"`
	Window   string            `json:"replay_window"`
	BodyB64  string            `json:"body_b64"`
	Headers  map[string]string `json:"headers"`
	NowUnix  int64             `json:"now_unix"`
	Expected bool              `json:"expected"`

	// TimeSensitive marks a case whose verdict depends on the replay window.
	// The official libraries read the system clock and cannot be handed our
	// fixed `now`, so the vendor-oracle leg skips these; the cross-language
	// leg still covers them, because both our implementations do accept an
	// injected clock.
	TimeSensitive bool `json:"time_sensitive"`

	// Oracle names the official library that can independently judge this
	// case, or "none" where no vendor library verifies this shape.
	Oracle string `json:"oracle"`
}

// Reference instant for every vector. Fixed so the file is deterministic.
var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	stripeSecret  = "whsec_diff"
	githubSecret  = "ghdiff"
	shopifySecret = "shopdiff"
)

var (
	plain   = []byte(`{"id":"evt_1","object":"event","type":"payment_intent.succeeded"}`)
	emoji   = []byte(`{"id":"evt_2","object":"event","note":"thanks 🚀✨"}`)
	spaced  = []byte("{ \"id\":\"evt_3\", \"object\":\"event\",  \"amount\":100.00 }")
	empty   = []byte{}
	rawByte = []byte{0x7b, 0x00, 0x01, 0xff, 0xfe, 0x7d}
	newline = []byte("{\n  \"a\": 1\n}\n")
)

func hmacHex(secret string, msg []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func hmacB64(secret string, msg []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(msg)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// stripeSig is the documented algorithm: HMAC-SHA256 over "<t>.<body>".
func stripeSig(secret string, ts int64, body []byte) string {
	t := strconv.FormatInt(ts, 10)
	return "t=" + t + ",v1=" + hmacHex(secret, append([]byte(t+"."), body...))
}

func main() {
	ts := now.Unix()
	stale := now.Add(-10 * time.Minute).Unix()
	future := now.Add(10 * time.Minute).Unix()

	var vs []Vector

	add := func(v Vector) {
		v.NowUnix = ts
		vs = append(vs, v)
	}

	stripeCase := func(name string, body []byte, header string, expected bool, timeSensitive bool) {
		h := map[string]string{}
		if header != "" {
			h["Stripe-Signature"] = header
		}
		add(Vector{
			Name: "stripe/" + name, Provider: "stripe", Secret: stripeSecret,
			Window: "5m", BodyB64: base64.StdEncoding.EncodeToString(body),
			Headers: h, Expected: expected, TimeSensitive: timeSensitive,
			Oracle: "stripe",
		})
	}

	// Accepted.
	stripeCase("valid plain", plain, stripeSig(stripeSecret, ts, plain), true, false)
	stripeCase("valid emoji", emoji, stripeSig(stripeSecret, ts, emoji), true, false)
	stripeCase("valid spaced float", spaced, stripeSig(stripeSecret, ts, spaced), true, false)
	stripeCase("valid empty body", empty, stripeSig(stripeSecret, ts, empty), true, false)
	stripeCase("valid non-utf8 body", rawByte, stripeSig(stripeSecret, ts, rawByte), true, false)
	stripeCase("valid trailing newline", newline, stripeSig(stripeSecret, ts, newline), true, false)
	stripeCase("valid among several v1",
		plain,
		"t="+strconv.FormatInt(ts, 10)+",v1="+hex.EncodeToString(make([]byte, 32))+
			",v1="+hmacHex(stripeSecret, append([]byte(strconv.FormatInt(ts, 10)+"."), plain...)),
		true, false)
	stripeCase("valid with unknown v0",
		plain,
		"t="+strconv.FormatInt(ts, 10)+",v0=deadbeef,v1="+
			hmacHex(stripeSecret, append([]byte(strconv.FormatInt(ts, 10)+"."), plain...)),
		true, false)

	// Rejected: the header signs a different body than the one sent.
	stripeCase("tampered body", plain, stripeSig(stripeSecret, ts, emoji), false, false)
	stripeCase("wrong secret", plain, stripeSig("someone-else", ts, plain), false, false)
	stripeCase("stale timestamp", plain, stripeSig(stripeSecret, stale, plain), false, true)
	stripeCase("future timestamp", plain, stripeSig(stripeSecret, future, plain), false, true)
	stripeCase("missing header", plain, "", false, false)
	stripeCase("malformed header", plain, "garbage", false, false)
	stripeCase("no timestamp", plain, "v1="+hmacHex(stripeSecret, plain), false, false)
	stripeCase("no signature", plain, "t="+strconv.FormatInt(ts, 10), false, false)
	stripeCase("non-hex signature", plain, "t="+strconv.FormatInt(ts, 10)+",v1=zzzz", false, false)
	stripeCase("non-numeric timestamp", plain, "t=abc,v1="+hmacHex(stripeSecret, plain), false, false)

	githubCase := func(name string, body []byte, header string, expected bool) {
		h := map[string]string{}
		if header != "" {
			h["X-Hub-Signature-256"] = header
		}
		add(Vector{
			Name: "github/" + name, Provider: "github", Secret: githubSecret,
			BodyB64: base64.StdEncoding.EncodeToString(body), Headers: h,
			Expected: expected, Oracle: "go-github",
		})
	}

	githubCase("valid plain", plain, "sha256="+hmacHex(githubSecret, plain), true)
	githubCase("valid emoji", emoji, "sha256="+hmacHex(githubSecret, emoji), true)
	githubCase("valid empty body", empty, "sha256="+hmacHex(githubSecret, empty), true)
	githubCase("valid non-utf8 body", rawByte, "sha256="+hmacHex(githubSecret, rawByte), true)
	githubCase("valid trailing newline", newline, "sha256="+hmacHex(githubSecret, newline), true)
	githubCase("tampered body", plain, "sha256="+hmacHex(githubSecret, emoji), false)
	githubCase("wrong secret", plain, "sha256="+hmacHex("someone-else", plain), false)
	githubCase("missing header", plain, "", false)
	githubCase("no prefix", plain, hmacHex(githubSecret, plain), false)
	githubCase("sha1 prefix", plain, "sha1="+hmacHex(githubSecret, plain), false)
	githubCase("non-hex", plain, "sha256=zzzz", false)
	githubCase("odd length hex", plain, "sha256=abc", false)
	// bytes.fromhex would skip the space; Go's hex.DecodeString errors. The
	// two implementations must agree, which is the whole point of this case.
	githubCase("hex with space", plain,
		"sha256="+hmacHex(githubSecret, plain)[:2]+" "+hmacHex(githubSecret, plain)[2:], false)

	shopifyCase := func(name string, body []byte, header string, expected bool) {
		h := map[string]string{}
		if header != "" {
			h["X-Shopify-Hmac-SHA256"] = header
		}
		add(Vector{
			Name: "shopify/" + name, Provider: "shopify", Secret: shopifySecret,
			BodyB64: base64.StdEncoding.EncodeToString(body), Headers: h,
			Expected: expected,
			// No official library in either language verifies a Shopify
			// webhook body: the Python SDK's validate_hmac is for OAuth query
			// parameters, a different algorithm. Both implementations are
			// checked against the documented algorithm and against each other.
			Oracle: "none",
		})
	}

	shopifyCase("valid plain", plain, hmacB64(shopifySecret, plain), true)
	shopifyCase("valid emoji", emoji, hmacB64(shopifySecret, emoji), true)
	shopifyCase("valid empty body", empty, hmacB64(shopifySecret, empty), true)
	shopifyCase("valid non-utf8 body", rawByte, hmacB64(shopifySecret, rawByte), true)
	shopifyCase("valid trailing newline", newline, hmacB64(shopifySecret, newline), true)
	shopifyCase("tampered body", plain, hmacB64(shopifySecret, emoji), false)
	shopifyCase("wrong secret", plain, hmacB64("someone-else", plain), false)
	shopifyCase("missing header", plain, "", false)
	shopifyCase("hex not base64", plain, hmacHex(shopifySecret, plain), false)
	shopifyCase("invalid base64", plain, "!!!not base64!!!", false)

	out := map[string]any{
		"_comment": "Generated by oracle/sigvecgen from the providers' documented algorithms, " +
			"independently of either implementation. Do not hand-edit; regenerate with: " +
			"cd oracle && go run ./sigvecgen > ../tests/vectors/signatures.json",
		"reference_time": now.Format(time.RFC3339),
		"vectors":        vs,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
