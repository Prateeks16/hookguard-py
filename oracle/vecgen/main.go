// Command vecgen emits the cross-language vectors in ../../tests/vectors/core.json
// from the Go implementation carried over in this module.
//
// The point is that the Python port is pinned to Go's actual behaviour rather
// than to a reimplementation we then test against itself: a round-trip test
// would pass just as happily against a preimage we had invented. Both the
// signature preimage and Go's time.ParseDuration grammar are captured here.
//
// Regenerate (from the repo root) after changing anything in oracle/:
//
//	cd oracle && go run ./vecgen > ../tests/vectors/core.json
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"hookguardoracle/gatewaysig"
)

type sigVector struct {
	Name      string `json:"name"`
	Secret    string `json:"secret"`
	Provider  string `json:"provider"`
	BodyB64   string `json:"body_b64"`
	Signature string `json:"signature"`
}

type durVector struct {
	Name  string  `json:"name"`
	Input string  `json:"input"`
	Nanos *int64  `json:"nanos"` // null => Go rejects this input
	Error *string `json:"error"`
}

func main() {
	// Bodies chosen for the ways bytes get mangled in transit: multi-byte
	// UTF-8, whitespace a JSON re-serializer would normalize, the empty body,
	// bytes that are not valid UTF-8 at all, and trailing newlines.
	bodies := []struct {
		name string
		body []byte
	}{
		{"plain json", []byte(`{"id":"evt_1","amount":4242}`)},
		{"emoji", []byte(`{"id":"evt_2","note":"thanks 🚀✨"}`)},
		{"spaced and float", []byte("{ \"id\":\"evt_3\",  \"amount\":100.00 }")},
		{"empty body", []byte{}},
		{"raw bytes", []byte{0x00, 0x01, 0xff, 0xfe, 0x7f, 0x80}},
		{"newlines", []byte("{\n  \"a\": 1\n}\n")},
	}
	providers := []string{"stripe", "github", "shopify", "paypal", "console-ingest"}
	secrets := []string{"internal", "s3cr3t-with-dashes", ""}

	sigs := []sigVector{}
	for _, s := range secrets {
		for _, p := range providers {
			for _, b := range bodies {
				sigs = append(sigs, sigVector{
					Name:      fmt.Sprintf("%s/%s/secret=%q", p, b.name, s),
					Secret:    s,
					Provider:  p,
					BodyB64:   base64.StdEncoding.EncodeToString(b.body),
					Signature: gatewaysig.Sign([]byte(s), p, b.body),
				})
			}
		}
	}

	durInputs := []string{
		// Accepted by Go.
		"5m", "1h30m", "300s", "0", "0s", "1.5h", ".5s", "100ms", "1us", "1µs",
		"1μs", "1ns", "-5m", "+5m", "2h45m", "1h0m0s", "1m30.5s", "5.m", "-0",
		"0.000000001s", "9223372036854775807ns",
		// Rejected by Go -- the important half. A parser that quietly accepts
		// any of these, or returns zero for it, disables the replay-window
		// check while every other test still passes.
		"", "5", "m", "abc", "5x", "1.2.3s", "  5m", "5m ", "5 m", "--5m",
		"9223372036854775808ns", "10000000000000h",
	}
	durs := []durVector{}
	for _, in := range durInputs {
		v := durVector{Name: fmt.Sprintf("%q", in), Input: in}
		if d, err := time.ParseDuration(in); err != nil {
			msg := err.Error()
			v.Error = &msg
		} else {
			n := int64(d)
			v.Nanos = &n
		}
		durs = append(durs, v)
	}

	// How Go actually marshals the event timestamp. RFC3339Nano prints up to
	// nine fractional digits and strips trailing zeros, so the wire format
	// varies run to run -- and nine digits is more than Python's
	// datetime.fromisoformat accepts. The Console has to parse all of these.
	tsCases := []struct {
		name string
		t    time.Time
	}{
		{"nanosecond precision", time.Date(2026, 8, 29, 12, 0, 0, 123456789, time.UTC)},
		{"microsecond precision", time.Date(2026, 8, 29, 12, 0, 0, 123456000, time.UTC)},
		{"millisecond precision", time.Date(2026, 8, 29, 12, 0, 0, 123000000, time.UTC)},
		{"whole second", time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)},
		{"single digit fraction", time.Date(2026, 8, 29, 12, 0, 0, 100000000, time.UTC)},
		{"non-utc offset", time.Date(2026, 8, 29, 12, 0, 0, 500000000, time.FixedZone("IST", 5*3600+1800))},
		{"epoch", time.Unix(0, 0).UTC()},
	}
	timestamps := []map[string]any{}
	for _, c := range tsCases {
		b, err := c.t.MarshalJSON() // exactly what encoding/json does to the field
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var wire string
		if err := json.Unmarshal(b, &wire); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		timestamps = append(timestamps, map[string]any{
			"name":     c.name,
			"wire":     wire,
			"unix_ns":  c.t.UnixNano(),
			"utc_wire": c.t.UTC().Format(time.RFC3339Nano),
		})
	}

	out := map[string]any{
		"_comment": "Generated from the Go implementation by oracle/vecgen. " +
			"Do not hand-edit; regenerate with: cd oracle && go run ./vecgen > ../tests/vectors/core.json",
		"go_version":      runtime.Version(),
		"header":          gatewaysig.Header,
		"provider_header": gatewaysig.ProviderHeader,
		"gatewaysig":      sigs,
		"goduration":      durs,
		"timestamps":      timestamps,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
